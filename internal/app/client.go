package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
	"github.com/icholy/digest"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"software.sslmate.com/src/go-pkcs12"
)

func executeRequests(ctx context.Context, plans []executionPlan, stdout io.Writer) error {
	var jar http.CookieJar
	var outputFiles *outputFileState
	if len(plans) > 0 {
		jar = plans[0].Runtime.CookieJar
		outputFiles = plans[0].Runtime.outputFiles
	}
	if jar == nil {
		var err error
		jar, err = cookiejar.New(nil)
		if err != nil {
			return err
		}
	}
	if outputFiles == nil {
		outputFiles = newOutputFileState()
	}

	for i := range plans {
		plans[i].Runtime.CookieJar = jar
		plans[i].Runtime.outputFiles = outputFiles
	}

	for i, plan := range plans {
		result, err := executeRequest(ctx, plan)
		if err != nil {
			plan.Runtime.Logger.Errorf("request %q failed: %v", safeRequestLabel(plan.Request.Name, plan.Request.URL), sanitizeError(err, plan.Request.URL))
			return err
		}
		if i > 0 {
			if _, err := fmt.Fprintln(stdout); err != nil {
				return err
			}
		}
		if err := writeResponse(stdout, plan.Request, result.resp, result.body, result.outputFile, plan.Runtime.Colorizer, responseMetadata{
			totalBytes:       result.totalBytes,
			previewTruncated: result.previewTruncated,
		}); err != nil {
			return err
		}
	}

	return nil
}

type responseResult struct {
	resp             *http.Response
	body             []byte
	outputFile       string
	totalBytes       int
	previewTruncated bool
}

func executeRequest(ctx context.Context, plan executionPlan) (responseResult, error) {
	reqSpec := plan.Request
	runtime := plan.Runtime
	logger := runtime.Logger
	resolver := resolver{
		RequestVars: reqSpec.FileVars,
		FileVars:    runtime.FileVars,
		VarsFile:    runtime.VarsFileVars,
		ConfigVars:  runtime.Config.Vars,
		CLIVars:     runtime.CLIVars,
	}

	resolved, err := resolveRequest(reqSpec, runtime, resolver)
	if err != nil {
		return responseResult{}, err
	}
	logger.Infof("executing request %q", safeRequestLabel(resolved.Name, resolved.URL))
	logger.Debugf("resolved request method=%s url=%s http_version=%s", resolved.Method, safeURL(resolved.URL), resolved.HTTPVersion)

	bodyBytes, err := buildBody(resolved)
	if err != nil {
		return responseResult{outputFile: resolved.OutputFile}, err
	}
	if len(bodyBytes) > 0 {
		logger.Debugf("prepared request body bytes=%d", len(bodyBytes))
	}

	request, err := http.NewRequestWithContext(ctx, resolved.Method, resolved.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		return responseResult{outputFile: resolved.OutputFile}, sanitizeError(err, resolved.URL)
	}
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}
	for key, values := range resolved.Headers {
		if strings.EqualFold(key, "Host") {
			if len(values) > 0 {
				request.Host = values[len(values)-1]
			}
			continue
		}
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	request = withTrace(request, logger)

	transport, closer, err := buildTransport(resolved)
	if err != nil {
		return responseResult{outputFile: resolved.OutputFile}, err
	}
	if closer != nil {
		defer closer.Close()
	}
	if idleCloser, ok := transport.(interface{ CloseIdleConnections() }); ok {
		defer idleCloser.CloseIdleConnections()
	}

	var roundTripper http.RoundTripper = loggingRoundTripper{base: transport, logger: logger}
	switch strings.ToLower(resolved.Auth.Scheme) {
	case "basic":
		logger.Debugf("configuring basic authentication")
		request.SetBasicAuth(resolved.Auth.Username, resolved.Auth.Password)
	case "bearer":
		logger.Debugf("configuring bearer authentication")
		request.Header.Set("Authorization", "Bearer "+resolved.Auth.Token)
	case "digest":
		logger.Debugf("configuring digest authentication handshake")
		roundTripper = &digest.Transport{
			Username:  resolved.Auth.Username,
			Password:  resolved.Auth.Password,
			Transport: roundTripper,
			Jar:       runtime.CookieJar,
		}
	case "ntlm":
		logger.Debugf("configuring NTLM authentication handshake")
		request.SetBasicAuth(resolved.Auth.Username, resolved.Auth.Password)
		roundTripper = ntlmssp.Negotiator{RoundTripper: roundTripper}
	case "azuread":
		logger.Debugf("requesting Azure AD access token")
		token, err := getAzureToken(ctx, resolved)
		if err != nil {
			return responseResult{outputFile: resolved.OutputFile}, err
		}
		request.Header.Set("Authorization", "Bearer "+token)
	case "":
	case "mtls":
		logger.Debugf("using mTLS client certificate authentication")
	default:
		return responseResult{outputFile: resolved.OutputFile}, fmt.Errorf("unsupported auth scheme %q", resolved.Auth.Scheme)
	}

	client := &http.Client{
		Transport: roundTripper,
		Jar:       runtime.CookieJar,
		Timeout:   resolved.Timeout,
	}

	started := time.Now()
	resp, err := client.Do(request)
	if err != nil {
		err = sanitizeError(err, resolved.URL)
		logger.Errorf("request %q transport error: %v", safeRequestLabel(resolved.Name, resolved.URL), err)
		return responseResult{outputFile: resolved.OutputFile}, err
	}
	defer resp.Body.Close()

	if resolved.OutputFile != "" {
		outputFiles := runtime.outputFiles
		if outputFiles == nil {
			outputFiles = newOutputFileState()
		}
		body, totalBytes, truncated, err := outputFiles.writeFromReader(resolved.OutputFile, resp.Body)
		if err != nil {
			return responseResult{outputFile: resolved.OutputFile}, err
		}
		logger.Debugf("wrote response body to %s", resolved.OutputFile)
		logger.Infof("request %q completed with status=%s duration=%s", safeRequestLabel(resolved.Name, resolved.URL), resp.Status, time.Since(started).Round(time.Microsecond))
		return responseResult{resp: resp, body: body, outputFile: resolved.OutputFile, totalBytes: totalBytes, previewTruncated: truncated}, nil
	}
	body, totalBytes, truncated, err := readCappedBody(resp.Body, maxResponsePreviewSize)
	if err != nil {
		return responseResult{outputFile: resolved.OutputFile}, err
	}
	logger.Infof("request %q completed with status=%s duration=%s", safeRequestLabel(resolved.Name, resolved.URL), resp.Status, time.Since(started).Round(time.Microsecond))
	return responseResult{resp: resp, body: body, outputFile: resolved.OutputFile, totalBytes: totalBytes, previewTruncated: truncated}, nil
}

// readCappedBody reads at most limit bytes of reader into memory for preview
// purposes, then drains and counts any remaining bytes without buffering
// them, so a large response (especially one whose body will be discarded
// as binary) cannot exhaust memory on the stdout path.
func readCappedBody(reader io.Reader, limit int) ([]byte, int, bool, error) {
	limited := io.LimitReader(reader, int64(limit))
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, len(body), false, err
	}
	remaining, err := io.Copy(io.Discard, reader)
	if err != nil {
		return nil, len(body) + int(remaining), false, err
	}
	totalBytes := len(body) + int(remaining)
	return body, totalBytes, remaining > 0, nil
}

type outputFileState struct {
	initialized map[string]struct{}
}

func newOutputFileState() *outputFileState {
	return &outputFileState{initialized: make(map[string]struct{})}
}

func (s *outputFileState) write(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if _, ok := s.initialized[path]; ok {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	file, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	s.initialized[path] = struct{}{}
	return nil
}

const maxResponsePreviewSize = 1 << 20

func (s *outputFileState) writeFromReader(path string, reader io.Reader) ([]byte, int, bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, 0, false, err
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if _, ok := s.initialized[path]; ok {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	file, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return nil, 0, false, err
	}
	preview := &previewWriter{limit: maxResponsePreviewSize}
	totalBytes, copyErr := io.Copy(io.MultiWriter(file, preview), reader)
	closeErr := file.Close()
	if copyErr != nil {
		return nil, int(totalBytes), false, copyErr
	}
	if closeErr != nil {
		return nil, int(totalBytes), false, closeErr
	}
	s.initialized[path] = struct{}{}
	return preview.Bytes(), int(totalBytes), int(totalBytes) > len(preview.Bytes()), nil
}

type previewWriter struct {
	buffer bytes.Buffer
	limit  int
}

func (w *previewWriter) Write(p []byte) (int, error) {
	written := len(p)
	if w.buffer.Len() < w.limit {
		remaining := w.limit - w.buffer.Len()
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = w.buffer.Write(p)
	}
	return written, nil
}

func (w *previewWriter) Bytes() []byte {
	return w.buffer.Bytes()
}

type resolvedRequest struct {
	RequestSpec
	Timeout            time.Duration
	Auth               AuthConfig
	CertFile           string
	KeyFile            string
	SelfSignedCertFile string
	Logger             *Logger
}

func resolveRequest(spec RequestSpec, runtime RuntimeConfig, vars resolver) (resolvedRequest, error) {
	resolved := resolvedRequest{
		RequestSpec: spec,
		Timeout:     runtime.Timeout,
		Auth:        mergeAuth(runtime.Config.Auth, runtime.Auth, spec.Auth),
		Logger:      runtime.Logger,
	}
	if resolved.Timeout == 0 {
		resolved.Timeout = 30 * time.Second
	}

	resolved.Method = spec.Method
	var err error
	if resolved.URL, err = resolveString(spec.URL, vars); err != nil {
		return resolved, err
	}
	if resolved.Body, err = resolveString(spec.Body, vars); err != nil {
		return resolved, err
	}
	if resolved.BodyFile, err = chooseResolvedPath(runtime.RootDir, runtime.BodyFile, spec.BodyFile, vars); err != nil {
		return resolved, err
	}
	if resolved.OutputFile, err = chooseResolvedPath(runtime.RootDir, runtime.OutputFile, spec.OutputFile, vars); err != nil {
		return resolved, err
	}
	if resolved.Proxy, err = chooseResolvedValue(spec.Proxy, runtime.Proxy, runtime.Config.Proxy, vars); err != nil {
		return resolved, err
	}
	if resolved.HTTPVersion, err = chooseResolvedValue(spec.HTTPVersion, runtime.HTTPVersion, runtime.Config.HTTPVersion, vars); err != nil {
		return resolved, err
	}
	resolved.HTTPVersion = strings.ToLower(resolved.HTTPVersion)
	resolved.CertFile, err = chooseResolvedPath(runtime.RootDir, runtime.Config.CertFile, vars)
	if err != nil {
		return resolved, err
	}
	resolved.KeyFile, err = chooseResolvedPath(runtime.RootDir, runtime.Config.KeyFile, vars)
	if err != nil {
		return resolved, err
	}
	if resolved.SelfSignedCertFile, err = chooseResolvedPath(runtime.RootDir, runtime.SelfSignedCertFile, spec.SelfSignedCertFile, runtime.Config.SelfSignedCertFile, vars); err != nil {
		return resolved, err
	}
	if resolved.Auth.CACertFile != "" {
		authCACert, err := resolveString(resolved.Auth.CACertFile, vars)
		if err != nil {
			return resolved, err
		}
		resolved.Auth.CACertFile = resolvePath(runtime.RootDir, authCACert)
	}
	// An explicit request-level `# @ca-cert` directive always wins; otherwise
	// an auth-level CA overrides the global config default.
	if resolved.CACertFile, err = chooseResolvedPath(runtime.RootDir, spec.CACertFile, resolved.Auth.CACertFile, runtime.Config.CACertFile, vars); err != nil {
		return resolved, err
	}
	resolved.Insecure = runtime.Config.Insecure || runtime.Insecure
	if spec.InsecureSet {
		resolved.Insecure = spec.Insecure
	} else if spec.Insecure {
		resolved.Insecure = true
	}
	resolved.Headers = http.Header{}
	for key, values := range spec.Headers {
		for _, value := range values {
			resolvedValue, err := resolveString(value, vars)
			if err != nil {
				return resolved, err
			}
			resolved.Headers.Add(key, resolvedValue)
		}
	}

	if resolved.Auth.Username, err = resolveString(resolved.Auth.Username, vars); err != nil {
		return resolved, err
	}
	if resolved.Auth.Password, err = resolveString(resolved.Auth.Password, vars); err != nil {
		return resolved, err
	}
	if resolved.Auth.Token, err = resolveString(resolved.Auth.Token, vars); err != nil {
		return resolved, err
	}
	if resolved.Auth.Scope, err = resolveString(resolved.Auth.Scope, vars); err != nil {
		return resolved, err
	}
	if resolved.Auth.Resource, err = resolveString(resolved.Auth.Resource, vars); err != nil {
		return resolved, err
	}
	if resolved.Auth.TenantID, err = resolveString(resolved.Auth.TenantID, vars); err != nil {
		return resolved, err
	}
	if resolved.Auth.ClientID, err = resolveString(resolved.Auth.ClientID, vars); err != nil {
		return resolved, err
	}
	if resolved.Auth.ClientSecret, err = resolveString(resolved.Auth.ClientSecret, vars); err != nil {
		return resolved, err
	}
	if resolved.Auth.TokenURL, err = resolveString(resolved.Auth.TokenURL, vars); err != nil {
		return resolved, err
	}
	if resolved.Auth.CertFile != "" {
		if resolved.Auth.CertFile, err = resolveString(resolved.Auth.CertFile, vars); err != nil {
			return resolved, err
		}
		resolved.Auth.CertFile = resolvePath(runtime.RootDir, resolved.Auth.CertFile)
	}
	if resolved.Auth.KeyFile != "" {
		if resolved.Auth.KeyFile, err = resolveString(resolved.Auth.KeyFile, vars); err != nil {
			return resolved, err
		}
		resolved.Auth.KeyFile = resolvePath(runtime.RootDir, resolved.Auth.KeyFile)
	}
	if resolved.Auth.CertFile == "" {
		resolved.Auth.CertFile = resolved.CertFile
	}
	if resolved.Auth.KeyFile == "" {
		resolved.Auth.KeyFile = resolved.KeyFile
	}
	if strings.EqualFold(resolved.Auth.Scheme, "mtls") {
		switch {
		case resolved.Auth.CertFile == "":
			return resolved, errors.New("mtls authentication requires a certificate file")
		case isPKCS12Path(resolved.Auth.CertFile) && resolved.Auth.Password == "":
			return resolved, errors.New("mtls authentication with a PKCS#12 certificate requires a password")
		case !isPKCS12Path(resolved.Auth.CertFile) && resolved.Auth.KeyFile == "":
			return resolved, errors.New("mtls authentication with a PEM certificate requires a key file")
		}
	}

	if resolved.HTTPVersion == "" {
		resolved.HTTPVersion = "auto"
	}
	if !isSupportedHTTPVersion(resolved.HTTPVersion) {
		return resolved, fmt.Errorf("unsupported http version %q", resolved.HTTPVersion)
	}
	if runtime.Logger != nil && runtime.Logger.Enabled(LogLevelDebug) {
		runtime.Logger.Debugf("resolved request config name=%q proxy=%q output_file=%q body_file=%q", safeRequestLabel(resolved.Name, resolved.URL), safeURL(resolved.Proxy), resolved.OutputFile, resolved.BodyFile)
	}

	return resolved, nil
}

func chooseResolvedValue(values ...any) (string, error) {
	if len(values) == 0 {
		return "", nil
	}
	var vars resolver
	if last, ok := values[len(values)-1].(resolver); ok {
		vars = last
		values = values[:len(values)-1]
	}
	for _, raw := range values {
		value, _ := raw.(string)
		if strings.TrimSpace(value) == "" {
			continue
		}
		resolved, err := resolveString(value, vars)
		if err != nil {
			return "", err
		}
		return resolved, nil
	}
	return "", nil
}

func chooseResolvedPath(root string, values ...any) (string, error) {
	value, err := chooseResolvedValue(values...)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", nil
	}
	return resolvePath(root, value), nil
}

func resolvePath(root, value string) string {
	if value == "" {
		return ""
	}
	if filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(root, value)
}

func mergeAuth(configAuth, cliAuth, requestAuth AuthConfig) AuthConfig {
	merged := AuthConfig{}
	merged = overlayAuth(merged, configAuth)
	merged = overlayAuth(merged, cliAuth)
	merged = overlayAuth(merged, requestAuth)
	return merged
}

func overlayAuth(base, override AuthConfig) AuthConfig {
	if isEmptyAuth(override) {
		return base
	}
	if override.Scheme != "" && base.Scheme != "" && !strings.EqualFold(override.Scheme, base.Scheme) {
		base = AuthConfig{}
	}
	if override.Scheme != "" {
		base.Scheme = override.Scheme
	}
	if override.Username != "" {
		base.Username = override.Username
	}
	if override.Password != "" {
		base.Password = override.Password
	}
	if override.Token != "" {
		base.Token = override.Token
	}
	if override.CertFile != "" {
		base.CertFile = override.CertFile
	}
	if override.KeyFile != "" {
		base.KeyFile = override.KeyFile
	}
	if override.CACertFile != "" {
		base.CACertFile = override.CACertFile
	}
	if override.TenantID != "" {
		base.TenantID = override.TenantID
	}
	if override.ClientID != "" {
		base.ClientID = override.ClientID
	}
	if override.ClientSecret != "" {
		base.ClientSecret = override.ClientSecret
	}
	if override.Scope != "" {
		base.Scope = override.Scope
	}
	if override.Resource != "" {
		base.Resource = override.Resource
	}
	if override.TokenURL != "" {
		base.TokenURL = override.TokenURL
	}
	return base
}

func isEmptyAuth(auth AuthConfig) bool {
	return auth == (AuthConfig{})
}

func buildBody(resolved resolvedRequest) ([]byte, error) {
	if resolved.BodyFile != "" {
		if resolved.Logger != nil {
			resolved.Logger.Debugf("reading request body from file %s", resolved.BodyFile)
		}
		return os.ReadFile(resolved.BodyFile)
	}
	if strings.HasPrefix(strings.TrimSpace(resolved.Body), "< ") {
		bodyFile := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(resolved.Body), "< "))
		if resolved.Logger != nil {
			resolved.Logger.Debugf("reading request body from inline file reference %s", bodyFile)
		}
		return os.ReadFile(resolvePath(filepath.Dir(resolved.SourcePath), bodyFile))
	}
	if resolved.Body == "" {
		return nil, nil
	}
	return []byte(resolved.Body), nil
}

func newBody(body []byte) io.ReadCloser {
	if len(body) == 0 {
		return http.NoBody
	}
	return io.NopCloser(strings.NewReader(string(body)))
}

func safeURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "<invalid URL>"
	}
	parsed.User = nil
	parsed.Fragment = ""
	query := parsed.Query()
	for key := range query {
		query.Set(key, "[REDACTED]")
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func safeRequestLabel(name, rawURL string) string {
	if name == "" || name == rawURL {
		return safeURL(rawURL)
	}
	if strings.HasSuffix(name, rawURL) {
		return strings.TrimSuffix(name, rawURL) + safeURL(rawURL)
	}
	return name
}

func sanitizeError(err error, rawURL string) error {
	if err == nil {
		return nil
	}
	message := strings.ReplaceAll(err.Error(), rawURL, safeURL(rawURL))
	if message == err.Error() {
		return err
	}
	return &sanitizedError{message: message, cause: err}
}

// sanitizedError reports a redacted message via Error() while still allowing
// errors.Is/errors.As to reach the original cause via Unwrap. This avoids the
// leak that fmt.Errorf("%s: %w", message, err) would introduce, since %w's
// formatting includes the wrapped error's own (unredacted) Error() text.
type sanitizedError struct {
	message string
	cause   error
}

func (e *sanitizedError) Error() string { return e.message }
func (e *sanitizedError) Unwrap() error { return e.cause }

func buildTransport(resolved resolvedRequest) (http.RoundTripper, io.Closer, error) {
	if resolved.Logger != nil {
		resolved.Logger.Debugf("building transport http_version=%s proxy=%q insecure=%t", resolved.HTTPVersion, resolved.Proxy, resolved.Insecure)
	}
	tlsConfig, err := buildTLSConfig(resolved)
	if err != nil {
		return nil, nil, err
	}

	if resolved.HTTPVersion == "3" {
		if resolved.Proxy != "" {
			return nil, nil, errors.New("HTTP/3 proxy support is not available")
		}
		if resolved.Logger != nil {
			resolved.Logger.Debugf("using HTTP/3 transport")
		}
		transport := &http3.Transport{
			TLSClientConfig: tlsConfig,
		}
		return transport, transport, nil
	}
	if resolved.HTTPVersion == "2" {
		if strings.TrimSpace(resolved.URL) != "" {
			if parsedURL, err := url.Parse(resolved.URL); err == nil && parsedURL.Scheme != "https" {
				return nil, nil, errors.New("HTTP/2 requires an https URL")
			}
		}
		transport := &http2.Transport{
			TLSClientConfig: tlsConfig,
		}
		if resolved.Proxy != "" {
			proxyURL, err := url.Parse(resolved.Proxy)
			if err != nil {
				return nil, nil, err
			}
			transport.DialTLSContext = http2ProxyDialer(proxyURL, tlsConfig)
			if resolved.Logger != nil {
				resolved.Logger.Debugf("using strict HTTP/2 transport via proxy %s", safeURL(proxyURL.String()))
			}
		} else if resolved.Logger != nil {
			resolved.Logger.Debugf("using strict HTTP/2 transport")
		}
		return transport, nil, nil
	}

	transport := &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: resolved.HTTPVersion != "1",
		Proxy:             http.ProxyFromEnvironment,
	}
	if resolved.HTTPVersion == "1" {
		if resolved.Logger != nil {
			resolved.Logger.Debugf("forcing HTTP/1.x transport")
		}
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	if resolved.Proxy != "" {
		proxyURL, err := url.Parse(resolved.Proxy)
		if err != nil {
			return nil, nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		if resolved.Logger != nil {
			resolved.Logger.Debugf("using proxy %s", safeURL(proxyURL.String()))
		}
	}
	return transport, nil, nil
}

// http2ProxyDialer returns a DialTLSContext that tunnels an HTTP/2 TLS
// connection through an HTTP proxy using the CONNECT method, since
// golang.org/x/net/http2.Transport has no built-in proxy support.
func http2ProxyDialer(proxyURL *url.URL, cfg *tls.Config) func(ctx context.Context, network, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	return func(ctx context.Context, network, addr string, tlsCfg *tls.Config) (net.Conn, error) {
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, network, proxyURL.Host)
		if err != nil {
			return nil, err
		}
		// Close conn if ctx is canceled while negotiating the CONNECT tunnel
		// or performing the TLS handshake, since neither respects ctx on its
		// own once the initial dial has succeeded. Stop watching once the
		// handshake completes so a later context cancellation only affects
		// in-flight reads/writes, not the established connection.
		stopWatch := watchContext(ctx, conn)
		defer stopWatch()

		connectReq := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		if proxyURL.User != nil {
			if password, ok := proxyURL.User.Password(); ok {
				creds := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
				connectReq.Header.Set("Proxy-Authorization", "Basic "+creds)
			}
		}
		if err := connectReq.Write(conn); err != nil {
			conn.Close()
			return nil, err
		}
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, connectReq)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("proxy CONNECT to %s failed: %s", addr, resp.Status)
		}
		buffered := &bufferedConn{Conn: conn, reader: reader}
		tlsConn := tls.Client(buffered, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tlsConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
}

// watchContext closes conn if ctx is canceled before the returned stop
// function is called, and is a no-op once stop has run. It lets CONNECT
// negotiation and the TLS handshake, neither of which take a context
// themselves for their I/O, observe cancellation and timeouts.
func watchContext(ctx context.Context, conn net.Conn) (stop func()) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	var stopped bool
	return func() {
		if !stopped {
			stopped = true
			close(done)
		}
	}
}

// bufferedConn preserves any bytes the proxy already sent past the CONNECT
// response headers so they aren't dropped by the subsequent TLS handshake.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func buildTLSConfig(resolved resolvedRequest) (*tls.Config, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: resolved.Insecure} //nolint:gosec
	rootCerts := []string{}
	if resolved.CACertFile != "" {
		rootCerts = append(rootCerts, resolved.CACertFile)
	}
	if resolved.SelfSignedCertFile != "" {
		rootCerts = append(rootCerts, resolved.SelfSignedCertFile)
	}
	if len(rootCerts) > 0 {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		for _, certPath := range rootCerts {
			if resolved.Logger != nil {
				resolved.Logger.Debugf("loading trusted certificate from %s", certPath)
			}
			pemData, err := os.ReadFile(certPath)
			if err != nil {
				return nil, err
			}
			if !pool.AppendCertsFromPEM(pemData) {
				return nil, fmt.Errorf("failed to append certificates from %s", certPath)
			}
		}
		tlsConfig.RootCAs = pool
	}

	certFile := resolved.Auth.CertFile
	keyFile := resolved.Auth.KeyFile
	if certFile == "" {
		certFile = resolved.CertFile
	}
	if keyFile == "" {
		keyFile = resolved.KeyFile
	}
	if certFile != "" || keyFile != "" {
		if resolved.Logger != nil {
			resolved.Logger.Debugf("loading client certificate cert=%s", certFile)
		}
		cert, err := loadClientCertificate(certFile, keyFile, resolved.Auth.Password)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}

func loadClientCertificate(certFile, keyFile, password string) (tls.Certificate, error) {
	if isPKCS12Path(certFile) {
		pfxData, err := os.ReadFile(certFile)
		if err != nil {
			return tls.Certificate{}, err
		}
		privateKey, certificate, caCerts, err := pkcs12.DecodeChain(pfxData, password)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load PKCS#12 client certificate %s: %w", certFile, err)
		}
		certificateChain := make([][]byte, 0, 1+len(caCerts))
		certificateChain = append(certificateChain, certificate.Raw)
		for _, caCert := range caCerts {
			certificateChain = append(certificateChain, caCert.Raw)
		}
		return tls.Certificate{
			Certificate: certificateChain,
			PrivateKey:  privateKey,
			Leaf:        certificate,
		}, nil
	}
	if certFile == "" || keyFile == "" {
		return tls.Certificate{}, errors.New("both certificate and key files are required")
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func isPKCS12Path(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".p12", ".pfx":
		return true
	default:
		return false
	}
}

func getAzureToken(ctx context.Context, resolved resolvedRequest) (string, error) {
	if resolved.Auth.Token != "" {
		return resolved.Auth.Token, nil
	}
	tokenURL := resolved.Auth.TokenURL
	form := url.Values{}
	tenant := resolved.Auth.TenantID
	if tokenURL == "" {
		// The Microsoft identity platform does not support client-credentials
		// grants through the multi-tenant "common"/"organizations"/"consumers"
		// authorities, so a specific tenant is required for the built-in
		// token endpoint. A custom token_url may still use its own authority.
		if tenant == "" {
			return "", errors.New("azuread auth requires tenant_id (or a custom token_url) for client-credentials grants")
		}
		if resolved.Auth.Resource != "" {
			tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", tenant)
		} else {
			tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant)
		}
	}
	if resolved.Auth.Resource != "" {
		form.Set("resource", resolved.Auth.Resource)
	} else {
		scope := resolved.Auth.Scope
		if scope == "" {
			scope = "https://management.azure.com/.default"
		}
		form.Set("scope", scope)
	}

	if resolved.Auth.ClientID == "" || resolved.Auth.ClientSecret == "" {
		return "", errors.New("azuread auth requires token or client_id and client_secret")
	}

	form.Set("grant_type", "client_credentials")
	form.Set("client_id", resolved.Auth.ClientID)
	form.Set("client_secret", resolved.Auth.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", sanitizeError(err, tokenURL)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resolved.Logger != nil {
		resolved.Logger.Debugf("requesting Azure AD token from %s", safeURL(tokenURL))
	}

	tokenResolved := resolved
	tokenResolved.URL = tokenURL
	transport, closer, err := buildTransport(tokenResolved)
	if err != nil {
		return "", err
	}
	if closer != nil {
		defer closer.Close()
	}

	client := &http.Client{
		Timeout:   resolved.Timeout,
		Transport: loggingRoundTripper{base: transport, logger: resolved.Logger},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", sanitizeError(err, tokenURL)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("azuread token request failed: %s", strings.TrimSpace(string(body)))
	}

	payload := struct {
		AccessToken string `json:"access_token"`
	}{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if payload.AccessToken == "" {
		return "", errors.New("azuread token response did not include access_token")
	}
	return payload.AccessToken, nil
}

func isSupportedHTTPVersion(version string) bool {
	switch version {
	case "auto", "1", "2", "3":
		return true
	default:
		return false
	}
}

func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum[:])
}

type loggingRoundTripper struct {
	base   http.RoundTripper
	logger *Logger
}

func (l loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if l.base == nil {
		l.base = http.DefaultTransport
	}
	if l.logger != nil {
		l.logger.Tracef("round trip start method=%s url=%s", req.Method, safeURL(req.URL.String()))
	}
	resp, err := l.base.RoundTrip(req)
	if err != nil {
		if l.logger != nil {
			l.logger.Errorf("round trip failed method=%s url=%s err=%v", req.Method, safeURL(req.URL.String()), err)
		}
		return nil, err
	}
	if l.logger != nil {
		l.logger.Tracef("round trip done method=%s url=%s status=%s", req.Method, safeURL(req.URL.String()), resp.Status)
	}
	return resp, nil
}

func withTrace(req *http.Request, logger *Logger) *http.Request {
	if logger == nil || !logger.Enabled(LogLevelTrace) {
		return req
	}
	trace := &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			logger.Tracef("get connection addr=%s", hostPort)
		},
		DNSStart: func(info httptrace.DNSStartInfo) {
			logger.Tracef("dns start host=%s", info.Host)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			logger.Tracef("dns done addrs=%d err=%v", len(info.Addrs), info.Err)
		},
		ConnectStart: func(network, addr string) {
			logger.Tracef("connect start network=%s addr=%s", network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			logger.Tracef("connect done network=%s addr=%s err=%v", network, addr, err)
		},
		TLSHandshakeStart: func() {
			logger.Tracef("tls handshake start")
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			logger.Tracef("tls handshake done err=%v", err)
			if len(state.PeerCertificates) > 0 {
				logger.Tracef("peer certificate subject=%q sha256=%s", state.PeerCertificates[0].Subject.String(), certFingerprint(state.PeerCertificates[0]))
			}
		},
		WroteHeaders: func() {
			logger.Tracef("request headers written")
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			logger.Tracef("request write done err=%v", info.Err)
		},
		GotConn: func(info httptrace.GotConnInfo) {
			logger.Tracef("got connection reused=%t idle=%t", info.Reused, info.WasIdle)
		},
		GotFirstResponseByte: func() {
			logger.Tracef("received first response byte")
		},
	}
	return req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
}

type responseMetadata struct {
	totalBytes       int
	previewTruncated bool
}

func writeResponse(w io.Writer, req RequestSpec, resp *http.Response, body []byte, outputFile string, colorizer *Colorizer, metadata ...responseMetadata) error {
	if resp == nil {
		return errors.New("response is required")
	}
	if colorizer == nil {
		colorizer = NewColorizer(false)
	}
	if _, err := fmt.Fprintf(w, "%s\n", colorizer.Title("### %s", safeRequestLabel(req.Name, req.URL))); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s\n", formatResponseStatus(colorizer, resp)); err != nil {
		return err
	}
	for key, values := range resp.Header {
		if _, err := fmt.Fprintf(w, "%s\n", formatHeaderLine(colorizer, key, values)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	var info responseMetadata
	if len(metadata) > 0 {
		info = metadata[0]
	}
	if info.totalBytes == 0 {
		info.totalBytes = len(body)
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	isJSON := strings.HasSuffix(mediaType, "+json") || mediaType == "application/json"
	if isJSON {
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		var pretty any
		if err := decoder.Decode(&pretty); err == nil {
			var trailing any
			if decoder.Decode(&trailing) == io.EOF {
				formatted, err := json.MarshalIndent(pretty, "", "  ")
				if err == nil {
					_, err = fmt.Fprintln(w, string(formatted))
					return err
				}
			}
		}
	}
	if strings.HasPrefix(mediaType, "text/") || isJSON || strings.HasSuffix(mediaType, "+xml") || mediaType == "application/xml" || mediaType == "" {
		_, err := fmt.Fprintln(w, string(body))
		if err == nil && info.previewTruncated {
			if outputFile != "" {
				_, err = fmt.Fprintf(w, "%s\n", colorizer.Meta("response preview truncated at %d bytes; full body saved to %s (bytes=%d)", len(body), outputFile, info.totalBytes))
			} else {
				_, err = fmt.Fprintf(w, "%s\n", colorizer.Meta("response preview truncated at %d bytes (total bytes=%d); use --output to save the full body", len(body), info.totalBytes))
			}
		}
		return err
	}
	contentType := resp.Header.Get("Content-Type")
	if outputFile != "" {
		_, err := fmt.Fprintf(w, "%s\n", colorizer.Meta("binary body saved to %s; omitted from stdout (content-type=%s, bytes=%d)", outputFile, contentType, info.totalBytes))
		return err
	}
	_, err := fmt.Fprintf(w, "%s\n", colorizer.Meta("binary body omitted from stdout (content-type=%s, bytes=%d); use --output to save it", contentType, info.totalBytes))
	return err
}
