package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
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
)

func executeRequests(ctx context.Context, plans []executionPlan, stdout io.Writer) error {
	var jar http.CookieJar
	if len(plans) > 0 {
		jar = plans[0].Runtime.CookieJar
	}
	if jar == nil {
		var err error
		jar, err = cookiejar.New(nil)
		if err != nil {
			return err
		}
	}

	for i := range plans {
		plans[i].Runtime.CookieJar = jar
	}

	for i, plan := range plans {
		resp, body, err := executeRequest(ctx, plan)
		if err != nil {
			plan.Runtime.Logger.Errorf("request %q failed: %v", plan.Request.Name, err)
			return err
		}
		if i > 0 {
			if _, err := fmt.Fprintln(stdout); err != nil {
				return err
			}
		}
		if err := writeResponse(stdout, plan.Request, resp, body, plan.Runtime.Colorizer); err != nil {
			return err
		}
	}

	return nil
}

func executeRequest(ctx context.Context, plan executionPlan) (*http.Response, []byte, error) {
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
		return nil, nil, err
	}
	logger.Infof("executing request %q", resolved.Name)
	logger.Debugf("resolved request method=%s url=%s http_version=%s", resolved.Method, resolved.URL, resolved.HTTPVersion)

	bodyBytes, err := buildBody(resolved)
	if err != nil {
		return nil, nil, err
	}
	if len(bodyBytes) > 0 {
		logger.Debugf("prepared request body bytes=%d", len(bodyBytes))
	}

	request, err := http.NewRequestWithContext(ctx, resolved.Method, resolved.URL, newBody(bodyBytes))
	if err != nil {
		return nil, nil, err
	}
	request.GetBody = func() (io.ReadCloser, error) {
		return newBody(bodyBytes), nil
	}
	for key, values := range resolved.Headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	request = withTrace(request, logger)

	transport, closer, err := buildTransport(resolved)
	if err != nil {
		return nil, nil, err
	}
	if closer != nil {
		defer closer.Close()
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
			return nil, nil, err
		}
		request.Header.Set("Authorization", "Bearer "+token)
	case "":
	case "mtls":
		logger.Debugf("using mTLS client certificate authentication")
	default:
		return nil, nil, fmt.Errorf("unsupported auth scheme %q", resolved.Auth.Scheme)
	}

	client := &http.Client{
		Transport: roundTripper,
		Jar:       runtime.CookieJar,
		Timeout:   resolved.Timeout,
	}

	started := time.Now()
	resp, err := client.Do(request)
	if err != nil {
		logger.Errorf("request %q transport error: %v", resolved.Name, err)
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	logger.Infof("request %q completed with status=%s duration=%s", resolved.Name, resp.Status, time.Since(started).Round(time.Microsecond))
	if resolved.OutputFile != "" {
		if err := os.MkdirAll(filepath.Dir(resolved.OutputFile), 0o755); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(resolved.OutputFile, body, 0o644); err != nil {
			return nil, nil, err
		}
		logger.Debugf("wrote response body to %s", resolved.OutputFile)
	}
	return resp, body, nil
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
		RequestSpec:        spec,
		Timeout:            runtime.Timeout,
		Auth:               mergeAuth(runtime.Config.Auth, runtime.Auth, spec.Auth),
		CertFile:           resolvePath(runtime.RootDir, runtime.Config.CertFile),
		KeyFile:            resolvePath(runtime.RootDir, runtime.Config.KeyFile),
		SelfSignedCertFile: resolvePath(runtime.RootDir, runtime.SelfSignedCertFile),
		Logger:             runtime.Logger,
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
	resolved.BodyFile = chooseResolvedPath(runtime.RootDir, runtime.BodyFile, spec.BodyFile, vars)
	resolved.OutputFile = chooseResolvedPath(runtime.RootDir, runtime.OutputFile, spec.OutputFile, vars)
	resolved.Proxy = chooseResolvedValue(spec.Proxy, runtime.Proxy, runtime.Config.Proxy, vars)
	resolved.HTTPVersion = strings.ToLower(chooseResolvedValue(spec.HTTPVersion, runtime.HTTPVersion, runtime.Config.HTTPVersion, vars))
	resolved.CACertFile = chooseResolvedPath(runtime.RootDir, spec.CACertFile, runtime.Config.CACertFile, vars)
	resolved.SelfSignedCertFile = chooseResolvedPath(runtime.RootDir, spec.SelfSignedCertFile, runtime.SelfSignedCertFile, runtime.Config.SelfSignedCertFile, vars)
	if resolved.Auth.CACertFile != "" {
		authCACert, err := resolveString(resolved.Auth.CACertFile, vars)
		if err != nil {
			return resolved, err
		}
		resolved.Auth.CACertFile = resolvePath(runtime.RootDir, authCACert)
		if resolved.CACertFile == "" {
			resolved.CACertFile = resolved.Auth.CACertFile
		}
	}
	resolved.Insecure = runtime.Config.Insecure || runtime.Insecure || spec.Insecure
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
	if resolved.Auth.CACertFile != "" {
		if resolved.Auth.CACertFile, err = resolveString(resolved.Auth.CACertFile, vars); err != nil {
			return resolved, err
		}
		resolved.Auth.CACertFile = resolvePath(runtime.RootDir, resolved.Auth.CACertFile)
		if resolved.CACertFile == "" {
			resolved.CACertFile = resolved.Auth.CACertFile
		}
	}
	if resolved.Auth.CertFile == "" {
		resolved.Auth.CertFile = resolved.CertFile
	}
	if resolved.Auth.KeyFile == "" {
		resolved.Auth.KeyFile = resolved.KeyFile
	}

	if resolved.HTTPVersion == "" {
		resolved.HTTPVersion = "auto"
	}
	if !isSupportedHTTPVersion(resolved.HTTPVersion) {
		return resolved, fmt.Errorf("unsupported http version %q", resolved.HTTPVersion)
	}
	if runtime.Logger != nil && runtime.Logger.Enabled(LogLevelDebug) {
		runtime.Logger.Debugf("resolved request config name=%q proxy=%q output_file=%q body_file=%q", resolved.Name, resolved.Proxy, resolved.OutputFile, resolved.BodyFile)
	}

	return resolved, nil
}

func chooseResolvedValue(values ...any) string {
	if len(values) == 0 {
		return ""
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
		if err == nil {
			return resolved
		}
	}
	return ""
}

func chooseResolvedPath(root string, values ...any) string {
	value := chooseResolvedValue(values...)
	if value == "" {
		return ""
	}
	return resolvePath(root, value)
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
		if resolved.Logger != nil {
			resolved.Logger.Debugf("using strict HTTP/2 transport")
		}
		return &http2.Transport{
			TLSClientConfig: tlsConfig,
		}, nil, nil
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
			resolved.Logger.Debugf("using proxy %s", proxyURL.Redacted())
		}
	}
	return transport, nil, nil
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
		if certFile == "" || keyFile == "" {
			return nil, errors.New("both certificate and key files are required")
		}
		if resolved.Logger != nil {
			resolved.Logger.Debugf("loading client certificate cert=%s key=%s", certFile, keyFile)
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}

func getAzureToken(ctx context.Context, resolved resolvedRequest) (string, error) {
	if resolved.Auth.Token != "" {
		return resolved.Auth.Token, nil
	}
	tokenURL := resolved.Auth.TokenURL
	form := url.Values{}
	tenant := resolved.Auth.TenantID
	if tenant == "" {
		tenant = "common"
	}
	if tokenURL == "" {
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
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resolved.Logger != nil {
		resolved.Logger.Debugf("requesting Azure AD token from %s", tokenURL)
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
		return "", err
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
		l.logger.Tracef("round trip start method=%s url=%s", req.Method, req.URL.String())
	}
	resp, err := l.base.RoundTrip(req)
	if err != nil {
		if l.logger != nil {
			l.logger.Errorf("round trip failed method=%s url=%s err=%v", req.Method, req.URL.String(), err)
		}
		return nil, err
	}
	if l.logger != nil {
		l.logger.Tracef("round trip done method=%s url=%s status=%s", req.Method, req.URL.String(), resp.Status)
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

func writeResponse(w io.Writer, req RequestSpec, resp *http.Response, body []byte, colorizer *Colorizer) error {
	if resp == nil {
		return errors.New("response is required")
	}
	if colorizer == nil {
		colorizer = NewColorizer(false)
	}
	if _, err := fmt.Fprintf(w, "%s\n", colorizer.Title("### %s", req.Name)); err != nil {
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
	if strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		var pretty any
		if err := json.Unmarshal(body, &pretty); err == nil {
			formatted, err := json.MarshalIndent(pretty, "", "  ")
			if err == nil {
				_, err = fmt.Fprintln(w, string(formatted))
				return err
			}
		}
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(mediaType, "text/") || mediaType == "application/json" || mediaType == "" {
		_, err := fmt.Fprintln(w, string(body))
		return err
	}
	_, err := fmt.Fprintf(w, "%s\n", colorizer.Meta("%d bytes written", len(body)))
	return err
}
