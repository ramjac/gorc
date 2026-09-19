package app

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func TestExecuteRequestsUsesCookiesAndBasicAuth(t *testing.T) {
	t.Setenv("TEST_GORC_ENV", "env-value")

	handler := http.NewServeMux()
	handler.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")) {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok"})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"loggedIn":true}`))
	})
	handler.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value != "ok" {
			http.Error(w, "missing cookie", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("cookie-ok"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	dir := t.TempDir()
	bodyFile := filepath.Join(dir, "body.json")
	if err := os.WriteFile(bodyFile, []byte(`{"hello":"world"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	outputFile := filepath.Join(dir, "response.txt")

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime := RuntimeConfig{
		RootDir:  dir,
		FileVars: map[string]string{"base": server.URL, "bodyPath": bodyFile},
		CLIVars:  map[string]string{},
		Config: Config{
			Vars: map[string]string{},
		},
		CookieJar: jar,
	}

	plans := []executionPlan{
		{
			Request: RequestSpec{
				Name:       "login",
				Method:     http.MethodGet,
				URL:        "{{base}}/login",
				Headers:    http.Header{},
				OutputFile: outputFile,
				Auth: AuthConfig{
					Scheme:   "basic",
					Username: "alice",
					Password: "secret",
				},
			},
			Runtime: runtime,
		},
		{
			Request: RequestSpec{
				Name:    "me",
				Method:  http.MethodGet,
				URL:     "{{base}}/me",
				Headers: http.Header{},
			},
			Runtime: runtime,
		},
	}

	var output strings.Builder
	if err := executeRequests(context.Background(), plans, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "cookie-ok") {
		t.Fatalf("expected output to contain second response body, got %q", output.String())
	}
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"loggedIn":true`) {
		t.Fatalf("unexpected saved output: %q", string(data))
	}
}

func TestExecuteRequestsAppendsBodiesToSharedOutputFile(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/first", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("first"))
	})
	handler.HandleFunc("/second", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("second"))
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	outputFile := filepath.Join(t.TempDir(), "responses.txt")
	if err := os.WriteFile(outputFile, []byte("old-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	runtime := RuntimeConfig{
		OutputFile: outputFile,
		Config:     Config{Vars: map[string]string{}},
		FileVars:   map[string]string{},
		CLIVars:    map[string]string{},
	}
	plans := []executionPlan{
		{
			Request: RequestSpec{Name: "first", Method: http.MethodGet, URL: server.URL + "/first", Headers: http.Header{}},
			Runtime: runtime,
		},
		{
			Request: RequestSpec{Name: "second", Method: http.MethodGet, URL: server.URL + "/second", Headers: http.Header{}},
			Runtime: runtime,
		},
	}

	if err := executeRequests(context.Background(), plans, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "firstsecond"; got != want {
		t.Fatalf("expected response bodies to be appended in order, got %q want %q", got, want)
	}
}

func TestMergeAuthRefinesConfiguredScheme(t *testing.T) {
	t.Parallel()

	merged := mergeAuth(
		AuthConfig{Scheme: "azuread", ClientID: "cid", ClientSecret: "secret", Scope: "scope-a"},
		AuthConfig{},
		AuthConfig{Scheme: "azuread", Scope: "scope-b"},
	)
	if merged.ClientID != "cid" || merged.ClientSecret != "secret" {
		t.Fatalf("expected configured credentials to be preserved: %#v", merged)
	}
	if merged.Scope != "scope-b" {
		t.Fatalf("expected request scope override, got %#v", merged)
	}
}

func TestResolveRequestRequestOverridesConfigAndExpandsAuthPaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	runtime := RuntimeConfig{
		RootDir:            dir,
		FileVars:           map[string]string{"proxy": "http://request-proxy", "cert": "client.pem", "key": "client.key", "ca": "ca.pem"},
		CLIVars:            map[string]string{},
		Proxy:              "http://cli-proxy",
		HTTPVersion:        "2",
		SelfSignedCertFile: filepath.Join(dir, "cli.pem"),
		Config: Config{
			Vars:               map[string]string{},
			Proxy:              "http://config-proxy",
			HTTPVersion:        "1",
			CACertFile:         "config-ca.pem",
			SelfSignedCertFile: "config-self.pem",
			Auth: AuthConfig{
				Scheme:     "mtls",
				CertFile:   "config-client.pem",
				KeyFile:    "config-client.key",
				CACertFile: "config-auth-ca.pem",
			},
		},
	}

	resolved, err := resolveRequest(RequestSpec{
		Name:               "test",
		Method:             http.MethodGet,
		URL:                "https://example.com",
		Proxy:              "{{proxy}}",
		HTTPVersion:        "3",
		CACertFile:         "{{ca}}",
		SelfSignedCertFile: "request-self.pem",
		Auth: AuthConfig{
			Scheme:   "mtls",
			CertFile: "{{cert}}",
			KeyFile:  "{{key}}",
		},
	}, runtime, resolver{
		RequestVars: map[string]string{},
		FileVars:    runtime.FileVars,
		ConfigVars:  runtime.Config.Vars,
		CLIVars:     runtime.CLIVars,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Proxy != "http://request-proxy" {
		t.Fatalf("expected request proxy to win, got %q", resolved.Proxy)
	}
	if resolved.HTTPVersion != "3" {
		t.Fatalf("expected request http version to win, got %q", resolved.HTTPVersion)
	}
	if resolved.CACertFile != filepath.Join(dir, "ca.pem") {
		t.Fatalf("unexpected CA path: %q", resolved.CACertFile)
	}
	if resolved.SelfSignedCertFile != filepath.Join(dir, "cli.pem") {
		t.Fatalf("unexpected self-signed path: %q", resolved.SelfSignedCertFile)
	}
	if resolved.Auth.CertFile != filepath.Join(dir, "client.pem") || resolved.Auth.KeyFile != filepath.Join(dir, "client.key") {
		t.Fatalf("expected auth paths to expand, got cert=%q key=%q", resolved.Auth.CertFile, resolved.Auth.KeyFile)
	}
}

func TestResolveRequestInheritsTopLevelMTLSFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	runtime := RuntimeConfig{
		RootDir:  dir,
		FileVars: map[string]string{},
		CLIVars:  map[string]string{},
		Config: Config{
			Vars:     map[string]string{},
			CertFile: "config-client.pem",
			KeyFile:  "config-client.key",
		},
	}

	resolved, err := resolveRequest(RequestSpec{
		Name:    "test",
		Method:  http.MethodGet,
		URL:     "https://example.com",
		Headers: http.Header{},
		Auth:    AuthConfig{Scheme: "mtls"},
	}, runtime, resolver{
		RequestVars: map[string]string{},
		FileVars:    runtime.FileVars,
		ConfigVars:  runtime.Config.Vars,
		CLIVars:     runtime.CLIVars,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Auth.CertFile != filepath.Join(dir, "config-client.pem") || resolved.Auth.KeyFile != filepath.Join(dir, "config-client.key") {
		t.Fatalf("expected top-level client cert defaults to flow into auth, got cert=%q key=%q", resolved.Auth.CertFile, resolved.Auth.KeyFile)
	}
}

func TestResolveRequestRejectsMTLSWithoutEffectiveCertificatePair(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		auth      AuthConfig
		wantError string
	}{
		{
			name:      "neither PEM file",
			auth:      AuthConfig{Scheme: "mtls"},
			wantError: "mtls authentication requires a certificate file",
		},
		{
			name:      "PEM certificate only",
			auth:      AuthConfig{Scheme: "mtls", CertFile: "client.pem"},
			wantError: "mtls authentication with a PEM certificate requires a key file",
		},
		{
			name:      "PEM key only",
			auth:      AuthConfig{Scheme: "mtls", KeyFile: "client.key"},
			wantError: "mtls authentication requires a certificate file",
		},
		{
			name:      "PKCS12 without password",
			auth:      AuthConfig{Scheme: "mtls", CertFile: "client.pfx"},
			wantError: "mtls authentication with a PKCS#12 certificate requires a password",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := resolveRequest(RequestSpec{
				Name:    "test",
				Method:  http.MethodGet,
				URL:     "https://example.com",
				Headers: http.Header{},
				Auth:    test.auth,
			}, RuntimeConfig{
				RootDir:  t.TempDir(),
				FileVars: map[string]string{},
				CLIVars:  map[string]string{},
				Config:   Config{Vars: map[string]string{}},
			}, resolver{})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("expected %q, got %v", test.wantError, err)
			}
		})
	}
}

func TestResolveRequestAcceptsPasswordProtectedPKCS12Certificate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	resolved, err := resolveRequest(RequestSpec{
		Name:    "test",
		Method:  http.MethodGet,
		URL:     "https://example.com",
		Headers: http.Header{},
		Auth: AuthConfig{
			Scheme:   "mtls",
			CertFile: "client.P12",
			Password: "secret",
		},
	}, RuntimeConfig{
		RootDir:  dir,
		FileVars: map[string]string{},
		CLIVars:  map[string]string{},
		Config:   Config{Vars: map[string]string{}},
	}, resolver{})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Auth.CertFile != filepath.Join(dir, "client.P12") || resolved.Auth.KeyFile != "" {
		t.Fatalf("unexpected resolved PKCS#12 credentials: %#v", resolved.Auth)
	}
}

func TestResolveRequestUsesCLISelfSignedCertOverRequest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	runtime := RuntimeConfig{
		RootDir:            dir,
		FileVars:           map[string]string{},
		CLIVars:            map[string]string{},
		SelfSignedCertFile: "cli-self.pem",
		Config: Config{
			Vars:               map[string]string{},
			SelfSignedCertFile: "config-self.pem",
		},
	}

	resolved, err := resolveRequest(RequestSpec{
		Name:               "test",
		Method:             http.MethodGet,
		URL:                "https://example.com",
		Headers:            http.Header{},
		SelfSignedCertFile: "request-self.pem",
	}, runtime, resolver{
		RequestVars: map[string]string{},
		FileVars:    runtime.FileVars,
		ConfigVars:  runtime.Config.Vars,
		CLIVars:     runtime.CLIVars,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.SelfSignedCertFile != filepath.Join(dir, "cli-self.pem") {
		t.Fatalf("expected CLI self-signed cert to win over request, got %q", resolved.SelfSignedCertFile)
	}
}

func TestResolveRequestUsesCLISelfSignedCertOverConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	runtime := RuntimeConfig{
		RootDir:            dir,
		FileVars:           map[string]string{},
		CLIVars:            map[string]string{},
		SelfSignedCertFile: "cli-self.pem",
		Config: Config{
			Vars:               map[string]string{},
			SelfSignedCertFile: "config-self.pem",
		},
	}

	resolved, err := resolveRequest(RequestSpec{
		Name:    "test",
		Method:  http.MethodGet,
		URL:     "https://example.com",
		Headers: http.Header{},
	}, runtime, resolver{
		RequestVars: map[string]string{},
		FileVars:    runtime.FileVars,
		VarsFile:    runtime.VarsFileVars,
		ConfigVars:  runtime.Config.Vars,
		CLIVars:     runtime.CLIVars,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.SelfSignedCertFile != filepath.Join(dir, "cli-self.pem") {
		t.Fatalf("expected CLI self-signed cert to win over config, got %q", resolved.SelfSignedCertFile)
	}
}

func TestChooseResolvedValueReturnsResolutionError(t *testing.T) {
	t.Parallel()

	got, err := chooseResolvedValue("{{missing}}", "http://config-proxy", resolver{})
	if err == nil || !strings.Contains(err.Error(), `unresolved variable "missing"`) {
		t.Fatalf("expected unresolved variable error, got value=%q err=%v", got, err)
	}
}

func TestChooseResolvedPathReturnsResolutionError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	got, err := chooseResolvedPath(dir, "{{missing}}", "certs/server.pem", resolver{})
	if err == nil || !strings.Contains(err.Error(), `unresolved variable "missing"`) {
		t.Fatalf("expected unresolved variable error, got value=%q err=%v", got, err)
	}
}

func TestResolveRequestPropagatesOptionalFieldResolutionErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		spec    RequestSpec
		runtime RuntimeConfig
	}{
		{
			name: "body file",
			spec: RequestSpec{Name: "test", Method: http.MethodGet, URL: "https://example.com", Headers: http.Header{}},
			runtime: RuntimeConfig{
				BodyFile: "{{missing}}",
			},
		},
		{
			name: "output file",
			spec: RequestSpec{Name: "test", Method: http.MethodGet, URL: "https://example.com", Headers: http.Header{}, OutputFile: "{{missing}}"},
		},
		{
			name: "proxy",
			spec: RequestSpec{Name: "test", Method: http.MethodGet, URL: "https://example.com", Headers: http.Header{}, Proxy: "{{missing}}"},
		},
		{
			name: "http version",
			spec: RequestSpec{Name: "test", Method: http.MethodGet, URL: "https://example.com", Headers: http.Header{}, HTTPVersion: "{{missing}}"},
		},
		{
			name: "ca cert file",
			spec: RequestSpec{Name: "test", Method: http.MethodGet, URL: "https://example.com", Headers: http.Header{}, CACertFile: "{{missing}}"},
		},
		{
			name: "self-signed cert file",
			spec: RequestSpec{Name: "test", Method: http.MethodGet, URL: "https://example.com", Headers: http.Header{}},
			runtime: RuntimeConfig{
				SelfSignedCertFile: "{{missing}}",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.runtime.RootDir = t.TempDir()
			test.runtime.FileVars = map[string]string{}
			test.runtime.CLIVars = map[string]string{}
			test.runtime.Config.Vars = map[string]string{}
			_, err := resolveRequest(test.spec, test.runtime, resolver{
				RequestVars: map[string]string{},
				FileVars:    test.runtime.FileVars,
				VarsFile:    test.runtime.VarsFileVars,
				ConfigVars:  test.runtime.Config.Vars,
				CLIVars:     test.runtime.CLIVars,
			})
			if err == nil || !strings.Contains(err.Error(), `unresolved variable "missing"`) {
				t.Fatalf("expected unresolved variable error, got %v", err)
			}
		})
	}
}

func TestResolveRequestRootsRelativeCLIPaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	runtime := RuntimeConfig{
		RootDir:    dir,
		FileVars:   map[string]string{},
		CLIVars:    map[string]string{},
		BodyFile:   "payloads/request.json",
		OutputFile: "output/response.json",
		Config:     Config{Vars: map[string]string{}},
	}

	resolved, err := resolveRequest(RequestSpec{
		Name:    "test",
		Method:  http.MethodPost,
		URL:     "https://example.com",
		Headers: http.Header{},
	}, runtime, resolver{
		RequestVars: map[string]string{},
		FileVars:    runtime.FileVars,
		ConfigVars:  runtime.Config.Vars,
		CLIVars:     runtime.CLIVars,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.BodyFile != filepath.Join(dir, "payloads/request.json") {
		t.Fatalf("expected rooted CLI body file, got %q", resolved.BodyFile)
	}
	if resolved.OutputFile != filepath.Join(dir, "output/response.json") {
		t.Fatalf("expected rooted CLI output file, got %q", resolved.OutputFile)
	}
}

func TestResolveRequestRootsRelativeRequestOutputPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	runtime := RuntimeConfig{
		RootDir:  dir,
		FileVars: map[string]string{},
		CLIVars:  map[string]string{},
		Config:   Config{Vars: map[string]string{}},
	}

	resolved, err := resolveRequest(RequestSpec{
		Name:       "test",
		Method:     http.MethodGet,
		URL:        "https://example.com",
		Headers:    http.Header{},
		OutputFile: "responses/request.json",
	}, runtime, resolver{
		RequestVars: map[string]string{},
		FileVars:    runtime.FileVars,
		ConfigVars:  runtime.Config.Vars,
		CLIVars:     runtime.CLIVars,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.OutputFile != filepath.Join(dir, "responses/request.json") {
		t.Fatalf("expected rooted request output file, got %q", resolved.OutputFile)
	}
}

func TestResolveRequestExplicitInsecureFalseOverridesDefaults(t *testing.T) {
	t.Parallel()

	resolved, err := resolveRequest(RequestSpec{
		Name:        "test",
		Method:      http.MethodGet,
		URL:         "https://example.com",
		Headers:     http.Header{},
		Insecure:    false,
		InsecureSet: true,
	}, RuntimeConfig{
		Config:   Config{Vars: map[string]string{}, Insecure: true},
		Insecure: true,
		FileVars: map[string]string{},
		CLIVars:  map[string]string{},
	}, resolver{})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Insecure {
		t.Fatal("expected explicit request insecure=false to override insecure defaults")
	}
}

func TestResolveRequestInheritsInsecureDefaultsWithoutDirective(t *testing.T) {
	t.Parallel()

	resolved, err := resolveRequest(RequestSpec{
		Name:    "test",
		Method:  http.MethodGet,
		URL:     "https://example.com",
		Headers: http.Header{},
	}, RuntimeConfig{
		Config:   Config{Vars: map[string]string{}, Insecure: true},
		FileVars: map[string]string{},
		CLIVars:  map[string]string{},
	}, resolver{})
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.Insecure {
		t.Fatal("expected insecure config default to be inherited")
	}
}

func TestExecuteRequestRejectsUnknownAuthScheme(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	_, _, _, err := executeRequest(context.Background(), executionPlan{
		Request: RequestSpec{
			Name:    "bad auth",
			Method:  http.MethodGet,
			URL:     server.URL,
			Headers: http.Header{},
			Auth:    AuthConfig{Scheme: "madeup"},
		},
		Runtime: RuntimeConfig{Config: Config{Vars: map[string]string{}}, FileVars: map[string]string{}, CLIVars: map[string]string{}},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported auth scheme") {
		t.Fatalf("expected unsupported auth scheme error, got %v", err)
	}
}

func TestExecuteRequestRejectsHTTP2OnHTTPURL(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	_, _, _, err := executeRequest(context.Background(), executionPlan{
		Request: RequestSpec{
			Name:        "http2 over http",
			Method:      http.MethodGet,
			URL:         server.URL,
			Headers:     http.Header{},
			HTTPVersion: "2",
		},
		Runtime: RuntimeConfig{Config: Config{Vars: map[string]string{}}, FileVars: map[string]string{}, CLIVars: map[string]string{}},
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP/2 requires an https URL") {
		t.Fatalf("expected strict HTTP/2 error, got %v", err)
	}
}

func TestBuildTransportRejectsHTTP2Proxy(t *testing.T) {
	t.Parallel()

	_, _, err := buildTransport(resolvedRequest{
		RequestSpec: RequestSpec{
			URL:         "https://example.com",
			HTTPVersion: "2",
			Proxy:       "http://proxy.local:8080",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP/2 proxy support is not available") {
		t.Fatalf("expected strict HTTP/2 proxy error, got %v", err)
	}
}

func TestGetAzureTokenUsesCustomTokenURLScopeAndTLSConfig(t *testing.T) {
	var gotGrantType, gotScope string
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		gotGrantType = r.Form.Get("grant_type")
		gotScope = r.Form.Get("scope")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token-value"}`))
	}))
	defer tokenServer.Close()

	cert := tokenServer.Certificate()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	certFile := filepath.Join(t.TempDir(), "server.pem")
	if err := os.WriteFile(certFile, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AZURE_ACCESS_TOKEN", "ambient-token")

	token, err := getAzureToken(context.Background(), resolvedRequest{
		Timeout:            5 * time.Second,
		SelfSignedCertFile: certFile,
		RequestSpec:        RequestSpec{URL: tokenServer.URL},
		Auth: AuthConfig{
			Scheme:       "azuread",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			Scope:        "https://vault.azure.net/.default",
			TokenURL:     tokenServer.URL,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if token != "token-value" {
		t.Fatalf("unexpected token %q", token)
	}
	if gotGrantType != "client_credentials" || gotScope != "https://vault.azure.net/.default" {
		t.Fatalf("unexpected token request form grant_type=%q scope=%q", gotGrantType, gotScope)
	}
}

func TestGetAzureTokenUsesExplicitTokenBeforeRequestingNewOne(t *testing.T) {
	t.Parallel()

	token, err := getAzureToken(context.Background(), resolvedRequest{
		Auth: AuthConfig{
			Scheme: "azuread",
			Token:  "explicit-token",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if token != "explicit-token" {
		t.Fatalf("unexpected token %q", token)
	}
}

func TestBuildTLSConfigAcceptsSelfSignedCertFile(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	cert := server.Certificate()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	certFile := filepath.Join(t.TempDir(), "server.pem")
	if err := os.WriteFile(certFile, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	tlsConfig, err := buildTLSConfig(resolvedRequest{SelfSignedCertFile: certFile})
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
}

func TestBuildTLSConfigLoadsPasswordProtectedPKCS12Certificate(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	serverCertificate := server.Certificate()
	pfxData, err := pkcs12.Modern2023.Encode(
		server.TLS.Certificates[0].PrivateKey,
		serverCertificate,
		nil,
		"test-password",
	)
	if err != nil {
		t.Fatal(err)
	}
	pfxFile := filepath.Join(t.TempDir(), "client.pfx")
	if err := os.WriteFile(pfxFile, pfxData, 0o600); err != nil {
		t.Fatal(err)
	}

	tlsConfig, err := buildTLSConfig(resolvedRequest{
		Auth: AuthConfig{
			Scheme:   "mtls",
			CertFile: pfxFile,
			Password: "test-password",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tlsConfig.Certificates) != 1 || tlsConfig.Certificates[0].Leaf == nil {
		t.Fatalf("expected decoded PKCS#12 client certificate, got %#v", tlsConfig.Certificates)
	}
	if !tlsConfig.Certificates[0].Leaf.Equal(serverCertificate) {
		t.Fatal("decoded PKCS#12 leaf certificate does not match")
	}
}
