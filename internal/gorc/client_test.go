package gorc

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if resolved.SelfSignedCertFile != filepath.Join(dir, "request-self.pem") {
		t.Fatalf("unexpected self-signed path: %q", resolved.SelfSignedCertFile)
	}
	if resolved.Auth.CertFile != filepath.Join(dir, "client.pem") || resolved.Auth.KeyFile != filepath.Join(dir, "client.key") {
		t.Fatalf("expected auth paths to expand, got cert=%q key=%q", resolved.Auth.CertFile, resolved.Auth.KeyFile)
	}
}

func TestExecuteRequestRejectsUnknownAuthScheme(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	_, _, err := executeRequest(context.Background(), executionPlan{
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

	_, _, err := executeRequest(context.Background(), executionPlan{
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

func TestGetAzureTokenUsesCustomTokenURLScopeAndTLSConfig(t *testing.T) {
	t.Parallel()

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
