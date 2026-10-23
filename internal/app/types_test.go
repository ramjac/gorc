package app

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestAuthConfigJSONSerialization(t *testing.T) {
	t.Parallel()

	jsonInput := `{
		"scheme": "bearer",
		"username": "user1",
		"password": "secretpassword",
		"token": "token123",
		"cert_file": "cert.pem",
		"key_file": "key.pem",
		"ca_cert_file": "ca.pem",
		"tenant_id": "tenant-uuid",
		"client_id": "client-uuid",
		"client_secret": "client-secret-val",
		"scope": "openid profile",
		"resource": "https://api.example.com",
		"token_url": "https://login.example.com/oauth2/v2.0/token"
	}`

	var auth AuthConfig
	if err := json.Unmarshal([]byte(jsonInput), &auth); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if auth.Scheme != "bearer" {
		t.Errorf("expected Scheme 'bearer', got %q", auth.Scheme)
	}
	if auth.Username != "user1" {
		t.Errorf("expected Username 'user1', got %q", auth.Username)
	}
	if auth.Password != "secretpassword" {
		t.Errorf("expected Password 'secretpassword', got %q", auth.Password)
	}
	if auth.Token != "token123" {
		t.Errorf("expected Token 'token123', got %q", auth.Token)
	}
	if auth.CertFile != "cert.pem" {
		t.Errorf("expected CertFile 'cert.pem', got %q", auth.CertFile)
	}
	if auth.KeyFile != "key.pem" {
		t.Errorf("expected KeyFile 'key.pem', got %q", auth.KeyFile)
	}
	if auth.CACertFile != "ca.pem" {
		t.Errorf("expected CACertFile 'ca.pem', got %q", auth.CACertFile)
	}
	if auth.TenantID != "tenant-uuid" {
		t.Errorf("expected TenantID 'tenant-uuid', got %q", auth.TenantID)
	}
	if auth.ClientID != "client-uuid" {
		t.Errorf("expected ClientID 'client-uuid', got %q", auth.ClientID)
	}
	if auth.ClientSecret != "client-secret-val" {
		t.Errorf("expected ClientSecret 'client-secret-val', got %q", auth.ClientSecret)
	}
	if auth.Scope != "openid profile" {
		t.Errorf("expected Scope 'openid profile', got %q", auth.Scope)
	}
	if auth.Resource != "https://api.example.com" {
		t.Errorf("expected Resource 'https://api.example.com', got %q", auth.Resource)
	}
	if auth.TokenURL != "https://login.example.com/oauth2/v2.0/token" {
		t.Errorf("expected TokenURL 'https://login.example.com/oauth2/v2.0/token', got %q", auth.TokenURL)
	}

	marshaled, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	var remarshaled AuthConfig
	if err := json.Unmarshal(marshaled, &remarshaled); err != nil {
		t.Fatalf("unexpected unmarshal error of marshaled JSON: %v", err)
	}

	if remarshaled != auth {
		t.Errorf("expected remarshaled struct %#v to match original %#v", remarshaled, auth)
	}
}

func TestConfigJSONSerialization(t *testing.T) {
	t.Parallel()

	jsonInput := `{
		"vars": {"env": "prod", "host": "localhost"},
		"proxy": "http://127.0.0.1:8080",
		"http_version": "2",
		"log_level": "debug",
		"format": "json",
		"no_color": true,
		"insecure": true,
		"ca_cert_file": "/path/to/ca.crt",
		"self_signed_cert_file": "/path/to/self.crt",
		"cert_file": "/path/to/client.crt",
		"key_file": "/path/to/client.key",
		"timeout": "30s",
		"auth": {
			"scheme": "basic",
			"username": "admin"
		}
	}`

	var cfg Config
	if err := json.Unmarshal([]byte(jsonInput), &cfg); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if cfg.Vars["env"] != "prod" || cfg.Vars["host"] != "localhost" {
		t.Errorf("unexpected Vars: %#v", cfg.Vars)
	}
	if cfg.Proxy != "http://127.0.0.1:8080" {
		t.Errorf("expected Proxy 'http://127.0.0.1:8080', got %q", cfg.Proxy)
	}
	if cfg.HTTPVersion != "2" {
		t.Errorf("expected HTTPVersion '2', got %q", cfg.HTTPVersion)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected LogLevel 'debug', got %q", cfg.LogLevel)
	}
	if cfg.Format != "json" {
		t.Errorf("expected Format 'json', got %q", cfg.Format)
	}
	if !cfg.NoColor {
		t.Errorf("expected NoColor true, got false")
	}
	if !cfg.Insecure {
		t.Errorf("expected Insecure true, got false")
	}
	if cfg.CACertFile != "/path/to/ca.crt" {
		t.Errorf("expected CACertFile '/path/to/ca.crt', got %q", cfg.CACertFile)
	}
	if cfg.SelfSignedCertFile != "/path/to/self.crt" {
		t.Errorf("expected SelfSignedCertFile '/path/to/self.crt', got %q", cfg.SelfSignedCertFile)
	}
	if cfg.CertFile != "/path/to/client.crt" {
		t.Errorf("expected CertFile '/path/to/client.crt', got %q", cfg.CertFile)
	}
	if cfg.KeyFile != "/path/to/client.key" {
		t.Errorf("expected KeyFile '/path/to/client.key', got %q", cfg.KeyFile)
	}
	if cfg.Timeout != "30s" {
		t.Errorf("expected Timeout '30s', got %q", cfg.Timeout)
	}
	if cfg.Auth.Scheme != "basic" || cfg.Auth.Username != "admin" {
		t.Errorf("unexpected Auth: %#v", cfg.Auth)
	}
}

func TestHTTPFileAndRequestSpecInitialization(t *testing.T) {
	t.Parallel()

	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")

	req := RequestSpec{
		Name:               "Test Request",
		Method:             "POST",
		URL:                "https://api.example.com/test",
		Headers:            headers,
		Body:               `{"key":"value"}`,
		BodyFile:           "body.json",
		OutputFile:         "output.json",
		Proxy:              "http://proxy.local",
		HTTPVersion:        "1.1",
		CACertFile:         "ca.crt",
		SelfSignedCertFile: "self.crt",
		Insecure:           true,
		InsecureSet:        true,
		Auth: AuthConfig{
			Scheme: "bearer",
			Token:  "secret",
		},
		FileVars: map[string]string{
			"foo": "bar",
		},
		SourcePath: "/tmp/test.http",
	}

	file := HTTPFile{
		FileVars: map[string]string{
			"global": "value",
		},
		Requests: []RequestSpec{req},
	}

	if len(file.Requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(file.Requests))
	}

	gotReq := file.Requests[0]
	if gotReq.Name != "Test Request" {
		t.Errorf("expected Name 'Test Request', got %q", gotReq.Name)
	}
	if gotReq.Method != "POST" {
		t.Errorf("expected Method 'POST', got %q", gotReq.Method)
	}
	if gotReq.URL != "https://api.example.com/test" {
		t.Errorf("expected URL 'https://api.example.com/test', got %q", gotReq.URL)
	}
	if gotReq.Headers.Get("Content-Type") != "application/json" {
		t.Errorf("expected Header Content-Type 'application/json', got %q", gotReq.Headers.Get("Content-Type"))
	}
	if gotReq.Insecure != true || gotReq.InsecureSet != true {
		t.Errorf("expected Insecure and InsecureSet to be true")
	}
	if gotReq.Auth.Scheme != "bearer" || gotReq.Auth.Token != "secret" {
		t.Errorf("unexpected Auth config: %#v", gotReq.Auth)
	}
	if gotReq.FileVars["foo"] != "bar" {
		t.Errorf("unexpected Request FileVars: %#v", gotReq.FileVars)
	}
	if file.FileVars["global"] != "value" {
		t.Errorf("unexpected HTTPFile FileVars: %#v", file.FileVars)
	}
}

func TestRunOptionsAndRuntimeConfigZeroValues(t *testing.T) {
	t.Parallel()

	var runOpts RunOptions
	if runOpts.FilePath != "" || runOpts.All != false || runOpts.Timeout != 0 {
		t.Errorf("unexpected non-zero RunOptions: %#v", runOpts)
	}

	var runtimeCfg RuntimeConfig
	if runtimeCfg.RootDir != "" || runtimeCfg.Timeout != 0 || runtimeCfg.ColorEnabled != false {
		t.Errorf("unexpected non-zero RuntimeConfig: %#v", runtimeCfg)
	}

	opts := RunOptions{
		FilePath:     "test.http",
		Names:        []string{"req1"},
		Indices:      []int{0},
		Timeout:      10 * time.Second,
		SelectedAuth: AuthConfig{Scheme: "basic"},
	}

	if opts.FilePath != "test.http" {
		t.Errorf("expected FilePath 'test.http', got %q", opts.FilePath)
	}
	if opts.Timeout != 10*time.Second {
		t.Errorf("expected Timeout 10s, got %v", opts.Timeout)
	}

	plan := executionPlan{
		Request: RequestSpec{Name: "plan_req"},
		Runtime: RuntimeConfig{RootDir: "/app"},
	}

	if plan.Request.Name != "plan_req" {
		t.Errorf("expected Request.Name 'plan_req', got %q", plan.Request.Name)
	}
	if plan.Runtime.RootDir != "/app" {
		t.Errorf("expected Runtime.RootDir '/app', got %q", plan.Runtime.RootDir)
	}
}
