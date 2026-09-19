package gorc

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDefaultLoggingIsSilent(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	requestFile := writeHTTPFile(t, "@base = "+server.URL+"\n\nGET {{base}}\n")

	var stdout, stderr strings.Builder
	err := run(RunOptions{FilePath: requestFile}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output by default, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "ok") {
		t.Fatalf("expected response body in stdout, got %q", stdout.String())
	}
}

func TestRunTraceLoggingEmitsDiagnostics(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:trace-pass"))
		if r.Header.Get("Authorization") != expected {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("traced"))
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://localhost:" + serverURL.Port()
	requestFile := writeHTTPFile(t, "@base = "+baseURL+"\n###\n# @name traced request\nGET {{base}}\n")

	var stdout, stderr strings.Builder
	err = run(RunOptions{
		FilePath: requestFile,
		LogLevel: "trace",
		SelectedAuth: AuthConfig{
			Scheme:   "basic",
			Username: "alice",
			Password: "trace-pass",
		},
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "traced") {
		t.Fatalf("expected response body in stdout, got %q", stdout.String())
	}
	logs := stderr.String()
	for _, want := range []string{
		"[INFO] executing request",
		"[DEBUG] configuring basic authentication",
		"[TRACE] round trip start",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("expected log output to contain %q, got %q", want, logs)
		}
	}
}

func writeHTTPFile(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "requests.http")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
