package gorc

import (
	"context"
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

func TestSelectRequestsPreservesDistinctSelections(t *testing.T) {
	t.Parallel()

	requests := []RequestSpec{
		{Name: "dup", Method: http.MethodPost, URL: "https://example.com", Body: "one"},
		{Name: "dup", Method: http.MethodPost, URL: "https://example.com", Body: "two"},
	}

	selected, err := selectRequests(requests, RunOptions{Indices: []int{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 2 || selected[0].Body != "one" || selected[1].Body != "two" {
		t.Fatalf("expected both requests to be preserved, got %#v", selected)
	}
}

func TestRunInteractiveLoopsUntilQuit(t *testing.T) {
	t.Parallel()

	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	requests := []RequestSpec{{
		Name:    "once",
		Method:  http.MethodGet,
		URL:     server.URL,
		Headers: http.Header{},
	}}

	var stdout, stderr strings.Builder
	err := runInteractive(
		context.Background(),
		requests,
		RuntimeConfig{Config: Config{Vars: map[string]string{}}, FileVars: map[string]string{}, CLIVars: map[string]string{}},
		&stdout,
		&stderr,
		strings.NewReader("1\nq\n"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("expected exactly one request execution, got %d", hits)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected clean quit without stderr, got %q", stderr.String())
	}
}

func TestParseRunOptionsUsesSingleHTTPFileInCurrentDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	requestPath := filepath.Join(dir, "only.http")
	if err := os.WriteFile(requestPath, []byte("GET https://example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chdir(cwd)
	}()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	options, err := parseRunOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if options.FilePath != "only.http" {
		t.Fatalf("expected implicit file selection, got %q", options.FilePath)
	}
}

func TestParseRunOptionsErrorsWhenMultipleHTTPFilesExist(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"one.http", "two.http"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("GET https://example.com\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chdir(cwd)
	}()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	_, err = parseRunOptions(nil)
	if err == nil || !strings.Contains(err.Error(), "multiple .http files found") {
		t.Fatalf("expected multiple-file error, got %v", err)
	}
}

func TestParseRunOptionsSupportsInteractiveShortFlag(t *testing.T) {
	t.Parallel()

	options, err := parseRunOptions([]string{"-i", "requests.http"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.Interactive {
		t.Fatal("expected -i to enable interactive mode")
	}
	if options.FilePath != "requests.http" {
		t.Fatalf("unexpected file path %q", options.FilePath)
	}
}

func TestParseRunOptionsSupportsMixedShortFlags(t *testing.T) {
	t.Parallel()

	options, err := parseRunOptions([]string{
		"-a",
		"-c", "config.json",
		"-o", "response.out",
		"-b", "body.json",
		"-p", "http://proxy.local:8080",
		"-H", "2",
		"-l", "debug",
		"-C",
		"-s", "server.pem",
		"-k",
		"-n", "login",
		"-v", "token=abc",
		"-x", "1,2",
		"-e", "vars.json",
		"requests.http",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.All || !options.Insecure || !options.NoColor {
		t.Fatalf("expected bool short flags to be set: %#v", options)
	}
	if options.ConfigPath != "config.json" || options.OutputFile != "response.out" || options.BodyFile != "body.json" {
		t.Fatalf("unexpected file options: %#v", options)
	}
	if options.Proxy != "http://proxy.local:8080" || options.HTTPVersion != "2" || options.LogLevel != "debug" || options.SelfSignedCertFile != "server.pem" {
		t.Fatalf("unexpected transport options: %#v", options)
	}
	if len(options.Names) != 1 || options.Names[0] != "login" {
		t.Fatalf("unexpected names: %#v", options.Names)
	}
	if len(options.Indices) != 2 || options.Indices[0] != 1 || options.Indices[1] != 2 {
		t.Fatalf("unexpected indices: %#v", options.Indices)
	}
	if options.VarsFile != "vars.json" || options.Vars["token"] != "abc" {
		t.Fatalf("unexpected vars config: file=%q vars=%#v", options.VarsFile, options.Vars)
	}
}

func TestParseRunOptionsSupportsNoColorFlag(t *testing.T) {
	t.Parallel()

	options, err := parseRunOptions([]string{"--no-color", "requests.http"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.NoColor {
		t.Fatal("expected --no-color to disable color")
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
