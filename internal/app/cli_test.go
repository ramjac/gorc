package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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
	err := run(context.Background(), RunOptions{FilePath: requestFile}, &stdout, &stderr)
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

func TestRunJSONFormatFromFlagAndConfig(t *testing.T) {
	t.Parallel()

	handler := http.NewServeMux()
	handler.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "one=1")
		w.Header().Add("Set-Cookie", "two=2")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	handler.HandleFunc("/bad", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusBadRequest)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	requestFile := writeHTTPFile(t, "# @name first\nGET "+server.URL+"/ok\n###\n# @name second\nGET "+server.URL+"/bad\n")
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"format":"json","log_level":"info"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--config", configPath, "--all", requestFile},
		{"--config", configPath, "--format", "json", "--all", requestFile},
	} {
		var stdout, stderr strings.Builder
		if code := runWithContext(context.Background(), args, &stdout, &stderr); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
		var document jsonDocument
		if err := json.Unmarshal([]byte(stdout.String()), &document); err != nil {
			t.Fatalf("invalid JSON stdout %q: %v", stdout.String(), err)
		}
		if len(document.Responses) != 2 || document.Summary == nil || document.Summary.Successful != 1 || document.Summary.Failed != 1 {
			t.Fatalf("unexpected document: %+v", document)
		}
		first := document.Responses[0]
		if first.Request != "first" || first.StatusCode != 200 || first.Body != `{"ok":true}` || first.BodyBytes != len(first.Body) ||
			len(first.Headers.Values("Set-Cookie")) != 2 || first.BodyTruncated || first.BodyOmitted {
			t.Fatalf("unexpected first response: %+v", first)
		}
		if document.Responses[1].Request != "second" || document.Responses[1].StatusCode != 400 {
			t.Fatalf("unexpected second response: %+v", document.Responses[1])
		}
		if strings.Contains(stdout.String(), "\x1b[") || !strings.Contains(stderr.String(), "completed with status=") {
			t.Fatalf("expected uncolored JSON stdout and diagnostic stderr, stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	}
}

func TestRunJSONFormatOverrideAndInvalidFormat(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	requestFile := writeHTTPFile(t, "GET "+server.URL+"\n")
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"format":"json"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	if code := runWithContext(context.Background(), []string{"--config", configPath, "--format", "text", requestFile}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "### ") {
		t.Fatalf("expected text override, got %q", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runWithContext(context.Background(), []string{"--format", "json", requestFile}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout.String()), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["summary"]; ok {
		t.Fatalf("single response should have no summary: %s", stdout.String())
	}
	var responses []jsonResponse
	if err := json.Unmarshal(raw["responses"], &responses); err != nil || len(responses) != 1 || responses[0].Body != "ok" {
		t.Fatalf("unexpected single response: %+v, err=%v", responses, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runWithContext(context.Background(), []string{"--format", "xml", requestFile}, &stdout, &stderr); code != 1 {
		t.Fatalf("expected invalid format error, exit=%d stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), `invalid output format "xml"`) {
		t.Fatalf("expected stderr-only format error, stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunJSONFormatPreservesOutputFileAndBodyLimits(t *testing.T) {
	t.Parallel()

	large := strings.Repeat("x", maxResponsePreviewSize+5)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/binary" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte{0, 1, 2})
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(large))
	}))
	defer server.Close()
	requestFile := writeHTTPFile(t, "GET "+server.URL+"/text\n###\nGET "+server.URL+"/binary\n")
	outputFile := filepath.Join(t.TempDir(), "responses")
	var stdout, stderr strings.Builder
	if code := runWithContext(context.Background(), []string{"--format", "json", "--all", "--output", outputFile, requestFile}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var document jsonDocument
	if err := json.Unmarshal([]byte(stdout.String()), &document); err != nil {
		t.Fatal(err)
	}
	text, binary := document.Responses[0], document.Responses[1]
	if text.BodyBytes != len(large) || len(text.Body) != maxResponsePreviewSize || !text.BodyTruncated || text.BodyOmitted || text.OutputFile != outputFile {
		t.Fatalf("unexpected text preview: bytes=%d preview=%d truncated=%t omitted=%t file=%q", text.BodyBytes, len(text.Body), text.BodyTruncated, text.BodyOmitted, text.OutputFile)
	}
	if binary.Body != "" || !binary.BodyOmitted || binary.BodyBytes != 3 || binary.BodyTruncated || binary.OutputFile != outputFile {
		t.Fatalf("unexpected binary response: %+v", binary)
	}
	data, err := os.ReadFile(outputFile)
	if err != nil || string(data) != large+"\x00\x01\x02" {
		t.Fatalf("unexpected raw output file: length=%d err=%v", len(data), err)
	}
}

func TestRunInteractiveJSONWritesPromptsToStderr(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	requests := []RequestSpec{{Name: "once", Method: http.MethodGet, URL: server.URL, Headers: http.Header{}}}
	var stdout, stderr strings.Builder
	err := runInteractive(context.Background(), requests, RuntimeConfig{
		Format: "json", Config: Config{Vars: map[string]string{}},
	}, &stdout, &stderr, strings.NewReader("1\n1\nq\n"))
	if err != nil {
		t.Fatal(err)
	}
	var document jsonDocument
	if err := json.Unmarshal([]byte(stdout.String()), &document); err != nil {
		t.Fatalf("invalid interactive JSON %q: %v", stdout.String(), err)
	}
	if len(document.Responses) != 2 || document.Summary == nil || document.Summary.Successful != 2 {
		t.Fatalf("unexpected interactive results: %+v", document)
	}
	if !strings.Contains(stderr.String(), "Available requests:") || strings.Contains(stdout.String(), "Available requests:") {
		t.Fatalf("unexpected prompt streams stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunVersionFlagPrintsVersion(t *testing.T) {
	// Not parallel: mutates the package-level Version var, which other
	// parallel tests read indirectly via newCLIParser when constructing a
	// cobra.Command.
	originalVersion := Version
	Version = "v0.5.0-beta"
	defer func() { Version = originalVersion }()

	var stdout, stderr strings.Builder
	exitCode := runWithContext(context.Background(), []string{"--version"}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", exitCode, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "gorc v0.5.0-beta" {
		t.Fatalf("expected version output %q, got %q", "gorc v0.5.0-beta", got)
	}
}

func TestRunOverwritesOutputFileOnEachInvocation(t *testing.T) {

	handler := http.NewServeMux()
	handler.HandleFunc("/first", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("first"))
	})
	handler.HandleFunc("/second", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("second"))
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	dir := t.TempDir()
	requestFile := filepath.Join(dir, "requests.http")
	requests := "GET " + server.URL + "/first\n###\nGET " + server.URL + "/second\n"
	if err := os.WriteFile(requestFile, []byte(requests), 0o644); err != nil {
		t.Fatal(err)
	}
	outputFile := filepath.Join(dir, "responses.txt")
	options := RunOptions{FilePath: requestFile, All: true, OutputFile: outputFile}

	for range 2 {
		if err := run(context.Background(), options, io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(data), "firstsecond"; got != want {
			t.Fatalf("expected one invocation's response bodies, got %q want %q", got, want)
		}
	}
}

func TestRunTraceLoggingEmitsDiagnostics(t *testing.T) {
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
	err = run(context.Background(), RunOptions{
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
		"executing request",
		"configuring basic authentication",
		"round trip start",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("expected log output to contain %q, got %q", want, logs)
		}
	}
	if !regexp.MustCompile(`completed with status=200 OK duration=\d+(?:\.\d+)?(?:ns|µs|ms|s)`).MatchString(logs) {
		t.Fatalf("expected completion log to include duration, got %q", logs)
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

func TestRunInteractiveQuitsOnFinalCommandWithoutTrailingNewline(t *testing.T) {
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
	// "q" with no trailing newline: ReadString returns it together with io.EOF.
	err := runInteractive(
		context.Background(),
		requests,
		RuntimeConfig{Config: Config{Vars: map[string]string{}}, FileVars: map[string]string{}, CLIVars: map[string]string{}},
		&stdout,
		&stderr,
		strings.NewReader("q"),
	)
	if err != nil {
		t.Fatalf("expected clean quit on EOF-terminated command, got %v", err)
	}
	if hits != 0 {
		t.Fatalf("expected no request execution, got %d", hits)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected clean quit without stderr, got %q", stderr.String())
	}
}

func TestParseRunOptionsUsesSingleHTTPFileInCurrentDirectory(t *testing.T) {
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

func TestRunReturnsCancellationErrorForCanceledContext(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	requestFile := writeHTTPFile(t, "GET "+server.URL+"\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr strings.Builder
	err := run(ctx, RunOptions{FilePath: requestFile}, &stdout, &stderr)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestRunExitCodeForCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	requestFile := writeHTTPFile(t, "GET "+server.URL+"\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr strings.Builder
	code := runWithContext(ctx, []string{requestFile}, &stdout, &stderr)
	if code != 130 {
		t.Fatalf("expected exit code 130, got %d", code)
	}
	if !strings.Contains(stderr.String(), "cancelled") {
		t.Fatalf("expected cancellation message, got %q", stderr.String())
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

func TestRunRejectsInteractiveCombinedWithSelectors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	requestFile := filepath.Join(dir, "requests.http")
	if err := os.WriteFile(requestFile, []byte("GET https://example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []RunOptions{
		{FilePath: requestFile, Interactive: true, All: true},
		{FilePath: requestFile, Interactive: true, Indices: []int{1}},
		{FilePath: requestFile, Interactive: true, Names: []string{"anything"}},
	}
	for _, options := range cases {
		if err := run(context.Background(), options, io.Discard, io.Discard); err == nil {
			t.Fatalf("expected conflict error for options %#v", options)
		}
	}
}

func TestSelectRequestsRejectsConflictingAllSelectors(t *testing.T) {
	t.Parallel()

	requests := []RequestSpec{{Name: "one"}, {Name: "two"}}
	if _, err := selectRequests(requests, RunOptions{All: true, Names: []string{"missing"}}); err == nil {
		t.Fatal("expected --all and --name conflict to be rejected")
	}
	if _, err := selectRequests(requests, RunOptions{All: true, Indices: []int{1}}); err == nil {
		t.Fatal("expected --all and --index conflict to be rejected")
	}
}
