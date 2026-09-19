package gorc

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
