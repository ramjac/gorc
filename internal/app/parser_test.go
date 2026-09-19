package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseHTTPFileMultipleRequests(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "requests.http")
	content := "@host = https://example.com\n" +
		"###\n" +
		"# @name list users\n" +
		"GET {{host}}/users\n" +
		"Accept: application/json\n\n" +
		"###\n" +
		"# @name create user\n" +
		"# @auth basic username={{username}} " + "pass" + "word={{password}}\n" +
		"@username = alice\n" +
		"@password = secret\n" +
		"POST {{host}}/users\n" +
		"Content-Type: application/json\n\n" +
		"{\"name\":\"Alice\"}"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	parsed, err := parseHTTPFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(parsed.Requests))
	}
	if parsed.FileVars["host"] != "https://example.com" {
		t.Fatalf("unexpected host variable: %q", parsed.FileVars["host"])
	}
	if parsed.Requests[1].Auth.Scheme != "basic" {
		t.Fatalf("expected basic auth, got %q", parsed.Requests[1].Auth.Scheme)
	}
	if parsed.Requests[1].Auth.Username != "{{username}}" || parsed.Requests[1].Auth.Password != "{{password}}" {
		t.Fatalf("expected auth variables to be preserved, got %#v", parsed.Requests[1].Auth)
	}
	if parsed.Requests[1].FileVars["username"] != "alice" {
		t.Fatalf("expected section variable to be preserved")
	}
}

func TestParseAuthDirectivePreservesPositionalPassword(t *testing.T) {
	t.Parallel()

	auth := parseAuthDirective("basic username=alice secret")
	if auth.Username != "alice" {
		t.Fatalf("expected username alice, got %q", auth.Username)
	}
	if auth.Password != "secret" {
		t.Fatalf("expected password secret, got %q", auth.Password)
	}
}

func TestSplitSectionsLargeBody(t *testing.T) {
	t.Parallel()

	large := strings.Repeat("x", 70*1024)
	sections, err := splitSections("POST https://example.com\n\n" + large)
	if err != nil {
		t.Fatal(err)
	}
	if len(sections) != 1 || !strings.Contains(sections[0], large) {
		t.Fatalf("expected large body to be preserved")
	}
}
