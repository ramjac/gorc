package gorc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseHTTPFileMultipleRequests(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "requests.http")
	content := `@host = https://example.com
###
# @name list users
GET {{host}}/users
Accept: application/json

###
# @name create user
# @auth basic username={{username}} ******
@username = alice
@password = secret
POST {{host}}/users
Content-Type: application/json

{"name":"Alice"}`
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
	if parsed.Requests[1].FileVars["username"] != "alice" {
		t.Fatalf("expected section variable to be preserved")
	}
}
