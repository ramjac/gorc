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
	if _, ok := parsed.Requests[0].FileVars["host"]; ok {
		t.Fatalf("expected shared file variable to stay out of request-local FileVars")
	}
	if _, ok := parsed.Requests[1].FileVars["host"]; ok {
		t.Fatalf("expected shared file variable to stay out of request-local FileVars")
	}
}

func TestParseSectionPreservesInlineBodyTrailingNewline(t *testing.T) {
	t.Parallel()

	section := "POST https://example.com\nContent-Type: text/plain\n\nline1\nline2\n"
	spec, _, hasRequest, err := parseSection(section, "test.http")
	if err != nil {
		t.Fatal(err)
	}
	if !hasRequest {
		t.Fatal("expected request to be parsed")
	}
	if spec.Body != "line1\nline2\n" {
		t.Fatalf("expected trailing newline to be preserved, got %q", spec.Body)
	}
}

func TestParseSectionWithoutTrailingBlankLineHasNoTrailingNewline(t *testing.T) {
	t.Parallel()

	section := "POST https://example.com\nContent-Type: text/plain\n\nline1\nline2"
	spec, _, hasRequest, err := parseSection(section, "test.http")
	if err != nil {
		t.Fatal(err)
	}
	if !hasRequest {
		t.Fatal("expected request to be parsed")
	}
	if spec.Body != "line1\nline2" {
		t.Fatalf("expected no trailing newline, got %q", spec.Body)
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

func TestParseAuthDirectiveBearerTokenWithEqualsPadding(t *testing.T) {
	t.Parallel()

	auth := parseAuthDirective("bearer abc=")
	if auth.Token != "abc=" {
		t.Fatalf("expected raw token 'abc=', got %q", auth.Token)
	}
}

func TestParseAuthDirectivePositionalOnlyUsername(t *testing.T) {
	t.Parallel()

	auth := parseAuthDirective("basic alice")
	if auth.Username != "alice" {
		t.Fatalf("expected username alice, got %q", auth.Username)
	}
	if auth.Password != "" {
		t.Fatalf("expected empty password, got %q", auth.Password)
	}
}

func TestParseAuthDirectivePositionalPasswordWithEquals(t *testing.T) {
	t.Parallel()

	auth := parseAuthDirective("basic alice abc=def")
	if auth.Username != "alice" {
		t.Fatalf("expected username alice, got %q", auth.Username)
	}
	if auth.Password != "abc=def" {
		t.Fatalf("expected password 'abc=def', got %q", auth.Password)
	}
}

func TestParseInsecureDirectiveTracksExplicitFalse(t *testing.T) {
	t.Parallel()

	spec := RequestSpec{}
	parseDirective(&spec, "# @insecure false")
	if !spec.InsecureSet {
		t.Fatal("expected insecure directive presence to be tracked")
	}
	if spec.Insecure {
		t.Fatal("expected explicit false insecure directive")
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
