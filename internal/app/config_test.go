package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigUsesGORCConfigEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"proxy":"http://proxy.local:8080","self_signed_cert_file":"./server.pem","auth":{"scheme":"azuread","token_url":"https://login.example.test/token"},"vars":{"tenant":"example"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GORC_CONFIG", path)

	cfg, loadedPath, err := loadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if loadedPath != path {
		t.Fatalf("expected %q, got %q", path, loadedPath)
	}
	if cfg.Proxy != "http://proxy.local:8080" {
		t.Fatalf("unexpected proxy %q", cfg.Proxy)
	}
	if cfg.SelfSignedCertFile != "./server.pem" {
		t.Fatalf("unexpected self-signed cert path %q", cfg.SelfSignedCertFile)
	}
	if cfg.Auth.Scheme != "azuread" || cfg.Auth.TokenURL != "https://login.example.test/token" {
		t.Fatalf("unexpected auth config %#v", cfg.Auth)
	}
	if cfg.Vars["tenant"] != "example" {
		t.Fatalf("unexpected vars %#v", cfg.Vars)
	}
}

func TestLoadVarsFileReadsJSONValues(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "vars.json")
	if err := os.WriteFile(path, []byte(`{"token":"abc","user":"alice"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	vars, loadedPath, err := loadVarsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loadedPath != path {
		t.Fatalf("expected %q, got %q", path, loadedPath)
	}
	if vars["token"] != "abc" || vars["user"] != "alice" {
		t.Fatalf("unexpected vars %#v", vars)
	}
}
