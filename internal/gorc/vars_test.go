package gorc

import "testing"

func TestResolveStringPrecedence(t *testing.T) {
	t.Setenv("TEST_GORC_ENV", "env-value")

	got, err := resolveString("{{value}} {{other}} {{$env TEST_GORC_ENV}}", resolver{
		RequestVars: map[string]string{"value": "request"},
		FileVars:    map[string]string{"other": "file"},
		ConfigVars:  map[string]string{"value": "config"},
		CLIVars:     map[string]string{"value": "cli"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "cli file env-value" {
		t.Fatalf("unexpected resolved value: %q", got)
	}
}
