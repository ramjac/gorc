package app

import (
	"fmt"
	"testing"
)

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

func TestResolveStringUsesExplicitEnvironmentVariable(t *testing.T) {
	t.Setenv("GORC_DEMO_AZURE_TENANT", "todo-demo-tenant")

	got, err := resolveString("{{$env GORC_DEMO_AZURE_TENANT}}", resolver{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "todo-demo-tenant" {
		t.Fatalf("unexpected environment value: %q", got)
	}
}

func TestResolveStringUsesVarsFileBetweenFileAndConfig(t *testing.T) {
	t.Parallel()

	got, err := resolveString("{{shared}}", resolver{
		FileVars:   map[string]string{},
		VarsFile:   map[string]string{"shared": "vars-file"},
		ConfigVars: map[string]string{"shared": "config"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "vars-file" {
		t.Fatalf("expected vars-file precedence, got %q", got)
	}
}

func TestResolveStringErrorsOnUnresolvedVariable(t *testing.T) {
	t.Parallel()

	_, err := resolveString("{{missing}}", resolver{})
	if err == nil {
		t.Fatal("expected unresolved variable error")
	}
}

func TestResolveStringSucceedsWhenFinalExpansionCompletesOnTenthPass(t *testing.T) {
	t.Parallel()

	// Build a chain v0 -> v1 -> ... -> v9 -> "final" that requires exactly
	// 10 replacement passes to fully resolve, exercising the loop's last
	// iteration rather than returning early on a stable/unchanged pass.
	vars := map[string]string{"v9": "final"}
	for i := 0; i < 9; i++ {
		vars[fmt.Sprintf("v%d", i)] = fmt.Sprintf("{{v%d}}", i+1)
	}

	got, err := resolveString("{{v0}}", resolver{ConfigVars: vars})
	if err != nil {
		t.Fatalf("expected chain to resolve within the recursion limit, got error: %v", err)
	}
	if got != "final" {
		t.Fatalf("expected fully resolved value %q, got %q", "final", got)
	}
}
