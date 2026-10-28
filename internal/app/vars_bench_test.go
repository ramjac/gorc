package app

import (
	"testing"
)

func BenchmarkResolveString_NoVars(b *testing.B) {
	vars := resolver{
		CLIVars: map[string]string{"user": "alice"},
	}
	input := "https://api.example.com/v1/users/profile"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = resolveString(input, vars)
	}
}

func BenchmarkResolveString_SingleVar(b *testing.B) {
	vars := resolver{
		CLIVars: map[string]string{"user": "alice"},
	}
	input := "https://api.example.com/v1/users/{{user}}"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = resolveString(input, vars)
	}
}

func BenchmarkResolveString_MultipleVars(b *testing.B) {
	b.Setenv("BENCH_GORC_ENV", "env-value")
	vars := resolver{
		RequestVars: map[string]string{"value": "request"},
		FileVars:    map[string]string{"other": "file"},
		ConfigVars:  map[string]string{"value": "config"},
		CLIVars:     map[string]string{"value": "cli"},
	}
	input := "{{value}} {{other}} {{$env BENCH_GORC_ENV}}"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = resolveString(input, vars)
	}
}

func BenchmarkResolveString_WithSpaces(b *testing.B) {
	vars := resolver{
		CLIVars: map[string]string{"user": "alice"},
	}
	input := "Hello {{   user   }}, welcome!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = resolveString(input, vars)
	}
}
