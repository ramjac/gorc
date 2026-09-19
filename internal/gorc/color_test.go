package gorc

import (
	"net/http"
	"strings"
	"testing"
)

func TestLoggerUsesColorByDefault(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	logger, err := NewLogger("info", &out, NewColorizer(true))
	if err != nil {
		t.Fatal(err)
	}
	logger.Infof("hello")
	if !strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("expected ANSI color output, got %q", out.String())
	}
}

func TestLoggerCanDisableColor(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	logger, err := NewLogger("info", &out, NewColorizer(false))
	if err != nil {
		t.Fatal(err)
	}
	logger.Infof("hello")
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("expected no ANSI color output, got %q", out.String())
	}
}

func TestWriteResponseUsesColorWhenEnabled(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
	}
	err := writeResponse(&out, RequestSpec{Name: "demo"}, resp, []byte("ok"), NewColorizer(true))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("expected ANSI color output, got %q", out.String())
	}
}

func TestWriteResponseCanDisableColor(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
	}
	err := writeResponse(&out, RequestSpec{Name: "demo"}, resp, []byte("ok"), NewColorizer(false))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("expected no ANSI color output, got %q", out.String())
	}
}
