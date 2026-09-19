package app

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
	err := writeResponse(&out, RequestSpec{Name: "demo"}, resp, []byte("ok"), "", NewColorizer(true))
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
	err := writeResponse(&out, RequestSpec{Name: "demo"}, resp, []byte("ok"), "", NewColorizer(false))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("expected no ANSI color output, got %q", out.String())
	}
}

func TestWriteResponseHandlesNilColorizer(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
	}
	err := writeResponse(&out, RequestSpec{Name: "demo"}, resp, []byte("ok"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "200 OK") {
		t.Fatalf("expected plain status output, got %q", out.String())
	}
}

func TestWriteResponseReportsBinaryBodyOmitted(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"image/png"}},
	}
	body := []byte{0x89, 'P', 'N', 'G'}
	if err := writeResponse(&out, RequestSpec{Name: "demo"}, resp, body, "", NewColorizer(false)); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "binary body omitted from stdout") ||
		!strings.Contains(got, "content-type=image/png") ||
		!strings.Contains(got, "bytes=4") ||
		!strings.Contains(got, "use --output to save it") {
		t.Fatalf("expected binary omission details, got %q", got)
	}
	if strings.Contains(got, "bytes written") {
		t.Fatalf("expected omission message instead of written message, got %q", got)
	}
}

func TestWriteResponseReportsBinaryBodySavedToOutput(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/octet-stream"}},
	}
	if err := writeResponse(&out, RequestSpec{Name: "demo"}, resp, []byte{1, 2, 3}, "/tmp/download.bin", NewColorizer(false)); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "binary body saved to /tmp/download.bin") ||
		!strings.Contains(got, "omitted from stdout") ||
		!strings.Contains(got, "content-type=application/octet-stream") ||
		!strings.Contains(got, "bytes=3") {
		t.Fatalf("expected binary saved details, got %q", got)
	}
}
