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

func TestWriteResponseDoesNotPrettyPrintTruncatedJSONPreview(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
	// A complete JSON value followed only by whitespace: on its own this
	// looks like the full body to a streaming decoder, even though the
	// preview was capped and bytes were actually omitted.
	body := []byte(`{"a":1}` + "\n")
	metadata := responseMetadata{totalBytes: 5 * 1024 * 1024, previewTruncated: true}
	if err := writeResponse(&out, RequestSpec{Name: "demo"}, resp, body, "", NewColorizer(false), metadata); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(got, "  \"a\": 1") {
		t.Fatalf("expected the truncated preview not to be pretty-printed as if complete, got %q", got)
	}
	if !strings.Contains(got, `{"a":1}`) {
		t.Fatalf("expected the raw truncated preview to be printed, got %q", got)
	}
	if !strings.Contains(got, "response preview truncated") {
		t.Fatalf("expected a truncation notice, got %q", got)
	}
}

func TestWriteResponseStillPrettyPrintsUntruncatedJSON(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
	body := []byte(`{"a":1}`)
	if err := writeResponse(&out, RequestSpec{Name: "demo"}, resp, body, "", NewColorizer(false)); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "\"a\": 1") {
		t.Fatalf("expected the untruncated JSON body to be pretty-printed, got %q", got)
	}
}

func TestFormatHeaderLineRendersRepeatedValuesOnSeparateLines(t *testing.T) {
	t.Parallel()

	got := formatHeaderLine(NewColorizer(false), "Set-Cookie", []string{
		"a=1; Path=/, weird",
		"b=2; Path=/",
	})
	want := "Set-Cookie: a=1; Path=/, weird\nSet-Cookie: b=2; Path=/"
	if got != want {
		t.Fatalf("expected each header value on its own repeated-label line, got %q want %q", got, want)
	}
}

func TestColorizerTitle(t *testing.T) {
	t.Parallel()

	t.Run("disabled color", func(t *testing.T) {
		t.Parallel()
		c := NewColorizer(false)
		got := c.Title("Hello %s", "World")
		want := "Hello World"
		if got != want {
			t.Fatalf("expected %q, got %q", want, got)
		}
	})

	t.Run("enabled color", func(t *testing.T) {
		t.Parallel()
		c := NewColorizer(true)
		got := c.Title("Hello %s", "World")
		if !strings.Contains(got, "Hello World") || !strings.Contains(got, "\x1b[") {
			t.Fatalf("expected colored output containing 'Hello World', got %q", got)
		}
	})
}

func TestColorizerMethods(t *testing.T) {
	t.Parallel()

	cDisabled := NewColorizer(false)
	cEnabled := NewColorizer(true)

	t.Run("Header", func(t *testing.T) {
		if got := cDisabled.Header("Header: %s", "Value"); got != "Header: Value" {
			t.Fatalf("expected plain header, got %q", got)
		}
		if got := cEnabled.Header("Header: %s", "Value"); !strings.Contains(got, "Header: Value") || !strings.Contains(got, "\x1b[") {
			t.Fatalf("expected colored header, got %q", got)
		}
	})

	t.Run("Meta", func(t *testing.T) {
		if got := cDisabled.Meta("Meta %d", 123); got != "Meta 123" {
			t.Fatalf("expected plain meta, got %q", got)
		}
		if got := cEnabled.Meta("Meta %d", 123); !strings.Contains(got, "Meta 123") || !strings.Contains(got, "\x1b[") {
			t.Fatalf("expected colored meta, got %q", got)
		}
	})

	t.Run("Status", func(t *testing.T) {
		statuses := []struct {
			code int
			text string
		}{
			{200, "200 OK"},
			{302, "302 Found"},
			{404, "404 Not Found"},
			{500, "500 Internal Server Error"},
		}
		for _, s := range statuses {
			if got := cDisabled.Status(s.text, s.code); got != s.text {
				t.Fatalf("code %d: expected plain status %q, got %q", s.code, s.text, got)
			}
			if got := cEnabled.Status(s.text, s.code); !strings.Contains(got, s.text) || !strings.Contains(got, "\x1b[") {
				t.Fatalf("code %d: expected colored status containing %q, got %q", s.code, s.text, got)
			}
		}
	})

	t.Run("LogLabel", func(t *testing.T) {
		levels := []LogLevel{LogLevelError, LogLevelInfo, LogLevelDebug, LogLevelTrace, LogLevel(99)}
		for _, lvl := range levels {
			plain := cDisabled.LogLabel(lvl)
			if plain == "" {
				t.Fatalf("level %v: expected non-empty label", lvl)
			}
			colored := cEnabled.LogLabel(lvl)
			if lvl == LogLevel(99) {
				if colored != plain {
					t.Fatalf("unknown level: expected %q, got %q", plain, colored)
				}
			} else {
				if !strings.Contains(colored, plain) || !strings.Contains(colored, "\x1b[") {
					t.Fatalf("level %v: expected colored label containing %q, got %q", lvl, plain, colored)
				}
			}
		}
	})
}
