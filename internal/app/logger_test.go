package app

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input   string
		want    LogLevel
		wantErr bool
	}{
		{"", LogLevelNone, false},
		{"none", LogLevelNone, false},
		{"off", LogLevelNone, false},
		{"silent", LogLevelNone, false},
		{"error", LogLevelError, false},
		{"ERROR", LogLevelError, false},
		{"  error  ", LogLevelError, false},
		{"info", LogLevelInfo, false},
		{"INFO", LogLevelInfo, false},
		{"  info  ", LogLevelInfo, false},
		{"debug", LogLevelDebug, false},
		{"DEBUG", LogLevelDebug, false},
		{"  debug  ", LogLevelDebug, false},
		{"trace", LogLevelTrace, false},
		{"TRACE", LogLevelTrace, false},
		{"  trace  ", LogLevelTrace, false},
		{"invalid", LogLevelNone, true},
		{"123", LogLevelNone, true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()

			got, err := parseLogLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseLogLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("parseLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNewLogger(t *testing.T) {
	t.Parallel()

	t.Run("valid level", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		colors := NewColorizer(false)
		logger, err := NewLogger("info", &buf, colors)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if logger == nil {
			t.Fatal("expected non-nil Logger")
		}
		if logger.level != LogLevelInfo {
			t.Fatalf("expected log level LogLevelInfo, got %v", logger.level)
		}
	})

	t.Run("invalid level", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		logger, err := NewLogger("invalid_level", &buf, nil)
		if err == nil {
			t.Fatal("expected error for invalid level, got nil")
		}
		if logger != nil {
			t.Fatalf("expected nil Logger, got %v", logger)
		}
	})
}

func TestLoggerEnabled(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	t.Run("nil logger receiver", func(t *testing.T) {
		t.Parallel()

		var nilLogger *Logger
		if nilLogger.Enabled(LogLevelInfo) {
			t.Fatal("expected nil logger to not be enabled")
		}
	})

	t.Run("nil writer", func(t *testing.T) {
		t.Parallel()

		logger := &Logger{level: LogLevelInfo, out: nil}
		if logger.Enabled(LogLevelInfo) {
			t.Fatal("expected logger with nil writer to not be enabled")
		}
	})

	t.Run("LogLevelNone is never enabled", func(t *testing.T) {
		t.Parallel()

		logger := &Logger{level: LogLevelTrace, out: &buf}
		if logger.Enabled(LogLevelNone) {
			t.Fatal("expected LogLevelNone to be disabled")
		}
	})

	t.Run("filtering levels", func(t *testing.T) {
		t.Parallel()

		logger := &Logger{level: LogLevelInfo, out: &buf}

		if !logger.Enabled(LogLevelError) {
			t.Error("expected Error level to be enabled for Info logger")
		}
		if !logger.Enabled(LogLevelInfo) {
			t.Error("expected Info level to be enabled for Info logger")
		}
		if logger.Enabled(LogLevelDebug) {
			t.Error("expected Debug level to be disabled for Info logger")
		}
		if logger.Enabled(LogLevelTrace) {
			t.Error("expected Trace level to be disabled for Info logger")
		}
	})
}

func TestLoggingMethods(t *testing.T) {
	t.Parallel()

	t.Run("log formatting and level filtering without colors", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		logger, err := NewLogger("debug", &buf, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		logger.Errorf("error msg %d", 1)
		logger.Infof("info msg %s", "test")
		logger.Debugf("debug msg")
		logger.Tracef("trace msg") // trace is disabled for debug level

		got := buf.String()
		expectedLines := []string{
			"[ERROR] error msg 1",
			"[INFO] info msg test",
			"[DEBUG] debug msg",
		}

		for _, line := range expectedLines {
			if !strings.Contains(got, line) {
				t.Errorf("expected log output to contain %q, got:\n%s", line, got)
			}
		}

		if strings.Contains(got, "trace msg") {
			t.Errorf("expected trace msg to be filtered out, got:\n%s", got)
		}
	})

	t.Run("colored logging label", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		logger, err := NewLogger("info", &buf, NewColorizer(true))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		logger.Infof("hello color")
		got := buf.String()
		if !strings.Contains(got, "\x1b[") {
			t.Fatalf("expected ANSI color codes in log label, got %q", got)
		}
		if !strings.Contains(got, "hello color") {
			t.Fatalf("expected message body in output, got %q", got)
		}
	})

	t.Run("disabled logger writes nothing", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		logger, err := NewLogger("none", &buf, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		logger.Errorf("should not be logged")
		logger.Infof("should not be logged")
		logger.Debugf("should not be logged")
		logger.Tracef("should not be logged")

		if buf.Len() > 0 {
			t.Fatalf("expected no output for disabled logger, got %q", buf.String())
		}
	})
}

func TestLevelName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		level LogLevel
		want  string
	}{
		{LogLevelError, "ERROR"},
		{LogLevelInfo, "INFO"},
		{LogLevelDebug, "DEBUG"},
		{LogLevelTrace, "TRACE"},
		{LogLevelNone, "NONE"},
		{LogLevel(99), "NONE"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			if got := levelName(tt.level); got != tt.want {
				t.Errorf("levelName(%v) = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

// Ensure discarding writer doesn't panic on log statements.
var _ io.Writer = (*bytes.Buffer)(nil)
