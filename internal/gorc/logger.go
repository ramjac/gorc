package gorc

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

type LogLevel int

const (
	LogLevelNone LogLevel = iota
	LogLevelError
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

type Logger struct {
	level LogLevel
	out   io.Writer
	colors *Colorizer
	mu    sync.Mutex
}

func parseLogLevel(value string) (LogLevel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "none", "off", "silent":
		return LogLevelNone, nil
	case "error":
		return LogLevelError, nil
	case "info":
		return LogLevelInfo, nil
	case "debug":
		return LogLevelDebug, nil
	case "trace":
		return LogLevelTrace, nil
	default:
		return LogLevelNone, fmt.Errorf("invalid log level %q", value)
	}
}

func NewLogger(level string, out io.Writer, colorEnabled bool) (*Logger, error) {
	parsed, err := parseLogLevel(level)
	if err != nil {
		return nil, err
	}
	return &Logger{level: parsed, out: out, colors: NewColorizer(colorEnabled)}, nil
}

func (l *Logger) Enabled(level LogLevel) bool {
	return l != nil && l.out != nil && l.level >= level && level != LogLevelNone
}

func (l *Logger) Errorf(format string, args ...any) { l.logf(LogLevelError, format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.logf(LogLevelInfo, format, args...) }
func (l *Logger) Debugf(format string, args ...any) { l.logf(LogLevelDebug, format, args...) }
func (l *Logger) Tracef(format string, args ...any) { l.logf(LogLevelTrace, format, args...) }

func (l *Logger) logf(level LogLevel, format string, args ...any) {
	if !l.Enabled(level) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	label := levelName(level)
	if l.colors != nil {
		label = l.colors.LogLabel(level)
	}
	_, _ = fmt.Fprintf(l.out, "[%s] %s\n", label, fmt.Sprintf(format, args...))
}

func levelName(level LogLevel) string {
	switch level {
	case LogLevelError:
		return "ERROR"
	case LogLevelInfo:
		return "INFO"
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelTrace:
		return "TRACE"
	default:
		return "NONE"
	}
}
