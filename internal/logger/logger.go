package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level represents a logging severity.
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

func (l Level) String() string {
	switch l {
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case WarnLevel:
		return "warn"
	case ErrorLevel:
		return "error"
	default:
		return "unknown"
	}
}

// ParseLevel converts a string level name to a Level.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "debug":
		return DebugLevel, nil
	case "info":
		return InfoLevel, nil
	case "warn", "warning":
		return WarnLevel, nil
	case "error":
		return ErrorLevel, nil
	default:
		return InfoLevel, fmt.Errorf("unknown log level %q", s)
	}
}

// Logger writes structured log lines to an io.Writer.
type Logger struct {
	out    io.Writer
	level  Level
	mu     sync.Mutex
	fields map[string]string
}

// New creates a Logger that writes to stderr by default.
func New(level Level) *Logger {
	return &Logger{
		out:    os.Stderr,
		level:  level,
		fields: make(map[string]string),
	}
}

// With returns a new Logger with the given persistent fields.
func (l *Logger) With(fields map[string]string) *Logger {
	merged := make(map[string]string, len(l.fields)+len(fields))
	for k, v := range l.fields {
		merged[k] = v
	}
	for k, v := range fields {
		merged[k] = v
	}
	return &Logger{
		out:    l.out,
		level:  l.level,
		fields: merged,
	}
}

// SetOutput changes the output writer. Used mainly in tests.
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out = w
}

func (l *Logger) log(level Level, msg string, extra map[string]string) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	fmt.Fprintf(l.out, "time=%s level=%s msg=%q", now, level.String(), msg)
	for k, v := range l.fields {
		fmt.Fprintf(l.out, " %s=%q", k, v)
	}
	for k, v := range extra {
		fmt.Fprintf(l.out, " %s=%q", k, v)
	}
	fmt.Fprintln(l.out)
}

func (l *Logger) Debug(msg string, extra ...map[string]string) { l.log(DebugLevel, msg, merge(extra)) }
func (l *Logger) Info(msg string, extra ...map[string]string)  { l.log(InfoLevel, msg, merge(extra)) }
func (l *Logger) Warn(msg string, extra ...map[string]string)  { l.log(WarnLevel, msg, merge(extra)) }
func (l *Logger) Error(msg string, extra ...map[string]string) { l.log(ErrorLevel, msg, merge(extra)) }

func merge(maps []map[string]string) map[string]string {
	if len(maps) == 0 {
		return nil
	}
	out := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}
