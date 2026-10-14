package logger

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  Level
	}{
		{"debug", DebugLevel},
		{"info", InfoLevel},
		{"warn", WarnLevel},
		{"warning", WarnLevel},
		{"error", ErrorLevel},
	}
	for _, tt := range tests {
		got, err := ParseLevel(tt.input)
		if err != nil {
			t.Errorf("ParseLevel(%q) error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}

	if _, err := ParseLevel("fatal"); err == nil {
		t.Error("expected error for unknown level")
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := New(InfoLevel)
	log.SetOutput(&buf)

	log.Debug("hidden")
	log.Info("shown")

	out := buf.String()
	if strings.Contains(out, "hidden") {
		t.Error("debug message should be filtered")
	}
	if !strings.Contains(out, "shown") {
		t.Error("info message should be shown")
	}
}

func TestLoggerWithFields(t *testing.T) {
	var buf bytes.Buffer
	log := New(DebugLevel)
	log.SetOutput(&buf)

	log.With(map[string]string{"user": "root"}).Info("synced", map[string]string{"keys": "3"})

	out := buf.String()
	if !strings.Contains(out, `user="root"`) {
		t.Errorf("persistent field missing: %s", out)
	}
	if !strings.Contains(out, `keys="3"`) {
		t.Errorf("event field missing: %s", out)
	}
}

func TestLoggerAllLevels(t *testing.T) {
	var buf bytes.Buffer
	log := New(DebugLevel)
	log.SetOutput(&buf)

	log.Debug("debug-msg")
	log.Info("info-msg")
	log.Warn("warn-msg")
	log.Error("error-msg")

	out := buf.String()
	for _, msg := range []string{"debug-msg", "info-msg", "warn-msg", "error-msg"} {
		if !strings.Contains(out, msg) {
			t.Errorf("%s message missing from output", msg)
		}
	}
}

func TestUnknownLevelString(t *testing.T) {
	l := Level(99)
	if l.String() != "unknown" {
		t.Errorf("unexpected level string: %q", l.String())
	}
}
