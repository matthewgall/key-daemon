package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunVersionCommand(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := run([]string{"key-daemon", "version"})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), version) {
		t.Errorf("expected version output containing %q, got %q", version, string(out))
	}
}

func TestRunInvalidSubcommand(t *testing.T) {
	err := run([]string{"key-daemon", "bogus"})
	if err == nil {
		t.Fatal("expected error for invalid subcommand")
	}
	if !strings.Contains(err.Error(), "unknown subcommand") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunInvalidLogLevel(t *testing.T) {
	err := run([]string{"key-daemon", "-log-level", "bogus", "version"})
	if err == nil {
		t.Fatal("expected error for invalid log level")
	}
	if !strings.Contains(err.Error(), "unknown log level") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunSyncMissingConfigNonRoot(t *testing.T) {
	// When running as non-root, a missing global config falls back to defaults
	// with per-user discovery. This may produce no users to sync, but it should
	// not fail at config load time.
	err := run([]string{"key-daemon", "sync", "-config", "/nonexistent/path/config.yaml", "-log-level", "error"})
	if err != nil {
		t.Fatalf("unexpected error for non-root missing config: %v", err)
	}
}

func TestRunSyncValidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
users:
  - name: root
    sources:
      - url:https://example.com/keys
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// The URL will fail (example.com/keys returns 404), but the controller
	// is fail-open, so Sync returns nil and the process exits 0.
	err := run([]string{"key-daemon", "sync", "-config", cfgPath})
	if err != nil {
		t.Fatalf("expected fail-open, got error: %v", err)
	}
}

func TestRunVersionFlag(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	// The version subcommand prints version to stdout.
	err := run([]string{"key-daemon", "version"})
	w.Close()

	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), version) {
		t.Errorf("expected version in output, got %q", string(out))
	}
}
