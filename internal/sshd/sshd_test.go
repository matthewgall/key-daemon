package sshd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSuccess(t *testing.T) {
	mockPath := writeMockSSHD(t, 0, "")
	v := &Validator{sshdPath: mockPath}

	candidate := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(candidate, []byte("test"), 0o600); err != nil {
		t.Fatalf("write candidate: %v", err)
	}

	if err := v.Validate(candidate); err != nil {
		t.Errorf("Validate failed: %v", err)
	}
}

func TestValidateFailure(t *testing.T) {
	mockPath := writeMockSSHD(t, 1, "bad config")
	v := &Validator{sshdPath: mockPath}

	candidate := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(candidate, []byte("test"), 0o600); err != nil {
		t.Fatalf("write candidate: %v", err)
	}

	if err := v.Validate(candidate); err == nil {
		t.Error("expected Validate to fail")
	} else if !strings.Contains(err.Error(), "sshd -t failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateMissingCandidate(t *testing.T) {
	mockPath := writeMockSSHD(t, 0, "")
	v := &Validator{sshdPath: mockPath}

	if err := v.Validate(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("expected error for missing candidate")
	}
}

func TestValidateDetectsMissingHostKeys(t *testing.T) {
	mockPath := writeMockSSHD(t, 1, "sshd: no hostkeys available")
	v := &Validator{sshdPath: mockPath}

	candidate := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(candidate, []byte("test"), 0o600); err != nil {
		t.Fatalf("write candidate: %v", err)
	}

	err := v.Validate(candidate)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no host keys") {
		t.Errorf("expected no-host-keys error, got: %v", err)
	}
}

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v.sshdPath == "" {
		t.Error("expected non-empty sshdPath")
	}
	if p, err := exec.LookPath("sshd"); err == nil && v.sshdPath != p {
		t.Errorf("expected sshdPath %q, got %q", p, v.sshdPath)
	}
}

func writeMockSSHD(t *testing.T, exitCode int, stderr string) string {
	t.Helper()
	script := "#!/bin/sh\n"
	if stderr != "" {
		script += fmt.Sprintf("echo '%s' >&2\n", stderr)
	}
	script += fmt.Sprintf("exit %d\n", exitCode)

	path := filepath.Join(t.TempDir(), "mock-sshd")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write mock: %v", err)
	}
	return path
}
