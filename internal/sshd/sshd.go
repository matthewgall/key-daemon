package sshd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrNoHostKeys is returned when sshd -t fails because the system has no
// SSH host keys. The operator should run ssh-keygen -A before key-daemon
// can validate files in root mode.
var ErrNoHostKeys = errors.New("sshd has no host keys; run ssh-keygen -A")

// commonSSHDPaths lists typical locations for the sshd binary on Linux
// distributions. It is consulted when sshd is not found in $PATH.
var commonSSHDPaths = []string{
	"/usr/sbin/sshd",
	"/usr/local/sbin/sshd",
	"/sbin/sshd",
}

// Validator runs sshd -t against a candidate authorized_keys file.
type Validator struct {
	sshdPath string
}

// NewValidator creates a Validator that uses the system sshd binary.
// It searches $PATH first, then falls back to common system locations.
func NewValidator() *Validator {
	path, err := exec.LookPath("sshd")
	if err == nil {
		return &Validator{sshdPath: path}
	}

	for _, p := range commonSSHDPaths {
		if _, err := os.Stat(p); err == nil {
			return &Validator{sshdPath: p}
		}
	}

	// Return a validator that will produce a clear error at validation time.
	return &Validator{sshdPath: "sshd"}
}

// Validate writes a minimal sshd_config that points AuthorizedKeysFile at the
// candidate path and runs sshd -t. It returns an error if sshd rejects the file.
func (v *Validator) Validate(candidatePath string) error {
	if candidatePath == "" {
		return fmt.Errorf("candidate path is empty")
	}
	if _, err := os.Stat(candidatePath); err != nil {
		return fmt.Errorf("candidate path: %w", err)
	}

	dir, err := os.MkdirTemp("", "key-daemon-sshd-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	cfgPath := filepath.Join(dir, "sshd_config")
	cfg := fmt.Sprintf("AuthorizedKeysFile %s\n", candidatePath)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return fmt.Errorf("write test config: %w", err)
	}

	cmd := exec.Command(v.sshdPath, "-t", "-f", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		outStr := string(out)
		if isNoHostKeysError(outStr) {
			return fmt.Errorf("%w: %s", ErrNoHostKeys, outStr)
		}
		return fmt.Errorf("sshd -t failed: %w\n%s", err, outStr)
	}
	return nil
}

// isNoHostKeysError reports whether sshd -t output indicates the system has
// no host keys available.
func isNoHostKeysError(out string) bool {
	lower := strings.ToLower(out)
	return strings.Contains(lower, "no hostkeys available") ||
		strings.Contains(lower, "could not load host key")
}
