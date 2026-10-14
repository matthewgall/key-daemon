package sshd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Validator runs sshd -t against a candidate authorized_keys file.
type Validator struct {
	sshdPath string
}

// NewValidator creates a Validator that uses the system sshd binary.
func NewValidator() *Validator {
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
		return fmt.Errorf("sshd -t failed: %w\n%s", err, string(out))
	}
	return nil
}
