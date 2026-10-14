// Package selfupdate replaces the running key-daemon binary with the latest
// release from GitHub and restarts the service. It is intentionally explicit:
// it never runs automatically in the background.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/matthewgall/key-daemon/internal/update"
)

const (
	repo     = "matthewgall/key-daemon"
	baseURL  = "https://github.com/matthewgall/key-daemon/releases/download"
	maxSize  = 20 * 1024 * 1024 // 20 MiB
)

// Updater replaces the installed binary with a newer release.
type Updater struct {
	installPath string
	checker     updateChecker
	httpClient  *http.Client
}

type updateChecker interface {
	LatestRelease(ctx context.Context) (*update.Info, error)
}

// New creates an Updater that targets the running binary's path.
func New() (*Updater, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("determine executable path: %w", err)
	}
	realPath, err := filepath.EvalSymlinks(execPath)
	if err != nil {
		return nil, fmt.Errorf("resolve executable path: %w", err)
	}
	return &Updater{
		installPath: realPath,
		checker:     update.NewChecker(),
		httpClient:  &http.Client{},
	}, nil
}

// InstallPath returns the path to the binary being replaced.
func (u *Updater) InstallPath() string {
	return u.installPath
}

// Run downloads the latest release binary, verifies its checksum, and
// replaces the installed binary. It returns the installed version.
func (u *Updater) Run(ctx context.Context, current string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("self-update is only supported on linux, not %s", runtime.GOOS)
	}

	latest, err := u.checker.LatestRelease(ctx)
	if err != nil {
		return "", fmt.Errorf("query latest release: %w", err)
	}
	if current != "" && current != "dev" && !update.IsNewer(current, latest.Version) {
		return current, fmt.Errorf("already up to date (%s)", current)
	}

	version := latest.Version
	binaryName := fmt.Sprintf("key-daemon-%s-%s", runtime.GOOS, runtime.GOARCH)
	binaryURL := fmt.Sprintf("%s/%s/%s", baseURL, version, binaryName)
	checksumsURL := fmt.Sprintf("%s/%s/checksums.txt", baseURL, version)

	tempDir, err := os.MkdirTemp("", "key-daemon-update-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	binaryPath := filepath.Join(tempDir, binaryName)
	checksumsPath := filepath.Join(tempDir, "checksums.txt")

	if err := u.downloadFile(ctx, binaryURL, binaryPath); err != nil {
		return "", fmt.Errorf("download binary: %w", err)
	}
	if err := u.downloadFile(ctx, checksumsURL, checksumsPath); err != nil {
		return "", fmt.Errorf("download checksums: %w", err)
	}

	if err := verifyChecksum(binaryPath, checksumsPath); err != nil {
		return "", fmt.Errorf("checksum verification failed: %w", err)
	}

	if err := os.Chmod(binaryPath, 0o755); err != nil {
		return "", err
	}

	// Atomic replace. Remove then rename avoids "text file busy" when the
	// old binary is currently executing; the running inode stays valid until
	// the process exits.
	if err := os.Remove(u.installPath); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("remove old binary: %w", err)
	}
	if err := os.Rename(binaryPath, u.installPath); err != nil {
		return "", fmt.Errorf("install new binary: %w", err)
	}

	return version, nil
}

func (u *Updater) downloadFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := u.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxSize {
		return fmt.Errorf("response exceeds %d bytes", maxSize)
	}
	return os.WriteFile(dest, data, 0o600)
}

func sha256sum(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifyChecksum(binaryPath, checksumsPath string) error {
	expected, err := findChecksum(checksumsPath, filepath.Base(binaryPath))
	if err != nil {
		return err
	}
	f, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer f.Close()
	computed, err := sha256sum(f)
	if err != nil {
		return err
	}
	if computed != expected {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, computed)
	}
	return nil
}

func findChecksum(checksumsPath, filename string) (string, error) {
	data, err := os.ReadFile(checksumsPath)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if fields[1] == filename {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksum not found for %s", filename)
}

// RestartService restarts the key-daemon service using systemd or OpenRC.
func RestartService() error {
	if isSystemd() {
		return run("systemctl", "restart", "key-daemon.service")
	}
	if isOpenRC() {
		return run("rc-service", "key-daemon", "restart")
	}
	return fmt.Errorf("no supported init system detected")
}

func isSystemd() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func isOpenRC() bool {
	_, err := exec.LookPath("rc-service")
	return err == nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
