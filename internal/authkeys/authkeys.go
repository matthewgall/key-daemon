package authkeys

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/matthewgall/key-daemon/internal/config"
	"github.com/matthewgall/key-daemon/internal/user"
)

const (
	sshDirMode        = 0o700
	authKeysMode      = 0o600
	backupNamePrefix  = ".authorized_keys.key-daemon."
	backupFilePattern = backupNamePrefix + "%s.bak"
	tmpFilePattern    = backupNamePrefix + "tmp.%d"
)

// ValidateFunc is called with the candidate file path before it is promoted.
type ValidateFunc func(candidatePath string) error

// Manager updates authorized_keys files safely for configured users.
type Manager struct {
	markers config.Markers
	backups config.Backups
}

// NewManager creates a Manager with the given markers and backup policy.
func NewManager(markers config.Markers, backups config.Backups) *Manager {
	return &Manager{
		markers: markers,
		backups: backups,
	}
}

// Sync ensures the user's authorized_keys contains the supplied managed keys
// in the marked section. It returns true if the file was changed.
func (m *Manager) Sync(u *user.Info, managedKeys string, validate ValidateFunc) (bool, error) {
	sshDir, authPath, err := m.paths(u)
	if err != nil {
		return false, err
	}

	if err := m.ensureSSHDir(sshDir, u); err != nil {
		return false, fmt.Errorf("ensure .ssh dir: %w", err)
	}

	candidatePath := filepath.Join(sshDir, fmt.Sprintf(tmpFilePattern, os.Getpid()))
	cleanup := func() { _ = os.Remove(candidatePath) }
	defer cleanup()

	candidate, err := m.buildCandidate(authPath, managedKeys)
	if err != nil {
		return false, fmt.Errorf("build candidate: %w", err)
	}

	if err := m.writeFile(candidatePath, []byte(candidate), u); err != nil {
		return false, fmt.Errorf("write candidate: %w", err)
	}

	if validate != nil {
		if err := validate(candidatePath); err != nil {
			return false, fmt.Errorf("validation failed: %w", err)
		}
	}

	existing, err := os.ReadFile(authPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("read existing authkeys: %w", err)
	}

	if string(existing) == candidate {
		return false, nil
	}

	if len(existing) > 0 {
		if err := m.createBackup(authPath, u); err != nil {
			return false, fmt.Errorf("create backup: %w", err)
		}
	}

	if err := os.Rename(candidatePath, authPath); err != nil {
		return false, fmt.Errorf("atomic rename: %w", err)
	}
	// Candidate is now the live file; disable cleanup.
	cleanup = func() {}

	if err := m.pruneBackups(sshDir, u); err != nil {
		// Non-fatal: the file is already updated.
		return true, fmt.Errorf("prune backups: %w", err)
	}

	return true, nil
}

// RestoreLatestBackup replaces the user's authorized_keys with the most recent backup.
func (m *Manager) RestoreLatestBackup(u *user.Info) error {
	sshDir, authPath, err := m.paths(u)
	if err != nil {
		return err
	}

	backups, err := m.listBackups(sshDir)
	if err != nil {
		return err
	}
	if len(backups) == 0 {
		return errors.New("no backups available")
	}

	latest := backups[len(backups)-1]
	if err := os.Rename(latest.path, authPath); err != nil {
		return fmt.Errorf("restore backup: %w", err)
	}
	return m.setOwnership(authPath, u)
}

func (m *Manager) paths(u *user.Info) (sshDir, authPath string, err error) {
	if u.HomeDir == "" {
		return "", "", fmt.Errorf("user %q has no home directory", u.Name)
	}
	sshDir = filepath.Join(u.HomeDir, ".ssh")
	authPath = filepath.Join(sshDir, "authorized_keys")
	return sshDir, authPath, nil
}

func (m *Manager) ensureSSHDir(sshDir string, u *user.Info) error {
	info, err := os.Stat(sshDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(sshDir, sshDirMode); err != nil {
				return err
			}
			return m.setOwnership(sshDir, u)
		}
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists but is not a directory", sshDir)
	}
	if err := os.Chmod(sshDir, sshDirMode); err != nil {
		return err
	}
	return m.setOwnership(sshDir, u)
}

func (m *Manager) buildCandidate(authPath, managedKeys string) (string, error) {
	existing := ""
	data, err := os.ReadFile(authPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err == nil {
		existing = string(data)
	}

	before, after := splitAroundMarkers(existing, m.markers)

	before = strings.TrimSpace(before)
	after = strings.TrimSpace(after)
	managedKeys = strings.TrimSpace(managedKeys)

	var parts []string
	if before != "" {
		parts = append(parts, before)
	}
	if managedKeys != "" {
		section := m.markers.Begin + "\n" + managedKeys + "\n" + m.markers.End
		parts = append(parts, section)
	}
	if after != "" {
		parts = append(parts, after)
	}

	result := strings.Join(parts, "\n\n")
	if result != "" {
		result += "\n"
	}
	return result, nil
}

// splitAroundMarkers returns the content before the first begin marker and
// after the last end marker. Any content between markers is discarded.
func splitAroundMarkers(content string, markers config.Markers) (before, after string) {
	lines := strings.Split(content, "\n")
	var beginIdx, endIdx = -1, -1
	for i, line := range lines {
		if line == markers.Begin {
			beginIdx = i
		}
		if line == markers.End {
			endIdx = i
		}
	}
	if beginIdx == -1 || endIdx == -1 || beginIdx >= endIdx {
		return content, ""
	}
	before = strings.Join(lines[:beginIdx], "\n")
	after = strings.Join(lines[endIdx+1:], "\n")
	return before, after
}

func (m *Manager) writeFile(path string, data []byte, u *user.Info) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, authKeysMode)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	if err := os.Chmod(path, authKeysMode); err != nil {
		return err
	}
	return m.setOwnership(path, u)
}

func (m *Manager) setOwnership(path string, u *user.Info) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not determine ownership of %s", path)
	}

	if int(stat.Uid) == u.UID && int(stat.Gid) == u.GID {
		return nil
	}

	if err := os.Chown(path, u.UID, u.GID); err != nil {
		return fmt.Errorf("chown %s to %d:%d: %w", path, u.UID, u.GID, err)
	}
	return nil
}

func (m *Manager) createBackup(authPath string, u *user.Info) error {
	if _, err := os.Stat(authPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	sshDir := filepath.Dir(authPath)
	ts := time.Now().UTC().Format("20060102T150405.000000")
	backupPath := filepath.Join(sshDir, fmt.Sprintf(backupFilePattern, ts))

	src, err := os.Open(authPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, authKeysMode)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	if err := src.Close(); err != nil {
		return err
	}

	return m.setOwnership(backupPath, u)
}

type backupFile struct {
	path    string
	modTime time.Time
}

func (m *Manager) listBackups(sshDir string) ([]backupFile, error) {
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil, err
	}

	var backups []backupFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), backupNamePrefix) || !strings.HasSuffix(e.Name(), ".bak") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		backups = append(backups, backupFile{
			path:    filepath.Join(sshDir, e.Name()),
			modTime: info.ModTime(),
		})
	}

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].modTime.Before(backups[j].modTime)
	})
	return backups, nil
}

func (m *Manager) pruneBackups(sshDir string, u *user.Info) error {
	backups, err := m.listBackups(sshDir)
	if err != nil {
		return err
	}

	now := time.Now()
	cutoff := now.Add(-m.backups.MaxAge.Duration())

	for i, b := range backups {
		tooOld := b.modTime.Before(cutoff)
		tooMany := len(backups)-i > m.backups.MaxCount
		if tooOld || tooMany {
			if err := os.Remove(b.path); err != nil {
				return err
			}
		}
	}
	return nil
}

// IsReadOnlyError reports whether an error is likely caused by a read-only filesystem.
func IsReadOnlyError(err error) bool {
	if err == nil {
		return false
	}
	// EROFS is the canonical read-only filesystem error code.
	return errors.Is(err, syscall.EROFS)
}
