package authkeys

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/matthewgall/key-daemon/internal/config"
	"github.com/matthewgall/key-daemon/internal/user"
)

func currentUser(t *testing.T) *user.Info {
	t.Helper()
	u, err := user.Lookup(os.Getenv("USER"))
	if err != nil {
		t.Skipf("could not look up current user: %v", err)
	}
	return u
}

func tempAuthPaths(t *testing.T, u *user.Info) (sshDir, authPath string) {
	t.Helper()
	home := t.TempDir()
	// Override home so paths resolve under temp dir.
	u.HomeDir = home
	return filepath.Join(home, ".ssh"), filepath.Join(home, ".ssh", "authorized_keys")
}

func TestPreview(t *testing.T) {
	u := currentUser(t)
	sshDir, authPath := tempAuthPaths(t, u)

	m := NewManager(config.Markers{Begin: "# BEGIN", End: "# END"}, config.Backups{MaxCount: 5, MaxAge: config.Duration(time.Hour)})

	candidate, wouldUpdate, err := m.Preview(u, "ssh-ed25519 AAAA test@example.com", nil)
	if err != nil {
		t.Fatalf("Preview failed: %v", err)
	}
	if !wouldUpdate {
		t.Error("expected wouldUpdate=true")
	}
	if !strings.Contains(candidate, "ssh-ed25519 AAAA") {
		t.Errorf("candidate missing key: %s", candidate)
	}

	if _, err := os.Stat(authPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("authorized_keys should not exist in dry-run, got: %v", err)
	}
	if _, err := os.Stat(sshDir); errors.Is(err, os.ErrNotExist) {
		t.Error(".ssh dir should have been created")
	}

	// Now actually write the file and re-preview.
	if _, err := m.Sync(u, "ssh-ed25519 AAAA test@example.com", nil); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	_, wouldUpdate, err = m.Preview(u, "ssh-ed25519 AAAA test@example.com", nil)
	if err != nil {
		t.Fatalf("Preview failed: %v", err)
	}
	if wouldUpdate {
		t.Error("expected wouldUpdate=false after already synced")
	}
}

func TestSyncCreatesFileAndSSHDir(t *testing.T) {
	u := currentUser(t)
	sshDir, authPath := tempAuthPaths(t, u)

	m := NewManager(config.Markers{Begin: "# BEGIN", End: "# END"}, config.Backups{MaxCount: 5, MaxAge: config.Duration(time.Hour)})

	updated, err := m.Sync(u, "ssh-ed25519 AAAA test@example.com", nil)
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if !updated {
		t.Error("expected updated=true")
	}

	if _, err := os.Stat(sshDir); err != nil {
		t.Errorf(".ssh dir not created: %v", err)
	}

	data, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("read authkeys: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "# BEGIN") || !strings.Contains(content, "# END") {
		t.Errorf("markers missing: %s", content)
	}
	if !strings.Contains(content, "ssh-ed25519 AAAA") {
		t.Errorf("key missing: %s", content)
	}
}

func TestSyncPreservesUnmanagedKeys(t *testing.T) {
	u := currentUser(t)
	sshDir, authPath := tempAuthPaths(t, u)

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	existing := "# my manual key\nssh-rsa BBBB manual@example.com\n"
	if err := os.WriteFile(authPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	m := NewManager(config.Markers{Begin: "# BEGIN", End: "# END"}, config.Backups{MaxCount: 5, MaxAge: config.Duration(time.Hour)})

	updated, err := m.Sync(u, "ssh-ed25519 AAAA test@example.com", nil)
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if !updated {
		t.Error("expected updated=true")
	}

	data, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("read authkeys: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "manual@example.com") {
		t.Errorf("manual key was not preserved: %s", content)
	}
	if !strings.Contains(content, "test@example.com") {
		t.Errorf("managed key missing: %s", content)
	}
}

func TestSyncUpdatesManagedSection(t *testing.T) {
	u := currentUser(t)
	sshDir, authPath := tempAuthPaths(t, u)

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	existing := "# BEGIN\nssh-ed25519 OLD old@example.com\n# END\n"
	if err := os.WriteFile(authPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	m := NewManager(config.Markers{Begin: "# BEGIN", End: "# END"}, config.Backups{MaxCount: 5, MaxAge: config.Duration(time.Hour)})

	updated, err := m.Sync(u, "ssh-ed25519 NEW new@example.com", nil)
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if !updated {
		t.Error("expected updated=true")
	}

	data, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("read authkeys: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "OLD") {
		t.Errorf("old managed key was not removed: %s", content)
	}
	if !strings.Contains(content, "NEW") {
		t.Errorf("new managed key missing: %s", content)
	}
}

func TestSyncNoChangeWhenIdentical(t *testing.T) {
	u := currentUser(t)
	sshDir, authPath := tempAuthPaths(t, u)

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	existing := "# BEGIN\nssh-ed25519 AAAA test@example.com\n# END\n"
	if err := os.WriteFile(authPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	m := NewManager(config.Markers{Begin: "# BEGIN", End: "# END"}, config.Backups{MaxCount: 5, MaxAge: config.Duration(time.Hour)})

	updated, err := m.Sync(u, "ssh-ed25519 AAAA test@example.com", nil)
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if updated {
		t.Error("expected updated=false when content is identical")
	}
}

func TestSyncValidationFailurePreventsUpdate(t *testing.T) {
	u := currentUser(t)
	_, authPath := tempAuthPaths(t, u)

	if err := os.MkdirAll(filepath.Dir(authPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(authPath, []byte("original\n"), 0o600); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	m := NewManager(config.Markers{Begin: "# BEGIN", End: "# END"}, config.Backups{MaxCount: 5, MaxAge: config.Duration(time.Hour)})

	validate := func(candidatePath string) error {
		return errors.New("simulated validation failure")
	}

	_, err := m.Sync(u, "ssh-ed25519 AAAA test@example.com", validate)
	if err == nil {
		t.Fatal("expected validation error")
	}

	data, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("read authkeys: %v", err)
	}
	if string(data) != "original\n" {
		t.Errorf("authkeys was changed despite validation failure: %q", string(data))
	}
}

func TestBackupCreationAndPruning(t *testing.T) {
	u := currentUser(t)
	sshDir, authPath := tempAuthPaths(t, u)

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(authPath, []byte("v1\n"), 0o600); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	m := NewManager(config.Markers{Begin: "# BEGIN", End: "# END"}, config.Backups{MaxCount: 2, MaxAge: config.Duration(time.Hour)})

	for i, key := range []string{"ssh-ed25519 A a@a", "ssh-ed25519 B b@b", "ssh-ed25519 C c@c"} {
		// Small sleep to ensure distinct timestamps.
		time.Sleep(5 * time.Millisecond)
		_, err := m.Sync(u, key, nil)
		if err != nil {
			t.Fatalf("Sync round %d failed: %v", i, err)
		}
	}

	entries, err := os.ReadDir(sshDir)
	if err != nil {
		t.Fatalf("read ssh dir: %v", err)
	}

	backupCount := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".authorized_keys.key-daemon.") && strings.HasSuffix(e.Name(), ".bak") {
			backupCount++
		}
	}
	if backupCount != 2 {
		t.Errorf("expected 2 backups due to max_count, got %d", backupCount)
	}
}

func TestRestoreLatestBackup(t *testing.T) {
	u := currentUser(t)
	sshDir, authPath := tempAuthPaths(t, u)

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(authPath, []byte("original\n"), 0o600); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	m := NewManager(config.Markers{Begin: "# BEGIN", End: "# END"}, config.Backups{MaxCount: 5, MaxAge: config.Duration(time.Hour)})

	_, err := m.Sync(u, "ssh-ed25519 AAAA test@example.com", nil)
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if err := m.RestoreLatestBackup(u); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	data, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(data) != "original\n" {
		t.Errorf("restore did not return original: %q", string(data))
	}
}

func TestSyncNoHomeDir(t *testing.T) {
	u := currentUser(t)
	u.HomeDir = ""

	m := NewManager(config.Markers{Begin: "# BEGIN", End: "# END"}, config.Backups{MaxCount: 5, MaxAge: config.Duration(time.Hour)})
	_, err := m.Sync(u, "ssh-ed25519 AAAA test@example.com", nil)
	if err == nil {
		t.Fatal("expected error when user has no home dir")
	}
}

func TestSyncSSHDirIsFile(t *testing.T) {
	u := currentUser(t)
	sshDir, _ := tempAuthPaths(t, u)

	if err := os.WriteFile(sshDir, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	m := NewManager(config.Markers{Begin: "# BEGIN", End: "# END"}, config.Backups{MaxCount: 5, MaxAge: config.Duration(time.Hour)})
	_, err := m.Sync(u, "ssh-ed25519 AAAA test@example.com", nil)
	if err == nil {
		t.Fatal("expected error when .ssh path is a file")
	}
}

func TestSyncReadExistingError(t *testing.T) {
	u := currentUser(t)
	sshDir, authPath := tempAuthPaths(t, u)

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Create authorized_keys as a directory so ReadFile fails.
	if err := os.MkdirAll(authPath, 0o700); err != nil {
		t.Fatalf("mkdir authPath: %v", err)
	}

	m := NewManager(config.Markers{Begin: "# BEGIN", End: "# END"}, config.Backups{MaxCount: 5, MaxAge: config.Duration(time.Hour)})
	_, err := m.Sync(u, "ssh-ed25519 AAAA test@example.com", nil)
	if err == nil {
		t.Fatal("expected error when existing authorized_keys is a directory")
	}
}

func TestSyncChownError(t *testing.T) {
	u := currentUser(t)
	// Set UID to a different user so chown fails.
	u.UID = 0

	m := NewManager(config.Markers{Begin: "# BEGIN", End: "# END"}, config.Backups{MaxCount: 5, MaxAge: config.Duration(time.Hour)})
	_, err := m.Sync(u, "ssh-ed25519 AAAA test@example.com", nil)
	if err == nil {
		t.Fatal("expected chown error when running as non-root")
	}
}

func TestRestoreLatestBackupNoBackups(t *testing.T) {
	u := currentUser(t)
	_, _ = tempAuthPaths(t, u)

	m := NewManager(config.Markers{Begin: "# BEGIN", End: "# END"}, config.Backups{MaxCount: 5, MaxAge: config.Duration(time.Hour)})
	err := m.RestoreLatestBackup(u)
	if err == nil {
		t.Fatal("expected error when no backups exist")
	}
}

func TestIsReadOnlyError(t *testing.T) {
	if IsReadOnlyError(nil) {
		t.Error("nil should not be read-only")
	}
	if IsReadOnlyError(os.ErrNotExist) {
		t.Error("ErrNotExist should not be read-only")
	}
	if !IsReadOnlyError(syscall.EROFS) {
		t.Error("EROFS should be read-only")
	}
}
