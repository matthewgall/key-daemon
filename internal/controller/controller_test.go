package controller

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/matthewgall/key-daemon/internal/authkeys"
	"github.com/matthewgall/key-daemon/internal/config"
	"github.com/matthewgall/key-daemon/internal/discovery"
	"github.com/matthewgall/key-daemon/internal/logger"
	"github.com/matthewgall/key-daemon/internal/user"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// newTestController creates a Controller configured for root-mode tests.
// This avoids single-user filtering so tests can manage arbitrary users.
func newTestController(t *testing.T, path string, log *logger.Logger) *Controller {
	t.Helper()
	ctrl := New(path, log, "test")
	ctrl.isRootFn = func() bool { return true }
	ctrl.currentUserFn = func() (string, error) { return "testuser", nil }
	return ctrl
}

func TestRestore(t *testing.T) {
	log := logger.New(logger.ErrorLevel)
	ctrl := newTestController(t, writeConfig(t, ""), log)
	ctrl.resolver = resolverFunc(func(name string) (*user.Info, error) {
		return &user.Info{Name: name, UID: 0, GID: 0, HomeDir: t.TempDir()}, nil
	})
	ctrl.manager = &mockManager{}

	if err := ctrl.Restore(context.Background(), "testuser"); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}
	if !ctrl.manager.(*mockManager).restoreCalled {
		t.Error("expected RestoreLatestBackup to be called")
	}
}

func TestRestoreRequiresUsernameAsRoot(t *testing.T) {
	log := logger.New(logger.ErrorLevel)
	ctrl := New(writeConfig(t, ""), log, "test")
	ctrl.isRootFn = func() bool { return true }

	err := ctrl.Restore(context.Background(), "")
	if err == nil {
		t.Fatal("expected error when username is empty as root")
	}
	if !strings.Contains(err.Error(), "username is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRestoreDefaultsToCurrentUserWhenNotRoot(t *testing.T) {
	log := logger.New(logger.ErrorLevel)
	ctrl := New(writeConfig(t, ""), log, "test")
	ctrl.isRootFn = func() bool { return false }
	ctrl.currentUserFn = func() (string, error) { return "testuser", nil }
	ctrl.resolver = resolverFunc(func(name string) (*user.Info, error) {
		return &user.Info{Name: name, UID: 0, GID: 0, HomeDir: t.TempDir()}, nil
	})
	ctrl.manager = &mockManager{}

	if err := ctrl.Restore(context.Background(), ""); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}
	if !ctrl.manager.(*mockManager).restoreCalled {
		t.Error("expected RestoreLatestBackup to be called")
	}
}

func TestWriteAndReadStatus(t *testing.T) {
	log := logger.New(logger.ErrorLevel)
	ctrl := newTestController(t, writeConfig(t, ""), log)
	statusPath := filepath.Join(t.TempDir(), "status.json")
	ctrl.statusPath = statusPath

	cfg, err := config.Load(writeConfig(t, `
users:
  - name: root
    sources:
      - github:coder
`))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if err := ctrl.writeStatus(cfg, true, 3, 7); err != nil {
		t.Fatalf("write status: %v", err)
	}
	if _, err := os.Stat(statusPath); err != nil {
		t.Errorf("status file not created: %v", err)
	}

	status, err := ctrl.Status()
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status.Users != 3 || status.Keys != 7 || !status.LastSyncOK {
		t.Errorf("unexpected status: %+v", status)
	}
}

func TestSyncHappyPath(t *testing.T) {
	path := writeConfig(t, `
users:
  - name: root
    sources:
      - url:https://example.com/keys
`)

	logBuf := &strings.Builder{}
	log := logger.New(logger.DebugLevel)
	log.SetOutput(logBuf)

	ctrl := newTestController(t, path, log)
	ctrl.resolver = resolverFunc(func(name string) (*user.Info, error) {
		return &user.Info{Name: name, UID: 0, GID: 0, HomeDir: t.TempDir()}, nil
	})
	ctrl.provider = &mockProvider{keys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoodKeyMaterialHere test@example.com"}
	ctrl.manager = &mockManager{}

	if err := ctrl.Sync(context.Background()); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if !ctrl.manager.(*mockManager).syncCalled {
		t.Error("manager.Sync was not called")
	}
}

func TestSyncSkipsMissingUsers(t *testing.T) {
	path := writeConfig(t, `
users:
  - name: nobody
    sources:
      - url:https://example.com/keys
`)

	log := logger.New(logger.DebugLevel)
	ctrl := newTestController(t, path, log)
	ctrl.resolver = resolverFunc(func(name string) (*user.Info, error) {
		return nil, errors.New("user not found")
	})
	ctrl.provider = &mockProvider{keys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoodKeyMaterialHere test@example.com"}
	ctrl.manager = &mockManager{}

	err := ctrl.Sync(context.Background())
	if err == nil {
		t.Fatal("expected Sync to report error for missing user")
	}
	if !strings.Contains(err.Error(), "nobody") {
		t.Errorf("error should mention user: %v", err)
	}
}

func TestSyncFailOpenOnFetchError(t *testing.T) {
	path := writeConfig(t, `
users:
  - name: root
    sources:
      - url:https://example.com/keys
`)

	log := logger.New(logger.DebugLevel)
	ctrl := newTestController(t, path, log)
	ctrl.resolver = resolverFunc(func(name string) (*user.Info, error) {
		return &user.Info{Name: name, UID: 0, GID: 0, HomeDir: t.TempDir()}, nil
	})
	ctrl.provider = &mockProvider{err: errors.New("network down")}
	ctrl.manager = &mockManager{}

	err := ctrl.Sync(context.Background())
	if err != nil {
		t.Fatalf("expected fail-open, got error: %v", err)
	}
	if ctrl.manager.(*mockManager).syncCalled {
		t.Error("manager.Sync should not be called when fetch fails")
	}
}

func TestSyncFailOpenOnInvalidKeys(t *testing.T) {
	path := writeConfig(t, `
users:
  - name: root
    sources:
      - url:https://example.com/keys
`)

	log := logger.New(logger.DebugLevel)
	ctrl := newTestController(t, path, log)
	ctrl.resolver = resolverFunc(func(name string) (*user.Info, error) {
		return &user.Info{Name: name, UID: 0, GID: 0, HomeDir: t.TempDir()}, nil
	})
	ctrl.provider = &mockProvider{keys: "<!DOCTYPE html><html>bad</html>"}
	ctrl.manager = &mockManager{}

	err := ctrl.Sync(context.Background())
	if err != nil {
		t.Fatalf("expected fail-open on invalid keys, got error: %v", err)
	}
	if ctrl.manager.(*mockManager).syncCalled {
		t.Error("manager.Sync should not be called when keys are invalid")
	}
}

func TestRunHonoursContextCancellation(t *testing.T) {
	path := writeConfig(t, `
users:
  - name: root
    sources:
      - url:https://example.com/keys
`)

	log := logger.New(logger.DebugLevel)
	ctrl := newTestController(t, path, log)
	ctrl.resolver = resolverFunc(func(name string) (*user.Info, error) {
		return &user.Info{Name: name, UID: 0, GID: 0, HomeDir: t.TempDir()}, nil
	})
	ctrl.provider = &mockProvider{keys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoodKeyMaterialHere test@example.com"}
	ctrl.manager = &mockManager{}
	ctrl.interval = 1 * time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- ctrl.Run(ctx)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}
}

func TestRunSIGHUPReloads(t *testing.T) {
	path := writeConfig(t, `
users:
  - name: root
    sources:
      - url:https://example.com/keys
`)

	log := logger.New(logger.DebugLevel)
	ctrl := newTestController(t, path, log)
	ctrl.resolver = resolverFunc(func(name string) (*user.Info, error) {
		return &user.Info{Name: name, UID: 0, GID: 0, HomeDir: t.TempDir()}, nil
	})
	ctrl.provider = &mockProvider{keys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoodKeyMaterialHere test@example.com"}
	ctrl.manager = &mockManager{}
	ctrl.interval = 1 * time.Hour

	sigCh := make(chan os.Signal, 1)
	ctrl.testSignalCh = sigCh

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- ctrl.Run(ctx)
	}()

	// Wait for initial sync, then trigger SIGHUP.
	time.Sleep(50 * time.Millisecond)
	sigCh <- syscall.SIGHUP

	// Wait for reload sync, then stop.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}

	m := ctrl.manager.(*mockManager)
	if m.syncCount < 2 {
		t.Errorf("expected at least 2 syncs (initial + SIGHUP), got %d", m.syncCount)
	}
}

func TestSyncDiscoversAndAugmentsUsers(t *testing.T) {
	path := writeConfig(t, `
discover_user_configs: true
allowed_user_sources:
  - github
users:
  - name: globaluser
    sources:
      - github:globaluser
`)

	log := logger.New(logger.DebugLevel)
	ctrl := newTestController(t, path, log)
	ctrl.resolver = resolverFunc(func(name string) (*user.Info, error) {
		return &user.Info{Name: name, UID: 0, GID: 0, HomeDir: t.TempDir()}, nil
	})
	ctrl.provider = &mockProvider{keys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoodKeyMaterialHere test@example.com"}
	ctrl.manager = &mockManager{}

	// Inject a discoverer that returns one new user and augments an existing one.
	ctrl.discoverer = &mockDiscoverer{
		users: []discovery.User{
			{
				Name:    "globaluser",
				HomeDir: t.TempDir(),
				UID:     1000,
				Sources: []config.Source{{Type: "github", Value: "extra"}},
			},
			{
				Name:    "discovereduser",
				HomeDir: t.TempDir(),
				UID:     1001,
				Sources: []config.Source{{Type: "github", Value: "discovered"}},
			},
		},
	}

	if err := ctrl.Sync(context.Background()); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if ctrl.manager.(*mockManager).syncCount != 2 {
		t.Errorf("expected 2 syncs, got %d", ctrl.manager.(*mockManager).syncCount)
	}
}

func TestSyncSingleUserMode(t *testing.T) {
	path := writeConfig(t, `
users:
  - name: root
    sources:
      - github:matthewgall
  - name: coder
    sources:
      - github:coder
`)

	log := logger.New(logger.DebugLevel)
	ctrl := New(path, log, "test")
	ctrl.isRootFn = func() bool { return false }
	ctrl.currentUserFn = func() (string, error) { return "coder", nil }
	ctrl.resolver = resolverFunc(func(name string) (*user.Info, error) {
		return &user.Info{Name: name, UID: 104, GID: 111, HomeDir: t.TempDir()}, nil
	})
	ctrl.provider = &mockProvider{keys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoodKeyMaterialHere test@example.com"}
	ctrl.manager = &mockManager{}

	if err := ctrl.Sync(context.Background()); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	m := ctrl.manager.(*mockManager)
	if m.syncCount != 1 {
		t.Errorf("expected 1 sync for current user, got %d", m.syncCount)
	}
}

func TestSyncSingleUserModeMissingGlobalConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")

	log := logger.New(logger.DebugLevel)
	ctrl := New(path, log, "test")
	ctrl.isRootFn = func() bool { return false }
	ctrl.currentUserFn = func() (string, error) { return "coder", nil }
	ctrl.resolver = resolverFunc(func(name string) (*user.Info, error) {
		return &user.Info{Name: name, UID: 104, GID: 111, HomeDir: t.TempDir()}, nil
	})
	ctrl.provider = &mockProvider{keys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoodKeyMaterialHere test@example.com"}
	ctrl.manager = &mockManager{}
	ctrl.discoverer = &mockDiscoverer{
		users: []discovery.User{
			{Name: "coder", HomeDir: t.TempDir(), UID: 104, Sources: []config.Source{{Type: "github", Value: "coder"}}},
		},
	}

	if err := ctrl.Sync(context.Background()); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	m := ctrl.manager.(*mockManager)
	if m.syncCount != 1 {
		t.Errorf("expected 1 sync for discovered current user, got %d", m.syncCount)
	}
}

func TestSyncDiscoveryError(t *testing.T) {
	path := writeConfig(t, `
discover_user_configs: true
allowed_user_sources:
  - github
users:
  - name: root
    sources:
      - github:matthewgall
`)

	log := logger.New(logger.DebugLevel)
	ctrl := newTestController(t, path, log)
	ctrl.discoverer = &mockDiscoverer{err: errors.New("discovery failed")}

	if err := ctrl.Sync(context.Background()); err == nil {
		t.Fatal("expected error from discovery")
	}
}

func TestRunSIGTERMShutsDown(t *testing.T) {
	path := writeConfig(t, `
users:
  - name: root
    sources:
      - url:https://example.com/keys
`)

	log := logger.New(logger.DebugLevel)
	ctrl := newTestController(t, path, log)
	ctrl.resolver = resolverFunc(func(name string) (*user.Info, error) {
		return &user.Info{Name: name, UID: 0, GID: 0, HomeDir: t.TempDir()}, nil
	})
	ctrl.provider = &mockProvider{keys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoodKeyMaterialHere test@example.com"}
	ctrl.manager = &mockManager{}
	ctrl.interval = 1 * time.Hour

	sigCh := make(chan os.Signal, 1)
	ctrl.testSignalCh = sigCh

	ctx := context.Background()
	errCh := make(chan error, 1)
	go func() {
		errCh <- ctrl.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	sigCh <- syscall.SIGTERM

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after SIGTERM")
	}
}

// mockProvider is a test double for keyProvider.
type mockProvider struct {
	keys string
	err  error
}

func (m *mockProvider) FetchAll(ctx context.Context, sources []config.Source) (string, error) {
	return m.keys, m.err
}

// mockManager is a test double for keyManager.
type mockManager struct {
	syncCalled    bool
	syncCount     int
	restoreCalled bool
	err           error
}

func (m *mockManager) Sync(u *user.Info, managedKeys string, validate authkeys.ValidateFunc) (bool, error) {
	m.syncCalled = true
	m.syncCount++
	return true, m.err
}

func (m *mockManager) Preview(u *user.Info, managedKeys string, validate authkeys.ValidateFunc) (string, bool, error) {
	return managedKeys, true, m.err
}

func (m *mockManager) RestoreLatestBackup(u *user.Info) error {
	m.restoreCalled = true
	return m.err
}

// mockDiscoverer is a test double for userDiscoverer.
type mockDiscoverer struct {
	users []discovery.User
	err   error
}

func (m *mockDiscoverer) Discover() ([]discovery.User, error) {
	return m.users, m.err
}

var _ keyProvider = (*mockProvider)(nil)
var _ keyManager = (*mockManager)(nil)
var _ userDiscoverer = (*mockDiscoverer)(nil)
