package discovery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/matthewgall/key-daemon/internal/config"
)

func currentUID() int {
	return os.Getuid()
}

func writePasswd(t *testing.T, entries string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(entries), 0o644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}
	return path
}

func writeUserConfig(t *testing.T, home string, content string) {
	t.Helper()
	dir := filepath.Join(home, ".config", "key-daemon")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func TestDiscoverFindsUsersWithConfig(t *testing.T) {
	allowed := []string{"github", "sshid"}
	d := NewDiscoverer(allowed)

	uid := currentUID()
	base := t.TempDir()
	aliceHome := filepath.Join(base, "alice")
	bobHome := filepath.Join(base, "bob")
	if err := os.MkdirAll(aliceHome, 0o755); err != nil {
		t.Fatalf("mkdir alice: %v", err)
	}
	if err := os.MkdirAll(bobHome, 0o755); err != nil {
		t.Fatalf("mkdir bob: %v", err)
	}

	writeUserConfig(t, aliceHome, "sources:\n  - github:alice\n")
	// Bob has no config.

	passwd := writePasswd(t, "alice:x:"+itoa(uid)+":1000:Alice:"+aliceHome+":/bin/bash\nbob:x:1001:1001:Bob:"+bobHome+":/bin/bash\n")
	d.SetPasswdPath(passwd)

	users, err := d.Discover()
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if len(users) != 1 {
		t.Fatalf("expected 1 discovered user, got %d", len(users))
	}
	if users[0].Name != "alice" {
		t.Errorf("expected user alice, got %q", users[0].Name)
	}
	if len(users[0].Sources) != 1 || users[0].Sources[0].Value != "alice" {
		t.Errorf("unexpected sources: %v", users[0].Sources)
	}
}

func TestDiscoverSkipsNoLogin(t *testing.T) {
	allowed := []string{"github"}
	d := NewDiscoverer(allowed)

	base := t.TempDir()
	home := filepath.Join(base, "svc")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeUserConfig(t, home, "sources:\n  - github:svc\n")

	passwd := writePasswd(t, "svc:x:999:999:Service:"+home+":/usr/sbin/nologin\n")
	d.SetPasswdPath(passwd)

	users, err := d.Discover()
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected no discovered users, got %d", len(users))
	}
}

func TestDiscoverRejectsDisallowedSourceType(t *testing.T) {
	allowed := []string{"github"}
	d := NewDiscoverer(allowed)

	uid := currentUID()
	base := t.TempDir()
	home := filepath.Join(base, "user")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeUserConfig(t, home, "sources:\n  - sshid:user\n")

	passwd := writePasswd(t, "user:x:"+itoa(uid)+":1000:User:"+home+":/bin/bash\n")
	d.SetPasswdPath(passwd)

	_, err := d.Discover()
	if err == nil {
		t.Fatal("expected error for disallowed source type")
	}
}

func TestDiscoverRejectsWorldWritable(t *testing.T) {
	allowed := []string{"github"}
	d := NewDiscoverer(allowed)

	uid := currentUID()
	base := t.TempDir()
	home := filepath.Join(base, "user")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeUserConfig(t, home, "sources:\n  - github:user\n")
	configPath := filepath.Join(home, ".config", "key-daemon", "config.yaml")
	if err := os.Chmod(configPath, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	passwd := writePasswd(t, "user:x:"+itoa(uid)+":1000:User:"+home+":/bin/bash\n")
	d.SetPasswdPath(passwd)

	_, err := d.Discover()
	if err == nil {
		t.Fatal("expected error for world-writable config")
	}
}

func TestDiscoverRejectsBadOwnership(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to test ownership rejection")
	}

	allowed := []string{"github"}
	d := NewDiscoverer(allowed)

	base := t.TempDir()
	home := filepath.Join(base, "user")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeUserConfig(t, home, "sources:\n  - github:user\n")
	configPath := filepath.Join(home, ".config", "key-daemon", "config.yaml")
	if err := os.Chown(configPath, 1001, 1001); err != nil {
		t.Fatalf("chown: %v", err)
	}

	passwd := writePasswd(t, "user:x:1000:1000:User:"+home+":/bin/bash\n")
	d.SetPasswdPath(passwd)

	_, err := d.Discover()
	if err == nil {
		t.Fatal("expected error for config not owned by user")
	}
}

func TestDiscoverSkipsNonDirectoryHome(t *testing.T) {
	allowed := []string{"github"}
	d := NewDiscoverer(allowed)

	// Create a fake home path that exists but is a file.
	fakeHome := filepath.Join(t.TempDir(), "nothome")
	if err := os.WriteFile(fakeHome, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("write fake home: %v", err)
	}

	uid := currentUID()
	passwd := writePasswd(t, "weird:x:"+itoa(uid)+":1000:Weird:"+fakeHome+":/bin/bash\n")
	d.SetPasswdPath(passwd)

	users, err := d.Discover()
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected no users, got %d", len(users))
	}
}

func TestDiscoverNoConfig(t *testing.T) {
	allowed := []string{"github"}
	d := NewDiscoverer(allowed)

	uid := currentUID()
	base := t.TempDir()
	home := filepath.Join(base, "user")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	passwd := writePasswd(t, "user:x:"+itoa(uid)+":1000:User:"+home+":/bin/bash\n")
	d.SetPasswdPath(passwd)

	users, err := d.Discover()
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected no users, got %d", len(users))
	}
}

func TestDiscoverSkipsMalformedPasswd(t *testing.T) {
	allowed := []string{"github"}
	d := NewDiscoverer(allowed)

	passwd := writePasswd(t, "this is not a valid passwd line\n")
	d.SetPasswdPath(passwd)

	users, err := d.Discover()
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected no users, got %d", len(users))
	}
}

func TestValidateUserSource(t *testing.T) {
	tests := []struct {
		src     config.Source
		wantErr bool
	}{
		{config.Source{Type: "github", Value: "user"}, false},
		{config.Source{Type: "url", Value: "https://example.com/keys"}, false},
		{config.Source{Type: "url", Value: "http://example.com/keys"}, true},
		{config.Source{Type: "github", Value: ""}, true},
	}

	for i, tt := range tests {
		err := validateUserSource(tt.src, i)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateUserSource(%+v) error = %v, wantErr %v", tt.src, err, tt.wantErr)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
