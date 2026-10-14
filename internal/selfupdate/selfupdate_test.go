package selfupdate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/matthewgall/key-daemon/internal/update"
)

type fakeChecker struct {
	info *update.Info
	err  error
}

func (f *fakeChecker) LatestRelease(ctx context.Context) (*update.Info, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.info, nil
}

func TestUpdaterAlreadyUpToDate(t *testing.T) {
	u := &Updater{
		checker: &fakeChecker{info: &update.Info{Version: "v1.0.0"}},
	}
	_, err := u.Run(context.Background(), "v1.0.0")
	if err == nil || err.Error() != "already up to date (v1.0.0)" {
		t.Fatalf("expected already up to date error, got: %v", err)
	}
}

func TestUpdaterRefusesNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("test only runs on non-linux")
	}
	u := &Updater{checker: &fakeChecker{info: &update.Info{Version: "v9.9.9"}}}
	_, err := u.Run(context.Background(), "v1.0.0")
	if err == nil {
		t.Fatal("expected non-linux error")
	}
}

func TestSha256Sum(t *testing.T) {
	f, err := os.CreateTemp("", "sha-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	fmt.Fprint(f, "hello")
	f.Close()

	r, err := os.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	sum, err := sha256sum(r)
	if err != nil {
		t.Fatal(err)
	}
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if sum != want {
		t.Fatalf("expected %s, got %s", want, sum)
	}
}

func TestFindChecksum(t *testing.T) {
	checksums := []byte("abc123  key-daemon-linux-amd64\ndef456  key-daemon-linux-arm64\n")
	path := filepath.Join(t.TempDir(), "checksums.txt")
	if err := os.WriteFile(path, checksums, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := findChecksum(path, "key-daemon-linux-arm64")
	if err != nil {
		t.Fatal(err)
	}
	if got != "def456" {
		t.Fatalf("expected def456, got %s", got)
	}
	_, err = findChecksum(path, "missing")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
