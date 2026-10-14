package user

import (
	"os"
	"testing"
)

func TestLookupCurrentUser(t *testing.T) {
	name := os.Getenv("USER")
	if name == "" {
		t.Skip("USER not set")
	}

	info, err := Lookup(name)
	if err != nil {
		t.Fatalf("Lookup(%q) failed: %v", name, err)
	}

	if info.Name != name {
		t.Errorf("name: got %q, want %q", info.Name, name)
	}
	if info.UID <= 0 {
		t.Errorf("uid should be positive, got %d", info.UID)
	}
	if info.GID < 0 {
		t.Errorf("gid should be non-negative, got %d", info.GID)
	}
	if info.HomeDir == "" {
		t.Error("home dir should not be empty")
	}
}

func TestLookupMissingUser(t *testing.T) {
	_, err := Lookup("definitely-not-a-real-user-12345")
	if err == nil {
		t.Error("expected error for missing user")
	}
}

func TestLookupIDCurrentUser(t *testing.T) {
	name := os.Getenv("USER")
	if name == "" {
		t.Skip("USER not set")
	}

	current, err := Lookup(name)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	byID, err := LookupID(current.UID)
	if err != nil {
		t.Fatalf("LookupID(%d) failed: %v", current.UID, err)
	}

	if byID.Name != current.Name {
		t.Errorf("LookupID returned %q, want %q", byID.Name, current.Name)
	}
}

func TestLookupIDInvalid(t *testing.T) {
	_, err := LookupID(-1)
	if err == nil {
		t.Error("expected error for invalid UID")
	}
}
