package keys

import (
	"strings"
	"testing"
)

const (
	validEd25519   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIhz2GK/XCUj4i6Q5yQJNL1MXMY0RxzPV2QrBqfHrDq test@example.com"
	validRSA       = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest test@example.com"
	validECDSA     = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHGG test@example.com"
	validSkED25519 = "sk-ssh-ed25519@openssh.com AAAAC3NzaC1lZDI1NTE5AAAAIDIhz2GK/XCUj4i6Q5yQJNL1MXMY0RxzPV2QrBqfHrDq test@example.com"
)

func TestParseLineValid(t *testing.T) {
	for _, line := range []string{validEd25519, validRSA, validECDSA, validSkED25519} {
		key, err := ParseLine(line)
		if err != nil {
			t.Errorf("ParseLine(%q) error: %v", line, err)
			continue
		}
		if key == nil {
			t.Errorf("ParseLine(%q) returned nil", line)
			continue
		}
		if key.Type == "" {
			t.Errorf("ParseLine(%q) missing type", line)
		}
		if key.Canonical == "" {
			t.Errorf("ParseLine(%q) missing canonical", line)
		}
	}
}

func TestParseLineWithOptions(t *testing.T) {
	line := `from="10.0.0.0/8",command="uptime" ` + validEd25519
	key, err := ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine error: %v", err)
	}
	if key == nil || key.Type != "ssh-ed25519" {
		t.Errorf("expected ssh-ed25519 with options, got %+v", key)
	}
}

func TestParseLineIgnoresCommentsAndEmpty(t *testing.T) {
	for _, line := range []string{"", "   ", "# comment"} {
		key, err := ParseLine(line)
		if err != nil {
			t.Errorf("ParseLine(%q) unexpected error: %v", line, err)
		}
		if key != nil {
			t.Errorf("ParseLine(%q) expected nil, got %+v", line, key)
		}
	}
}

func TestFilterByType(t *testing.T) {
	keys := parseKeys(t, []string{validEd25519, validRSA, validECDSA, validSkED25519})

	filtered := FilterByType(keys, []string{"ssh-ed25519", "sk-ssh-ed25519@openssh.com"})
	if len(filtered) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(filtered))
	}
	for _, k := range filtered {
		if k.Type != "ssh-ed25519" && k.Type != "sk-ssh-ed25519@openssh.com" {
			t.Errorf("unexpected key type %q", k.Type)
		}
	}

	if got := FilterByType(keys, nil); len(got) != len(keys) {
		t.Errorf("empty allowed types should allow all, got %d", len(got))
	}
}

func parseKeys(t *testing.T, lines []string) []Key {
	t.Helper()
	out := make([]Key, 0, len(lines))
	for _, line := range lines {
		k, err := ParseLine(line)
		if err != nil {
			t.Fatalf("ParseLine(%q) error: %v", line, err)
		}
		if k == nil {
			t.Fatalf("ParseLine(%q) returned nil", line)
		}
		out = append(out, *k)
	}
	return out
}

func TestParseLineInvalid(t *testing.T) {
	lines := []string{
		"not-a-key",
		"ssh-ed25519",
		"ssh-foo AAAAC3NzaC1lZDI1NTE5AAAAIDIhz2GK",
		"ssh-ed25519 short",
	}
	for _, line := range lines {
		key, err := ParseLine(line)
		if err == nil && key != nil {
			t.Errorf("ParseLine(%q) should have failed, got %+v", line, key)
		}
	}
}

func TestParseLineRejectsOverlongLines(t *testing.T) {
	line := strings.Repeat("a", MaxKeyLineLength+1)
	_, err := ParseLine(line)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum length") {
		t.Fatalf("expected max-length error, got: %v", err)
	}
}

func TestParseRejectsHTML(t *testing.T) {
	_, err := Parse("<!DOCTYPE html><html><body>oops</body></html>")
	if err == nil || !strings.Contains(err.Error(), "HTML") {
		t.Errorf("expected HTML error, got: %v", err)
	}
}

func TestParseRejectsNullByte(t *testing.T) {
	_, err := Parse("ssh-ed25519 AAAAC3NzaC" + "\x00" + "C test")
	if err == nil || !strings.Contains(err.Error(), "null byte") {
		t.Errorf("expected null byte error, got: %v", err)
	}
}

func TestDeduplicate(t *testing.T) {
	keys := []Key{
		{Raw: validEd25519, Canonical: "ssh-ed25519 A", Type: "ssh-ed25519"},
		{Raw: validRSA, Canonical: "ssh-rsa B", Type: "ssh-rsa"},
		{Raw: validEd25519 + " # dup", Canonical: "ssh-ed25519 A", Type: "ssh-ed25519"},
	}

	uniq := Deduplicate(keys)
	if len(uniq) != 2 {
		t.Errorf("expected 2 unique keys, got %d", len(uniq))
	}
}

func TestParseRequireOne(t *testing.T) {
	_, err := ParseRequireOne("")
	if err == nil || !strings.Contains(err.Error(), "no valid keys") {
		t.Errorf("expected no valid keys error, got: %v", err)
	}

	keys, err := ParseRequireOne(validEd25519)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
}

func TestFormat(t *testing.T) {
	keys := []Key{
		{Raw: validEd25519, Canonical: "ssh-ed25519 A", Type: "ssh-ed25519"},
		{Raw: validRSA, Canonical: "ssh-rsa B", Type: "ssh-rsa"},
	}
	formatted := Format(keys)
	if !strings.Contains(formatted, validEd25519) {
		t.Error("formatted output missing first key")
	}
	if !strings.Contains(formatted, validRSA) {
		t.Error("formatted output missing second key")
	}
	if strings.Count(formatted, "\n") != 1 {
		t.Errorf("expected one newline, got %d", strings.Count(formatted, "\n"))
	}
}
