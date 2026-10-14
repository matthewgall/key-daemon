package keys

import (
	"bufio"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// MaxKeyLineLength is the maximum length of a single authorized_keys line
// that will be parsed. Longer lines are rejected to avoid memory exhaustion.
const MaxKeyLineLength = 16 * 1024 // 16 KiB

var (
	keyTypes = map[string]struct{}{
		"ssh-rsa":                            {},
		"ssh-ed25519":                        {},
		"ecdsa-sha2-nistp256":                {},
		"ecdsa-sha2-nistp384":                {},
		"ecdsa-sha2-nistp521":                {},
		"sk-ssh-ed25519@openssh.com":         {},
		"sk-ecdsa-sha2-nistp256@openssh.com": {},
	}

	base64RE = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)
	htmlRE   = regexp.MustCompile(`(?i)<!doctype\s+html|<html|<head|<body`)
	nullByte = []byte{0}
)

// Key represents a single parsed authorized_keys entry.
type Key struct {
	// Raw is the full original line.
	Raw string
	// Canonical is "<type> <base64>" used for deduplication.
	Canonical string
	// Type is the SSH key algorithm.
	Type string
}

// IsValidKeyType reports whether t is a supported public-key algorithm.
func IsValidKeyType(t string) bool {
	_, ok := keyTypes[t]
	return ok
}

// ParseLine attempts to parse a single authorized_keys line.
// It returns nil for empty lines and comments.
func ParseLine(line string) (*Key, error) {
	if len(line) > MaxKeyLineLength {
		return nil, fmt.Errorf("line exceeds maximum length of %d bytes", MaxKeyLineLength)
	}

	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, nil
	}

	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return nil, fmt.Errorf("not enough fields")
	}

	// The key type may be preceded by options. Scan fields for a valid key type.
	for i, f := range fields {
		if !IsValidKeyType(f) {
			continue
		}
		if i+1 >= len(fields) {
			return nil, fmt.Errorf("key type %q without key material", f)
		}
		material := fields[i+1]
		if !base64RE.MatchString(material) || len(material) < 20 {
			return nil, fmt.Errorf("invalid key material for %q", f)
		}
		return &Key{
			Raw:       trimmed,
			Canonical: fmt.Sprintf("%s %s", f, material),
			Type:      f,
		}, nil
	}

	return nil, fmt.Errorf("no valid key type found")
}

// Parse extracts valid keys from multiline text.
func Parse(text string) ([]Key, error) {
	if strings.Contains(text, string(nullByte)) {
		return nil, errors.New("null byte found in key data")
	}
	if htmlRE.MatchString(text) {
		return nil, errors.New("HTML detected in key data")
	}

	var keys []Key
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		key, err := ParseLine(line)
		if err != nil {
			// Skip invalid individual lines unless the whole file is empty.
			continue
		}
		if key != nil {
			keys = append(keys, *key)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}

// ParseRequireOne is like Parse but returns an error if no valid keys were found.
func ParseRequireOne(text string) ([]Key, error) {
	keys, err := Parse(text)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("no valid keys found")
	}
	return keys, nil
}

// Deduplicate returns a slice of unique keys, preserving first-seen order.
func Deduplicate(keys []Key) []Key {
	seen := make(map[string]struct{}, len(keys))
	out := make([]Key, 0, len(keys))
	for _, k := range keys {
		if _, ok := seen[k.Canonical]; ok {
			continue
		}
		seen[k.Canonical] = struct{}{}
		out = append(out, k)
	}
	return out
}

// Format returns the raw text of the keys as an authorized_keys fragment.
func Format(keys []Key) string {
	if len(keys) == 0 {
		return ""
	}
	lines := make([]string, len(keys))
	for i, k := range keys {
		lines[i] = k.Raw
	}
	return strings.Join(lines, "\n")
}
