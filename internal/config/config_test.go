package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
users:
  - name: root
    sources:
      - github:matthewgall
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Interval.Duration() != DefaultInterval {
		t.Errorf("interval default: got %v, want %v", cfg.Interval.Duration(), DefaultInterval)
	}
	if cfg.Markers.Begin != DefaultBeginMarker {
		t.Errorf("begin marker default: got %q", cfg.Markers.Begin)
	}
	if cfg.Backups.MaxCount != DefaultMaxBackups {
		t.Errorf("max_count default: got %d", cfg.Backups.MaxCount)
	}
}

func TestLoadTypedAndShorthandSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
interval: 2m
users:
  - name: root
    sources:
      - type: github
        value: matthewgall
      - sshid:matthewgall
      - url:https://example.com/keys
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Interval.Duration() != 2*time.Minute {
		t.Errorf("interval: got %v", cfg.Interval.Duration())
	}

	sources := cfg.Users[0].Sources
	if len(sources) != 3 {
		t.Fatalf("expected 3 sources, got %d", len(sources))
	}

	cases := []struct {
		wantType  string
		wantValue string
	}{
		{"github", "matthewgall"},
		{"sshid", "matthewgall"},
		{"url", "https://example.com/keys"},
	}

	for i, c := range cases {
		if sources[i].Type != c.wantType || sources[i].Value != c.wantValue {
			t.Errorf("source %d: got %s=%s, want %s=%s",
				i, sources[i].Type, sources[i].Value, c.wantType, c.wantValue)
		}
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "interval too short",
			content: `
interval: 30s
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "interval must be at least",
		},
		{
			name: "duplicate user",
			content: `
users:
  - name: root
    sources:
      - github:matthewgall
  - name: root
    sources:
      - github:other
`,
			wantErr: "duplicate user",
		},
		{
			name: "missing user name",
			content: `
users:
  - sources:
      - github:matthewgall
`,
			wantErr: "name is required",
		},
		{
			name: "unsupported source type",
			content: `
users:
  - name: root
    sources:
      - bitbucket:matthewgall
`,
			wantErr: "unsupported type",
		},
		{
			name: "non-https url",
			content: `
users:
  - name: root
    sources:
      - url:http://example.com/keys
`,
			wantErr: "must use https://",
		},
		{
			name: "non-https remote config",
			content: `
remote_config:
  url: http://example.com/config.yaml
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "remote_config.url must use https://",
		},
		{
			name: "remote config interval too short",
			content: `
remote_config:
  url: https://example.com/config.yaml
  interval: 30s
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "remote_config.interval must be at least",
		},
		{
			name: "remote config public key requires signature url",
			content: `
remote_config:
  public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIhz2GKHuG2bJ55x2wv5F_qDFLZxFKL3ZGe1kqx93Gf"
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "signature_url is required",
		},
		{
			name: "remote config invalid public key",
			content: `
remote_config:
  url: https://example.com/config.yaml
  public_key: "not-a-key"
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "public_key is invalid",
		},
		{
			name: "jitter must be less than interval",
			content: `
interval: 1m
jitter: 1m
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "jitter",
		},
		{
			name: "empty markers",
			content: `
markers:
  begin: ""
  end: "# END"
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "marker begin and end must not be empty",
		},
		{
			name: "same markers",
			content: `
markers:
  begin: "# MARK"
  end: "# MARK"
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "marker begin and end must be different",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatalf("write config: %v", err)
			}

			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestRemoteConfigSigning(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	content := fmt.Sprintf(`
remote_config:
  url: https://example.com/config.yaml
  signature_url: https://example.com/config.yaml.sig
  public_key: %q
  interval: 1h
users:
  - name: root
    sources:
      - github:matthewgall
`, pubLine)

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.RemoteConfig.PublicKey != pubLine {
		t.Errorf("public key not loaded correctly")
	}
}

func TestLoadReadError(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestLoadParseError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("not valid yaml: ["), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestSourceUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "shorthand missing colon",
			content: `
users:
  - name: root
    sources:
      - github
`,
			wantErr: "invalid source shorthand",
		},
		{
			name: "shorthand empty type",
			content: `
users:
  - name: root
    sources:
      - :matthewgall
`,
			wantErr: "invalid source shorthand",
		},
		{
			name: "invalid node type",
			content: `
users:
  - name: root
    sources:
      - [1, 2]
`,
			wantErr: "source must be a string or mapping",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestDurationParsing(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"5m", 5 * time.Minute},
		{"1h", 1 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"1d", 24 * time.Hour},
	}
	for _, tt := range tests {
		path := filepath.Join(t.TempDir(), "config.yaml")
		content := "interval: " + tt.input + "\nusers:\n  - name: root\n    sources:\n      - github:matthewgall\n"
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load(%q) failed: %v", tt.input, err)
		}
		if cfg.Interval.Duration() != tt.want {
			t.Errorf("Load(%q): got %v, want %v", tt.input, cfg.Interval.Duration(), tt.want)
		}
	}
}

func TestDurationUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "not a string",
			content: `
interval: 5
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "invalid duration",
		},
		{
			name: "bad day suffix",
			content: `
interval: 5x
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "invalid duration",
		},
		{
			name: "empty day",
			content: `
interval: d
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "invalid day duration",
		},
		{
			name: "negative day",
			content: `
interval: -1d
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "negative day duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateBackupBounds(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "max_count too low",
			content: `
backups:
  max_count: 0
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "max_count must be between",
		},
		{
			name: "max_count too high",
			content: `
backups:
  max_count: 1001
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "max_count must be between",
		},
		{
			name: "max_age too low",
			content: `
backups:
  max_age: 30s
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "max_age must be at least",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateEmptySourceValue(t *testing.T) {
	content := `
users:
  - name: root
    sources:
      - type: github
        value: ""
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "value is required") {
		t.Errorf("expected value is required error, got: %v", err)
	}
}

func TestEffectiveSources(t *testing.T) {
	cfg := &Config{
		DefaultSources: []Source{{Type: "github", Value: "default"}},
		Users: []User{
			{Name: "root", Sources: []Source{{Type: "sshid", Value: "root"}}},
			{Name: "other"},
		},
	}

	if got := cfg.EffectiveSources(cfg.Users[0]); len(got) != 1 || got[0].Value != "root" {
		t.Errorf("root effective sources: %v", got)
	}
	if got := cfg.EffectiveSources(cfg.Users[1]); len(got) != 1 || got[0].Value != "default" {
		t.Errorf("other effective sources: %v", got)
	}
}

func TestAllowedKeyTypesValidation(t *testing.T) {
	base := `
users:
  - name: root
    sources:
      - github:matthewgall
`
	cases := []struct {
		name    string
		extra   string
		wantErr string
	}{
		{
			name: "valid key type",
			extra: `allowed_key_types:
  - ssh-ed25519
`,
		},
		{
			name: "unsupported key type",
			extra: `allowed_key_types:
  - ssh-dss
`,
			wantErr: "unsupported key type",
		},
		{
			name: "duplicate key type",
			extra: `allowed_key_types:
  - ssh-ed25519
  - ssh-ed25519
`,
			wantErr: "duplicate",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(base+tt.extra), 0o644); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err := Load(path)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestAllowedUserSourcesValidation(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "empty allowed sources when discovery enabled",
			content: `
discover_user_configs: true
allowed_user_sources: []
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "allowed_user_sources must not be empty",
		},
		{
			name: "unsupported allowed source type",
			content: `
discover_user_configs: true
allowed_user_sources:
  - bitbucket
users:
  - name: root
    sources:
      - github:matthewgall
`,
			wantErr: "unsupported type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
