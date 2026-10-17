package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultInterval            = 5 * time.Minute
	MinInterval                = 1 * time.Minute
	DefaultBeginMarker         = "# BEGIN key-daemon"
	DefaultEndMarker           = "# END key-daemon"
	DefaultMaxBackups          = 10
	DefaultMaxBackupAge        = 7 * 24 * time.Hour
	MinMaxBackups              = 1
	MaxMaxBackups              = 1000
	MinMaxBackupAge            = 1 * time.Hour
	DefaultConfigPath          = "/etc/key-daemon/config.yaml"
	DefaultUpdateCheckInterval = 24 * time.Hour
	MinUpdateCheckInterval     = 1 * time.Hour
)

// Source represents a single key source: a URL, GitHub user, or sshid.io handle.
type Source struct {
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

// UnmarshalYAML accepts either a shorthand string ("github:matthewgall")
// or a typed block ({type: github, value: matthewgall}).
func (s *Source) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		shorthand := node.Value
		parts := strings.SplitN(shorthand, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid source shorthand %q: expected type:value", shorthand)
		}
		s.Type = parts[0]
		s.Value = parts[1]
		return nil
	}

	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("source must be a string or mapping")
	}

	type rawSource Source
	var raw rawSource
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*s = Source(raw)
	return nil
}

// Duration is a time.Duration that also accepts a "d" suffix for days.
type Duration time.Duration

// UnmarshalYAML parses duration strings like "5m", "1h", "7d".
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}

	days := strings.Count(raw, "d")
	if days > 1 || (days == 1 && !strings.HasSuffix(raw, "d")) {
		return fmt.Errorf("invalid duration %q", raw)
	}

	if strings.HasSuffix(raw, "d") {
		v, err := parseDayDuration(raw)
		if err != nil {
			return err
		}
		*d = Duration(v)
		return nil
	}

	v, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	*d = Duration(v)
	return nil
}

func parseDayDuration(s string) (time.Duration, error) {
	num := strings.TrimSuffix(s, "d")
	if num == "" {
		return 0, fmt.Errorf("invalid day duration %q", s)
	}
	var n int
	if _, err := fmt.Sscanf(num, "%d", &n); err != nil {
		return 0, fmt.Errorf("invalid day duration %q: %w", s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("negative day duration %q", s)
	}
	return time.Duration(n) * 24 * time.Hour, nil
}

func (d Duration) Duration() time.Duration { return time.Duration(d) }

// Backups holds backup retention policy.
type Backups struct {
	MaxCount int      `yaml:"max_count"`
	MaxAge   Duration `yaml:"max_age"`
}

// Metrics holds the optional HTTP metrics endpoint configuration.
type Metrics struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
	Path    string `yaml:"path"`
}

// RemoteConfig describes a remote source of truth for the configuration file.
type RemoteConfig struct {
	URL      string   `yaml:"url"`
	Token    string   `yaml:"token"`
	Interval Duration `yaml:"interval"`
}

// Markers holds the authorized_keys section delimiters.
type Markers struct {
	Begin string `yaml:"begin"`
	End   string `yaml:"end"`
}

// User holds per-user configuration.
type User struct {
	Name    string   `yaml:"name"`
	Sources []Source `yaml:"sources,omitempty"`
}

// Config is the top-level daemon configuration.
type Config struct {
	Interval            Duration `yaml:"interval"`
	Markers             Markers  `yaml:"markers"`
	Backups             Backups  `yaml:"backups"`
	DefaultSources      []Source `yaml:"default_sources"`
	Users               []User   `yaml:"users"`
	DiscoverUserConfigs bool     `yaml:"discover_user_configs"`
	AllowedUserSources  []string `yaml:"allowed_user_sources"`
	DiscoverSkipShells  []string `yaml:"discover_skip_shells"`
	RunValidation       bool     `yaml:"validate"`
	CheckForUpdates     bool     `yaml:"check_for_updates"`
	UpdateCheckInterval Duration `yaml:"update_check_interval"`
	AllowedKeyTypes     []string     `yaml:"allowed_key_types"`
	Metrics             Metrics      `yaml:"metrics"`
	RemoteConfig        RemoteConfig `yaml:"remote_config"`
	StatusFile          string       `yaml:"status_file"`
}

// Load reads and validates a YAML configuration from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return LoadBytes(data)
}

// LoadBytes parses and validates YAML config data.
func LoadBytes(data []byte) (*Config, error) {
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// Default returns a Config populated with sensible defaults.
func Default() *Config {
	return &Config{
		Interval: Duration(DefaultInterval),
		Markers: Markers{
			Begin: DefaultBeginMarker,
			End:   DefaultEndMarker,
		},
		Backups: Backups{
			MaxCount: DefaultMaxBackups,
			MaxAge:   Duration(DefaultMaxBackupAge),
		},
		AllowedUserSources: []string{"github", "gitlab", "codeberg", "sourcehut", "launchpad", "sshid"},
		DiscoverSkipShells: []string{
			"/bin/false",
			"/usr/sbin/nologin",
			"/usr/bin/nologin",
		},
		RunValidation:       true,
		CheckForUpdates:     false,
		UpdateCheckInterval: Duration(DefaultUpdateCheckInterval),
		Metrics: Metrics{
			Enabled: false,
			Address: "127.0.0.1:9123",
			Path:    "/metrics",
		},
		RemoteConfig: RemoteConfig{
			Interval: Duration(DefaultInterval),
		},
	}
}

// Validate checks that the configuration is usable.
func (c *Config) Validate() error {
	if c.Interval.Duration() < MinInterval {
		return fmt.Errorf("interval must be at least %s", MinInterval)
	}

	if c.Markers.Begin == "" || c.Markers.End == "" {
		return errors.New("marker begin and end must not be empty")
	}
	if c.Markers.Begin == c.Markers.End {
		return errors.New("marker begin and end must be different")
	}

	if c.UpdateCheckInterval.Duration() < MinUpdateCheckInterval {
		return fmt.Errorf("update_check_interval must be at least %s", MinUpdateCheckInterval)
	}

	if c.Backups.MaxCount < MinMaxBackups || c.Backups.MaxCount > MaxMaxBackups {
		return fmt.Errorf("backups.max_count must be between %d and %d", MinMaxBackups, MaxMaxBackups)
	}
	if c.Backups.MaxAge.Duration() < MinMaxBackupAge {
		return fmt.Errorf("backups.max_age must be at least %s", MinMaxBackupAge)
	}

	for i, src := range c.DefaultSources {
		if err := validateSource(src, fmt.Sprintf("default_sources[%d]", i)); err != nil {
			return err
		}
	}

	seenKeyTypes := make(map[string]struct{})
	for i, kt := range c.AllowedKeyTypes {
		if kt == "" {
			return fmt.Errorf("allowed_key_types[%d] is empty", i)
		}
		if !AllowedKeyType(kt) {
			return fmt.Errorf("allowed_key_types[%d] has unsupported key type %q", i, kt)
		}
		if _, ok := seenKeyTypes[kt]; ok {
			return fmt.Errorf("allowed_key_types contains duplicate %q", kt)
		}
		seenKeyTypes[kt] = struct{}{}
	}

	if c.Metrics.Enabled {
		if c.Metrics.Address == "" {
			return errors.New("metrics.address is required when metrics.enabled is true")
		}
		if c.Metrics.Path == "" {
			return errors.New("metrics.path is required when metrics.enabled is true")
		}
		if !strings.HasPrefix(c.Metrics.Path, "/") {
			return errors.New("metrics.path must start with /")
		}
	}

	if c.RemoteConfig.URL != "" {
		if !strings.HasPrefix(c.RemoteConfig.URL, "https://") {
			return errors.New("remote_config.url must use https://")
		}
		if c.RemoteConfig.Interval.Duration() < MinInterval {
			return fmt.Errorf("remote_config.interval must be at least %s", MinInterval)
		}
	}

	seenUsers := make(map[string]int)
	for i, u := range c.Users {
		if u.Name == "" {
			return fmt.Errorf("users[%d].name is required", i)
		}
		if prev, ok := seenUsers[u.Name]; ok {
			return fmt.Errorf("duplicate user %q at users[%d] and users[%d]", u.Name, prev, i)
		}
		seenUsers[u.Name] = i

		sources := u.Sources
		if len(sources) == 0 {
			sources = c.DefaultSources
		}
		for j, src := range sources {
			if err := validateSource(src, fmt.Sprintf("users[%d].sources[%d]", i, j)); err != nil {
				return err
			}
		}
	}

	if c.DiscoverUserConfigs {
		if len(c.AllowedUserSources) == 0 {
			return errors.New("allowed_user_sources must not be empty when discover_user_configs is enabled")
		}
		for i, t := range c.AllowedUserSources {
			if !isAllowedUserSourceType(t) {
				return fmt.Errorf("allowed_user_sources[%d] has unsupported type %q", i, t)
			}
		}
	}

	return nil
}

func isAllowedUserSourceType(t string) bool {
	switch t {
	case "url", "github", "gitlab", "codeberg", "sourcehut", "launchpad", "sshid":
		return true
	}
	return false
}

func validateSource(src Source, path string) error {
	switch src.Type {
	case "url", "github", "gitlab", "codeberg", "sourcehut", "launchpad", "sshid":
		if src.Value == "" {
			return fmt.Errorf("%s value is required", path)
		}
	default:
		return fmt.Errorf("%s has unsupported type %q", path, src.Type)
	}
	if src.Type == "url" && !strings.HasPrefix(src.Value, "https://") {
		return fmt.Errorf("%s url must use https://", path)
	}
	return nil
}

// AllowedKeyType reports whether t is a supported SSH public key algorithm.
func AllowedKeyType(t string) bool {
	switch t {
	case "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com",
		"sk-ecdsa-sha2-nistp256@openssh.com":
		return true
	}
	return false
}

// EffectiveSources returns the sources that apply to a user, falling back to defaults.
func (c *Config) EffectiveSources(user User) []Source {
	if len(user.Sources) > 0 {
		return user.Sources
	}
	return c.DefaultSources
}
