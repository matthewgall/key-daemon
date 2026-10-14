package discovery

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/matthewgall/key-daemon/internal/config"
	"gopkg.in/yaml.v3"
)

const userConfigPath = ".config/key-daemon/config.yaml"

// User represents a user discovered via /etc/passwd with a valid per-user config.
type User struct {
	Name    string
	HomeDir string
	UID     int
	Sources []config.Source
}

// Discoverer finds users with per-user key-daemon configurations.
type Discoverer struct {
	allowedSources []string
	skipShells     map[string]struct{}
	passwdPath     string
}

// NewDiscoverer creates a Discoverer with the given allowed source types.
func NewDiscoverer(allowedSources []string) *Discoverer {
	skip := make(map[string]struct{})
	for _, s := range defaultSkipShells {
		skip[s] = struct{}{}
	}
	return &Discoverer{
		allowedSources: allowedSources,
		skipShells:     skip,
		passwdPath:     "/etc/passwd",
	}
}

// NewDiscovererWithSkipShells creates a Discoverer with custom skip shells.
func NewDiscovererWithSkipShells(allowedSources, skipShells []string) *Discoverer {
	skip := make(map[string]struct{}, len(skipShells))
	for _, s := range skipShells {
		skip[s] = struct{}{}
	}
	return &Discoverer{
		allowedSources: allowedSources,
		skipShells:     skip,
		passwdPath:     "/etc/passwd",
	}
}

// SetPasswdPath overrides the path to the passwd file. Used in tests.
func (d *Discoverer) SetPasswdPath(path string) {
	d.passwdPath = path
}

// Discover scans /etc/passwd and returns users with valid per-user configs.
func (d *Discoverer) Discover() ([]User, error) {
	entries, err := d.parsePasswd(d.passwdPath)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", d.passwdPath, err)
	}

	var users []User
	for _, e := range entries {
		if d.shouldSkip(e) {
			continue
		}

		configPath := filepath.Join(e.home, userConfigPath)
		sources, err := d.loadUserConfig(configPath, e.uid)
		if err != nil {
			// It is normal for users to not have a config.
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("user %q config: %w", e.username, err)
		}

		if len(sources) == 0 {
			continue
		}

		users = append(users, User{
			Name:    e.username,
			HomeDir: e.home,
			UID:     e.uid,
			Sources: sources,
		})
	}

	return users, nil
}

func (d *Discoverer) shouldSkip(e passwdEntry) bool {
	if e.home == "" {
		return true
	}
	if _, ok := d.skipShells[e.shell]; ok {
		return true
	}
	info, err := os.Stat(e.home)
	if err != nil || !info.IsDir() {
		return true
	}
	return false
}

func (d *Discoverer) loadUserConfig(path string, uid int) ([]config.Source, error) {
	if err := d.validatePermissions(path, uid); err != nil {
		// Permission denied likely means the file exists but we cannot read it,
		// or the home directory is inaccessible. Treat it as if there is no
		// usable per-user config for this user.
		if os.IsPermission(err) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg userConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	for i, src := range cfg.Sources {
		if !d.isAllowedSource(src) {
			return nil, fmt.Errorf("source %s:%s is not in allowed_user_sources", src.Type, src.Value)
		}
		if err := validateUserSource(src, i); err != nil {
			return nil, err
		}
	}

	return cfg.Sources, nil
}

func (d *Discoverer) isAllowedSource(src config.Source) bool {
	for _, t := range d.allowedSources {
		if t == src.Type {
			return true
		}
	}
	return false
}

func (d *Discoverer) validatePermissions(path string, uid int) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not determine ownership")
	}

	if stat.Uid != 0 && stat.Uid != uint32(uid) {
		return fmt.Errorf("must be owned by user %d or root", uid)
	}

	mode := info.Mode().Perm()
	if mode&0o022 != 0 {
		return fmt.Errorf("must not be writable by group or other")
	}

	return nil
}

type passwdEntry struct {
	username string
	uid      int
	home     string
	shell    string
}

// parsePasswd reads /etc/passwd and returns valid entries.
func (d *Discoverer) parsePasswd(path string) ([]passwdEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []passwdEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 7 {
			continue
		}

		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}

		entries = append(entries, passwdEntry{
			username: parts[0],
			uid:      uid,
			home:     parts[5],
			shell:    parts[6],
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

type userConfig struct {
	Sources []config.Source `yaml:"sources"`
}

func validateUserSource(src config.Source, idx int) error {
	if src.Value == "" {
		return fmt.Errorf("sources[%d] value is required", idx)
	}
	if src.Type == "url" && !strings.HasPrefix(src.Value, "https://") {
		return fmt.Errorf("sources[%d] url must use https://", idx)
	}
	return nil
}

var defaultSkipShells = []string{
	"/bin/false",
	"/usr/sbin/nologin",
	"/usr/bin/nologin",
}
