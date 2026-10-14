package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	osuser "os/user"
	"syscall"
	"time"

	"github.com/matthewgall/key-daemon/internal/authkeys"
	"github.com/matthewgall/key-daemon/internal/config"
	"github.com/matthewgall/key-daemon/internal/discovery"
	"github.com/matthewgall/key-daemon/internal/fetch"
	"github.com/matthewgall/key-daemon/internal/keys"
	"github.com/matthewgall/key-daemon/internal/logger"
	"github.com/matthewgall/key-daemon/internal/sources"
	"github.com/matthewgall/key-daemon/internal/sshd"
	"github.com/matthewgall/key-daemon/internal/user"
)

// userResolver looks up local user records.
type userResolver interface {
	Lookup(name string) (*user.Info, error)
}

// resolverFunc adapts a plain function to the userResolver interface.
type resolverFunc func(name string) (*user.Info, error)

func (f resolverFunc) Lookup(name string) (*user.Info, error) { return f(name) }

// currentUserFunc returns the current username. Overridable for tests.
type currentUserFunc func() (string, error)

// isRootFunc reports whether the process is running as root. Overridable for tests.
type isRootFunc func() bool

// keyProvider fetches raw key text from configured sources.
type keyProvider interface {
	FetchAll(ctx context.Context, sources []config.Source) (string, error)
}

// keyManager updates authorized_keys files safely.
type keyManager interface {
	Sync(u *user.Info, managedKeys string, validate authkeys.ValidateFunc) (bool, error)
}

// userDiscoverer finds users with per-user key-daemon configurations.
type userDiscoverer interface {
	Discover() ([]discovery.User, error)
}

// Controller orchestrates periodic key synchronization.
type Controller struct {
	configPath string
	log        *logger.Logger

	resolver   userResolver
	provider   keyProvider
	manager    keyManager
	validator  authkeys.ValidateFunc
	discoverer userDiscoverer

	// For tests: interval override.
	interval time.Duration
	// For tests: injected signal channel. If nil, real signals are used.
	testSignalCh chan os.Signal
	// For tests: override runtime user checks.
	currentUserFn currentUserFunc
	isRootFn      isRootFunc
}

// New creates a Controller using production dependencies.
func New(configPath string, log *logger.Logger) *Controller {
	fetcher := fetch.NewClient()
	return &Controller{
		configPath:    configPath,
		log:           log,
		resolver:      resolverFunc(user.Lookup),
		provider:      sources.NewProvider(fetcher),
		manager:       nil, // created per-config inside sync
		validator:     sshd.NewValidator().Validate,
		discoverer:    nil, // set after config is loaded
		currentUserFn: osuserCurrent,
		isRootFn:      isRoot,
	}
}

func osuserCurrent() (string, error) {
	u, err := osuser.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

func isRoot() bool {
	return os.Getuid() == 0
}

// Run starts the daemon loop. It returns when ctx is cancelled or SIGTERM is received.
func (c *Controller) Run(ctx context.Context) error {
	sigCh := c.signalChannel()
	if sigCh != c.testSignalCh {
		defer signal.Stop(sigCh)
	}

	if _, err := c.loadConfig(); err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := c.Sync(ctx); err != nil {
		c.log.Error("initial sync completed with errors", map[string]string{"error": err.Error()})
	}

	return c.runLoop(ctx, sigCh)
}

func (c *Controller) signalChannel() chan os.Signal {
	if c.testSignalCh != nil {
		return c.testSignalCh
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM)
	return sigCh
}

func (c *Controller) runLoop(ctx context.Context, sigCh chan os.Signal) error {
	for {
		interval := c.currentInterval()
		c.log.Debug("sleeping until next sync", map[string]string{"interval": interval.String()})

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			c.log.Info("shutting down")
			return nil

		case sig := <-sigCh:
			timer.Stop()
			if sig == syscall.SIGTERM {
				c.log.Info("shutting down")
				return nil
			}
			// SIGHUP: reload config and sync immediately.
			c.log.Info("reloading config after SIGHUP")
			if _, err := c.loadConfig(); err != nil {
				c.log.Error("failed to reload config", map[string]string{"error": err.Error()})
			} else if err := c.Sync(ctx); err != nil {
				c.log.Error("sync after reload completed with errors", map[string]string{"error": err.Error()})
			}

		case <-timer.C:
			if err := c.Sync(ctx); err != nil {
				c.log.Error("sync cycle completed with errors", map[string]string{"error": err.Error()})
			}
		}
	}
}

// Sync performs a single synchronization cycle against the current config.
func (c *Controller) Sync(ctx context.Context) error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}

	if c.manager == nil {
		c.manager = authkeys.NewManager(cfg.Markers, cfg.Backups)
	}

	users, err := c.buildUserList(cfg)
	if err != nil {
		return err
	}

	users, err = c.applyRuntimeRestrictions(users, cfg)
	if err != nil {
		return err
	}

	var errs []error
	for _, u := range users {
		if err := c.syncUser(ctx, cfg, u); err != nil {
			c.log.Error("failed to sync user", map[string]string{"user": u.Name, "error": err.Error()})
			errs = append(errs, fmt.Errorf("user %s: %w", u.Name, err))
		}
	}

	return errors.Join(errs...)
}

// applyRuntimeRestrictions filters the user list when not running as root.
// In single-user mode, only the current user is managed. It logs the reason
// for any skipped users so the operator understands the limitation.
func (c *Controller) applyRuntimeRestrictions(users []config.User, cfg *config.Config) ([]config.User, error) {
	if c.isRootFn() {
		return users, nil
	}

	current, err := c.currentUserFn()
	if err != nil {
		return nil, fmt.Errorf("determine current user: %w", err)
	}

	c.log.Info("running in single-user mode", map[string]string{"user": current})

	var out []config.User
	for _, u := range users {
		if u.Name == current {
			out = append(out, u)
		} else {
			c.log.Warn("skipping user, root privileges required",
				map[string]string{"user": u.Name, "current_user": current})
		}
	}

	if cfg.DiscoverUserConfigs && len(out) == 0 {
		c.log.Warn("no per-user config found for current user; discovery enabled but no matching entry", nil)
	}

	return out, nil
}

func (c *Controller) buildUserList(cfg *config.Config) ([]config.User, error) {
	byName := make(map[string]config.User, len(cfg.Users))
	for _, u := range cfg.Users {
		u.Sources = cfg.EffectiveSources(u)
		byName[u.Name] = u
	}

	if cfg.DiscoverUserConfigs {
		if c.discoverer == nil {
			c.discoverer = discovery.NewDiscoverer(cfg.AllowedUserSources)
		}
		discovered, err := c.discoverer.Discover()
		if err != nil {
			return nil, fmt.Errorf("discover user configs: %w", err)
		}

		for _, d := range discovered {
			if existing, ok := byName[d.Name]; ok {
				existing.Sources = append(existing.Sources, d.Sources...)
				byName[d.Name] = existing
			} else {
				byName[d.Name] = config.User{Name: d.Name, Sources: d.Sources}
			}
		}
	}

	users := make([]config.User, 0, len(byName))
	for _, u := range cfg.Users {
		if discovered, ok := byName[u.Name]; ok {
			users = append(users, discovered)
			delete(byName, u.Name)
		}
	}
	for _, u := range byName {
		users = append(users, u)
	}

	return users, nil
}

func (c *Controller) syncUser(ctx context.Context, cfg *config.Config, u config.User) error {
	info, err := c.resolver.Lookup(u.Name)
	if err != nil {
		return fmt.Errorf("lookup: %w", err)
	}

	sources := cfg.EffectiveSources(u)
	if len(sources) == 0 {
		c.log.Warn("no sources configured for user", map[string]string{"user": u.Name})
		return nil
	}

	raw, err := c.provider.FetchAll(ctx, sources)
	if err != nil {
		c.log.Warn("failed to fetch keys, retaining existing managed keys",
			map[string]string{"user": u.Name, "error": err.Error()})
		return nil // fail open
	}

	parsed, err := keys.Parse(raw)
	if err != nil {
		c.log.Warn("fetched keys failed sanity checks, retaining existing managed keys",
			map[string]string{"user": u.Name, "error": err.Error()})
		return nil // fail open
	}

	if len(parsed) == 0 {
		c.log.Warn("no valid keys found, retaining existing managed keys",
			map[string]string{"user": u.Name})
		return nil
	}

	unique := keys.Deduplicate(parsed)
	managed := keys.Format(unique)

	validate := c.validator
	if !c.isRootFn() {
		c.log.Debug("skipping sshd validation in single-user mode", map[string]string{"user": u.Name})
		validate = nil
	} else if !cfg.RunValidation {
		c.log.Warn("sshd validation disabled in config", map[string]string{"user": u.Name})
		validate = nil
	}

	updated, err := c.manager.Sync(info, managed, validate)
	if err != nil {
		if errors.Is(err, sshd.ErrNoHostKeys) {
			c.log.Error("sshd validation cannot run because the system has no SSH host keys; run 'ssh-keygen -A' and restart key-daemon",
				map[string]string{"user": u.Name})
		}
		return fmt.Errorf("sync authorized_keys: %w", err)
	}

	if updated {
		c.log.Info("updated authorized_keys", map[string]string{
			"user": u.Name,
			"keys": fmt.Sprintf("%d", len(unique)),
		})
	} else {
		c.log.Debug("authorized_keys unchanged", map[string]string{"user": u.Name})
	}

	return nil
}

func (c *Controller) loadConfig() (*config.Config, error) {
	cfg, err := config.Load(c.configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !c.isRootFn() {
			cfg = config.Default()
			cfg.DiscoverUserConfigs = true
			c.interval = cfg.Interval.Duration()
			c.log.Info("no global config found, using defaults with per-user discovery", map[string]string{
				"config_path": c.configPath,
			})
			return cfg, nil
		}
		return nil, fmt.Errorf("load config: %w", err)
	}
	c.interval = cfg.Interval.Duration()
	return cfg, nil
}

func (c *Controller) currentInterval() time.Duration {
	if c.interval > 0 {
		return c.interval
	}
	return config.DefaultInterval
}
