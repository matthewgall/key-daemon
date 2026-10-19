package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	osuser "os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/matthewgall/key-daemon/internal/authkeys"
	"github.com/matthewgall/key-daemon/internal/signconfig"
	"github.com/matthewgall/key-daemon/internal/sysinfo"

	"github.com/matthewgall/key-daemon/internal/config"
	"github.com/matthewgall/key-daemon/internal/discovery"
	"github.com/matthewgall/key-daemon/internal/fetch"
	"github.com/matthewgall/key-daemon/internal/keys"
	"github.com/matthewgall/key-daemon/internal/logger"
	"github.com/matthewgall/key-daemon/internal/sources"
	"github.com/matthewgall/key-daemon/internal/sshd"
	"github.com/matthewgall/key-daemon/internal/update"
	"github.com/matthewgall/key-daemon/internal/user"
	"golang.org/x/crypto/ssh"
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
	Preview(u *user.Info, managedKeys string, validate authkeys.ValidateFunc) (string, bool, error)
	RestoreLatestBackup(u *user.Info) error
}

// userDiscoverer finds users with per-user key-daemon configurations.
type userDiscoverer interface {
	Discover() ([]discovery.User, error)
}

// updateChecker queries GitHub Releases for newer versions.
type updateChecker interface {
	LatestRelease(ctx context.Context) (*update.Info, error)
}

// Controller orchestrates periodic key synchronization.
type Controller struct {
	configPath string
	log        *logger.Logger
	version    string

	resolver   userResolver
	provider   keyProvider
	manager    keyManager
	validator  authkeys.ValidateFunc
	discoverer userDiscoverer
	checker    updateChecker
	dryRun     bool

	// For tests: interval override.
	interval time.Duration
	// For tests: max random jitter added to each interval.
	jitter time.Duration
	// For tests: injected signal channel. If nil, real signals are used.
	testSignalCh chan os.Signal
	// For tests: override runtime user checks.
	currentUserFn currentUserFunc
	isRootFn      isRootFunc
	// lastUpdateCheck tracks when we last queried for updates.
	lastUpdateCheck time.Time

	// Targeting state.
	sysInfo sysinfo.Info

	// Metrics state.
	metricsMu        sync.Mutex
	metricsSyncCount uint64
	metricsLastSync  time.Time
	metricsLastOK    bool
	metricsUsers     int
	metricsKeys      int

	// Remote config state.
	remoteClient  *http.Client
	remoteLastReq time.Time

	// External IP state.
	externalClient *http.Client
	externalIPFn   func(ctx context.Context, client *http.Client, url string) (net.IP, error)

	// statusPath is the default path for persisting sync status.
	statusPath string
}

// SyncStatus describes the outcome of the most recent sync cycle. It is
// written to the configured status file so that `key-daemon status` can
// report on the daemon without runtime coupling.
type SyncStatus struct {
	ConfigPath string    `json:"config_path"`
	RemoteURL  string    `json:"remote_url,omitempty"`
	LastSync   time.Time `json:"last_sync"`
	LastSyncOK bool      `json:"last_sync_ok"`
	Users      int       `json:"users"`
	Keys       int       `json:"keys"`
}

// New creates a Controller using production dependencies. The version string
// is used to identify the running binary in User-Agent headers and update
// checks.
func New(configPath string, log *logger.Logger, version string) *Controller {
	fetcher := fetch.NewClient(userAgent(version))
	sinfo, _ := sysinfo.Gather()
	return &Controller{
		configPath:     configPath,
		log:            log,
		sysInfo:        sinfo,
		externalClient: &http.Client{Timeout: 10 * time.Second},
		externalIPFn:   sysinfo.FetchExternalIP,
		resolver:       resolverFunc(user.Lookup),
		provider:       sources.NewProvider(fetcher),
		manager:        nil, // created per-config inside sync
		validator:      sshd.NewValidator().Validate,
		discoverer:     nil, // set after config is loaded
		checker:        update.NewChecker(version),
		version:        version,
		currentUserFn:  osuserCurrent,
		isRootFn:       isRoot,
	}
}

// userAgent returns a User-Agent fragment for the given version.
// A bare version like "v1.5.2" is prefixed with "key-daemon/".
// Existing prefixes or unknown/development versions are returned unchanged.
func userAgent(version string) string {
	version = strings.TrimSpace(version)
	if version == "" || version == "dev" {
		return "key-daemon"
	}
	if strings.HasPrefix(version, "key-daemon/") {
		return version
	}
	return "key-daemon/" + version
}

// SetVersion sets the running daemon version. Used for update checks.
func (c *Controller) SetVersion(v string) {
	c.version = v
}

// SetDryRun enables dry-run mode: sync reports what would change without
// writing to disk.
func (c *Controller) SetDryRun(dryRun bool) {
	c.dryRun = dryRun
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

	if _, err := c.loadConfig(ctx); err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := c.Sync(ctx); err != nil {
		c.log.Error("initial sync completed with errors", map[string]string{"error": err.Error()})
	}

	cfg, _ := c.loadConfig(ctx)
	if cfg != nil {
		c.maybeCheckForUpdates(ctx, cfg)
	}

	watchCh, cleanup, err := c.watchConfig()
	if err != nil {
		c.log.Warn("config file watch not available", map[string]string{"error": err.Error()})
	}
	if cleanup != nil {
		defer cleanup()
	}

	metricsShutdown := c.startMetricsServer(ctx, cfg)
	if metricsShutdown != nil {
		defer metricsShutdown()
	}

	return c.runLoop(ctx, sigCh, watchCh)
}

// startMetricsServer starts an HTTP server exposing metrics if enabled by
// the config. It returns a shutdown function or nil if no server was started.
func (c *Controller) startMetricsServer(ctx context.Context, cfg *config.Config) func() {
	if !cfg.Metrics.Enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.Metrics.Path, c.metricsHandler)

	srv := &http.Server{
		Addr:              cfg.Metrics.Address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		c.log.Info("starting metrics server", map[string]string{
			"address": cfg.Metrics.Address,
			"path":    cfg.Metrics.Path,
		})
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			c.log.Error("metrics server error", map[string]string{"error": err.Error()})
		}
	}()

	shutdown := func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(stopCtx)
	}

	go func() {
		<-ctx.Done()
		shutdown()
	}()

	return shutdown
}

// metricsHandler writes the current metrics in Prometheus text exposition format.
func (c *Controller) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	c.metricsMu.Lock()
	lastSync := c.metricsLastSync
	lastOK := c.metricsLastOK
	syncCount := c.metricsSyncCount
	users := c.metricsUsers
	keys := c.metricsKeys
	c.metricsMu.Unlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP key_daemon_sync_count_total Total number of sync cycles run.\n")
	fmt.Fprintf(w, "# TYPE key_daemon_sync_count_total counter\n")
	fmt.Fprintf(w, "key_daemon_sync_count_total %d\n", syncCount)
	fmt.Fprintf(w, "# HELP key_daemon_last_sync_timestamp_seconds Unix timestamp of the last sync cycle.\n")
	fmt.Fprintf(w, "# TYPE key_daemon_last_sync_timestamp_seconds gauge\n")
	if lastSync.IsZero() {
		fmt.Fprintf(w, "key_daemon_last_sync_timestamp_seconds 0\n")
	} else {
		fmt.Fprintf(w, "key_daemon_last_sync_timestamp_seconds %d\n", lastSync.Unix())
	}
	fmt.Fprintf(w, "# HELP key_daemon_last_sync_success Whether the last sync cycle succeeded (1) or not (0).\n")
	fmt.Fprintf(w, "# TYPE key_daemon_last_sync_success gauge\n")
	if lastOK {
		fmt.Fprintf(w, "key_daemon_last_sync_success 1\n")
	} else {
		fmt.Fprintf(w, "key_daemon_last_sync_success 0\n")
	}
	fmt.Fprintf(w, "# HELP key_daemon_users Number of users managed in the last sync cycle.\n")
	fmt.Fprintf(w, "# TYPE key_daemon_users gauge\n")
	fmt.Fprintf(w, "key_daemon_users %d\n", users)
	fmt.Fprintf(w, "# HELP key_daemon_keys Total number of unique managed keys across all users.\n")
	fmt.Fprintf(w, "# TYPE key_daemon_keys gauge\n")
	fmt.Fprintf(w, "key_daemon_keys %d\n", keys)
}

// recordMetrics stores the result of the latest sync cycle.
func (c *Controller) recordMetrics(cfg *config.Config, ok bool, users, keys int) {
	c.metricsMu.Lock()
	defer c.metricsMu.Unlock()
	c.metricsSyncCount++
	c.metricsLastSync = time.Now()
	c.metricsLastOK = ok
	c.metricsUsers = users
	c.metricsKeys = keys

	if err := c.writeStatus(cfg, ok, users, keys); err != nil {
		c.log.Debug("failed to write status file", map[string]string{"error": err.Error()})
	}
}

// writeStatus persists a snapshot of the latest sync cycle.
func (c *Controller) writeStatus(cfg *config.Config, ok bool, users, keys int) error {
	path := c.StatusFile()
	if path == "" {
		return nil
	}
	status := SyncStatus{
		ConfigPath: c.configPath,
		RemoteURL:  c.remoteConfigPath(cfg),
		LastSync:   time.Now(),
		LastSyncOK: ok,
		Users:      users,
		Keys:       keys,
	}
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// watchConfig returns a channel that receives a value whenever the global
// config file changes. It returns an error if fsnotify is unable to watch
// the config path.
func (c *Controller) watchConfig() (<-chan struct{}, func(), error) {
	if _, err := os.Stat(c.configPath); err != nil {
		return nil, nil, fmt.Errorf("config path not watchable: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, nil, fmt.Errorf("create watcher: %w", err)
	}

	dir := filepath.Dir(c.configPath)
	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return nil, nil, fmt.Errorf("watch %q: %w", dir, err)
	}

	ch := make(chan struct{}, 1)
	go func() {
		defer close(ch)
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Name != c.configPath {
					continue
				}
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
					select {
					case ch <- struct{}{}:
					default:
					}
				}
			case <-watcher.Errors:
				// Ignore individual errors; we still tick on the interval.
			}
		}
	}()

	cleanup := func() {
		_ = watcher.Close()
	}
	return ch, cleanup, nil
}

func (c *Controller) signalChannel() chan os.Signal {
	if c.testSignalCh != nil {
		return c.testSignalCh
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM)
	return sigCh
}

func (c *Controller) runLoop(ctx context.Context, sigCh chan os.Signal, watchCh <-chan struct{}) error {
	for {
		interval := c.currentInterval()
		if c.jitter > 0 {
			interval += time.Duration(rand.Int63n(int64(c.jitter)))
		}
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
			c.reloadConfigAndSync(ctx, "SIGHUP")

		case <-watchCh:
			timer.Stop()
			c.reloadConfigAndSync(ctx, "file change")

		case <-timer.C:
			if err := c.Sync(ctx); err != nil {
				c.log.Error("sync cycle completed with errors", map[string]string{"error": err.Error()})
			} else if cfg, err := c.loadConfig(ctx); err == nil {
				c.maybeCheckForUpdates(ctx, cfg)
			}
		}
	}
}

// maybeCheckForUpdates logs a warning if a newer release is available.
// It is a no-op if the config disables update checks or if the last check
// is within the configured interval.
func (c *Controller) maybeCheckForUpdates(ctx context.Context, cfg *config.Config) {
	if !cfg.CheckForUpdates || c.version == "" || c.version == "dev" || c.checker == nil {
		return
	}

	now := time.Now()
	if !c.lastUpdateCheck.IsZero() && now.Sub(c.lastUpdateCheck) < cfg.UpdateCheckInterval.Duration() {
		return
	}
	c.lastUpdateCheck = now

	latest, err := c.checker.LatestRelease(ctx)
	if err != nil {
		c.log.Debug("failed to check for updates", map[string]string{"error": err.Error()})
		return
	}

	if update.IsNewer(c.version, latest.Version) {
		c.log.Warn("a newer version of key-daemon is available",
			map[string]string{
				"current":      c.version,
				"latest":       latest.Version,
				"download_url": latest.URL,
			})
	} else {
		c.log.Debug("key-daemon is up to date",
			map[string]string{"current": c.version, "latest": latest.Version})
	}
}

// reloadConfigAndSync loads the latest config and runs a sync cycle.
func (c *Controller) reloadConfigAndSync(ctx context.Context, reason string) {
	c.log.Info("reloading config", map[string]string{"reason": reason})
	if _, err := c.loadConfig(ctx); err != nil {
		c.log.Error("failed to reload config", map[string]string{"error": err.Error()})
		return
	}
	if err := c.Sync(ctx); err != nil {
		c.log.Error("sync after reload completed with errors", map[string]string{"error": err.Error()})
	}
}

// Sync performs a single synchronization cycle against the current config.
func (c *Controller) Sync(ctx context.Context) error {
	cfg, err := c.loadConfig(ctx)
	if err != nil {
		return err
	}

	if c.manager == nil {
		c.manager = authkeys.NewManager(cfg.Markers, cfg.Backups)
	}

	if err := c.refreshExternalIP(ctx, cfg); err != nil {
		c.log.Warn("failed to determine external IP, public_ip targeting rules will fail closed",
			map[string]string{"error": err.Error()})
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
	totalKeys := 0
	for _, u := range users {
		n, err := c.syncUser(ctx, cfg, u)
		if err != nil {
			c.log.Error("failed to sync user", map[string]string{"user": u.Name, "error": err.Error()})
			errs = append(errs, fmt.Errorf("user %s: %w", u.Name, err))
		} else {
			totalKeys += n
		}
	}

	ok := len(errs) == 0
	c.recordMetrics(cfg, ok, len(users), totalKeys)
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
		if u.When.Active() {
			ok, err := u.When.Match(c.sysInfo)
			if err != nil {
				return nil, fmt.Errorf("target rule for user %q: %w", u.Name, err)
			}
			if !ok {
				c.log.Debug("skipping user because host does not match target rule", map[string]string{"user": u.Name})
				continue
			}
		}
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

func (c *Controller) refreshExternalIP(ctx context.Context, cfg *config.Config) error {
	if cfg.ExternalIPURL == "" {
		return nil
	}
	needsExternal := false
	for _, u := range cfg.Users {
		if u.When.PublicIP != "" {
			needsExternal = true
			break
		}
	}
	if !needsExternal {
		return nil
	}
	ip, err := c.externalIPFn(ctx, c.externalClient, cfg.ExternalIPURL)
	if err != nil {
		return err
	}
	c.sysInfo.ExternalIP = ip
	return nil
}

func (c *Controller) syncUser(ctx context.Context, cfg *config.Config, u config.User) (int, error) {
	info, err := c.resolver.Lookup(u.Name)
	if err != nil {
		return 0, fmt.Errorf("lookup: %w", err)
	}

	sources := cfg.EffectiveSources(u)
	if len(sources) == 0 {
		c.log.Warn("no sources configured for user", map[string]string{"user": u.Name})
		return 0, nil
	}

	raw, err := c.provider.FetchAll(ctx, sources)
	if err != nil {
		c.log.Warn("failed to fetch keys, retaining existing managed keys",
			map[string]string{"user": u.Name, "error": err.Error()})
		return 0, nil // fail open
	}

	parsed, err := keys.Parse(raw)
	if err != nil {
		c.log.Warn("fetched keys failed sanity checks, retaining existing managed keys",
			map[string]string{"user": u.Name, "error": err.Error()})
		return 0, nil // fail open
	}

	if len(parsed) == 0 {
		c.log.Warn("no valid keys found, retaining existing managed keys",
			map[string]string{"user": u.Name})
		return 0, nil
	}

	filtered := keys.FilterByType(parsed, cfg.AllowedKeyTypes)
	if len(cfg.AllowedKeyTypes) > 0 {
		c.log.Debug("filtered keys by type", map[string]string{
			"user":          u.Name,
			"before":        fmt.Sprintf("%d", len(parsed)),
			"after":         fmt.Sprintf("%d", len(filtered)),
			"allowed_types": strings.Join(cfg.AllowedKeyTypes, ","),
		})
	}
	if len(filtered) == 0 {
		c.log.Warn("no keys matched allowed_key_types, retaining existing managed keys",
			map[string]string{"user": u.Name})
		return 0, nil
	}

	unique := keys.Deduplicate(filtered)
	managed := keys.Format(unique)

	validate := c.validator
	if !c.isRootFn() {
		c.log.Debug("skipping sshd validation in single-user mode", map[string]string{"user": u.Name})
		validate = nil
	} else if !cfg.RunValidation {
		c.log.Warn("sshd validation disabled in config", map[string]string{"user": u.Name})
		validate = nil
	}

	if c.dryRun {
		candidate, wouldUpdate, err := c.manager.Preview(info, managed, validate)
		if err != nil {
			if errors.Is(err, sshd.ErrNoHostKeys) {
				c.log.Error("sshd validation cannot run because the system has no SSH host keys; run 'ssh-keygen -A' and restart key-daemon",
					map[string]string{"user": u.Name})
			}
			return 0, fmt.Errorf("preview authorized_keys: %w", err)
		}
		if wouldUpdate {
			c.log.Info("would update authorized_keys", map[string]string{
				"user":      u.Name,
				"keys":      fmt.Sprintf("%d", len(unique)),
				"candidate": candidate,
			})
		} else {
			c.log.Info("authorized_keys unchanged", map[string]string{"user": u.Name})
		}
		return len(unique), nil
	}

	updated, err := c.manager.Sync(info, managed, validate)
	if err != nil {
		if errors.Is(err, sshd.ErrNoHostKeys) {
			c.log.Error("sshd validation cannot run because the system has no SSH host keys; run 'ssh-keygen -A' and restart key-daemon",
				map[string]string{"user": u.Name})
		}
		return 0, fmt.Errorf("sync authorized_keys: %w", err)
	}

	if updated {
		c.log.Info("updated authorized_keys", map[string]string{
			"user": u.Name,
			"keys": fmt.Sprintf("%d", len(unique)),
		})
	} else {
		c.log.Debug("authorized_keys unchanged", map[string]string{"user": u.Name})
	}

	return len(unique), nil
}

// Restore replaces a user's authorized_keys with the most recent backup.
// If username is empty and the daemon is not running as root, it restores the
// current user.
func (c *Controller) Restore(ctx context.Context, username string) error {
	if username == "" {
		if c.isRootFn() {
			return errors.New("username is required when running as root")
		}
		current, err := c.currentUserFn()
		if err != nil {
			return fmt.Errorf("determine current user: %w", err)
		}
		username = current
		c.log.Info("restoring current user", map[string]string{"user": username})
	}

	info, err := c.resolver.Lookup(username)
	if err != nil {
		return fmt.Errorf("lookup user %q: %w", username, err)
	}

	if err := c.manager.RestoreLatestBackup(info); err != nil {
		return fmt.Errorf("restore authorized_keys for %q: %w", username, err)
	}
	return nil
}

// Validate checks the configuration file and reports whether it is usable. If a
// remote_config is configured, it also fetches and validates the latest remote
// payload before the local file is loaded.
func (c *Controller) Validate(ctx context.Context) error {
	cfg, err := c.loadConfig(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.logOut(), "config is valid (%d users, %d sources)\n", len(cfg.Users), len(cfg.DefaultSources))
	return nil
}

// RemoteConfigPull immediately fetches the remote config and writes it to the
// local config path, bypassing the normal interval throttle. If dryRun is true,
// the fetched config is validated but not written.
func (c *Controller) RemoteConfigPull(ctx context.Context, dryRun bool) error {
	cfg, err := config.Load(c.configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read local config: %w", err)
	}
	if err != nil && errors.Is(err, os.ErrNotExist) {
		cfg = config.Default()
	}
	if cfg.RemoteConfig.URL == "" {
		return errors.New("remote_config.url is not set")
	}

	data, err := c.fetchRemoteConfig(ctx, cfg.RemoteConfig)
	if err != nil {
		return fmt.Errorf("fetch remote config: %w", err)
	}
	if _, err := config.LoadBytes(data); err != nil {
		return fmt.Errorf("remote config failed validation: %w", err)
	}

	existing, err := os.ReadFile(c.configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read existing config: %w", err)
	}
	if string(existing) == string(data) {
		fmt.Fprintln(c.logOut(), "remote config unchanged")
		return nil
	}

	if dryRun {
		fmt.Fprintf(c.logOut(), "remote config differs from %s; would write %d bytes (dry-run)\n", cfg.RemoteConfig.URL, len(data))
		return nil
	}

	if err := os.WriteFile(c.configPath, data, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Fprintf(c.logOut(), "pulled remote config from %s\n", cfg.RemoteConfig.URL)
	return nil
}

// Status reads the persisted sync status file. If no explicit status file is
// configured, the controller loads the config to determine the default path.
func (c *Controller) Status() (*SyncStatus, error) {
	path := c.statusPath
	if path == "" {
		cfg, err := config.Load(c.configPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("load config: %w", err)
		}
		if err != nil {
			cfg = config.Default()
		}
		if cfg.StatusFile != "" {
			path = cfg.StatusFile
		} else {
			path = c.defaultStatusPath(c.isRootFn())
		}
	}
	if path == "" {
		return nil, errors.New("no status file is configured")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read status file: %w", err)
	}
	var status SyncStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("parse status file: %w", err)
	}
	return &status, nil
}

// logOut returns the destination used for command output. Tests can override.
func (c *Controller) logOut() *os.File {
	return os.Stdout
}

func (c *Controller) loadConfig(ctx context.Context) (*config.Config, error) {
	if err := c.maybeFetchRemoteConfig(ctx); err != nil {
		c.log.Warn("remote config fetch failed, using local config", map[string]string{"error": err.Error()})
	}

	cfg, err := config.Load(c.configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !c.isRootFn() {
			cfg = config.Default()
			cfg.StatusFile = c.defaultStatusPath(false)
			cfg.DiscoverUserConfigs = true
			c.interval = cfg.Interval.Duration()
			c.jitter = cfg.Jitter.Duration()
			c.statusPath = cfg.StatusFile
			c.log.Info("no global config found, using defaults with per-user discovery", map[string]string{
				"config_path": c.configPath,
			})
			return cfg, nil
		}
		return nil, fmt.Errorf("load config: %w", err)
	}
	c.interval = cfg.Interval.Duration()
	c.jitter = cfg.Jitter.Duration()
	if cfg.StatusFile == "" {
		cfg.StatusFile = c.defaultStatusPath(c.isRootFn())
	}
	c.statusPath = cfg.StatusFile
	return cfg, nil
}

// defaultStatusPath returns the conventional status file path.
func (c *Controller) defaultStatusPath(root bool) string {
	if root {
		return "/var/lib/key-daemon/status.json"
	}
	home, err := osuser.LookupId(fmt.Sprintf("%d", os.Getuid()))
	if err != nil {
		return ""
	}
	return filepath.Join(home.HomeDir, ".cache", "key-daemon", "status.json")
}

func (c *Controller) remoteConfigPath(cfg *config.Config) string {
	if cfg.RemoteConfig.URL == "" {
		return ""
	}
	return cfg.RemoteConfig.URL
}

// StatusFile returns the configured status file path, or the empty string if
// none is configured and no default could be determined.
func (c *Controller) StatusFile() string {
	if c.statusPath != "" {
		return c.statusPath
	}
	return c.defaultStatusPath(c.isRootFn())
}

// maybeFetchRemoteConfig pulls the latest configuration from a configured
// remote URL and writes it to disk if it has changed. Failures are returned
// so callers can fall back to the local config.
func (c *Controller) maybeFetchRemoteConfig(ctx context.Context) error {
	cfg, err := config.Load(c.configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read local config: %w", err)
	}
	if err != nil && errors.Is(err, os.ErrNotExist) {
		cfg = config.Default()
	}
	if cfg.RemoteConfig.URL == "" {
		return nil
	}
	if time.Since(c.remoteLastReq) < cfg.RemoteConfig.Interval.Duration() {
		return nil
	}

	data, err := c.fetchRemoteConfig(ctx, cfg.RemoteConfig)
	if err != nil {
		return err
	}
	c.remoteLastReq = time.Now()

	// Validate the remote payload before persisting it.
	if _, err := config.LoadBytes(data); err != nil {
		return fmt.Errorf("remote config failed validation: %w", err)
	}

	existing, err := os.ReadFile(c.configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read existing config: %w", err)
	}
	if string(existing) == string(data) {
		return nil
	}

	if err := os.WriteFile(c.configPath, data, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	c.log.Info("updated config from remote source", map[string]string{
		"url": cfg.RemoteConfig.URL,
	})
	return nil
}

func (c *Controller) fetchRemoteConfig(ctx context.Context, rc config.RemoteConfig) ([]byte, error) {
	data, err := c.fetchURL(ctx, rc.URL, rc.Token)
	if err != nil {
		return nil, err
	}

	if rc.PublicKey != "" {
		sigURL := rc.SignatureURL
		if sigURL == "" {
			sigURL = rc.URL + ".sig"
		}
		sigData, err := c.fetchURL(ctx, sigURL, rc.Token)
		if err != nil {
			return nil, fmt.Errorf("fetch remote config signature: %w", err)
		}

		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rc.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("parse remote_config public key: %w", err)
		}
		if err := signconfig.Verify(data, sigData, pubKey, signconfig.VerifyOptions{Namespace: signconfig.DefaultNamespace}); err != nil {
			return nil, fmt.Errorf("verify remote config signature: %w", err)
		}
	}

	return data, nil
}

func (c *Controller) fetchURL(ctx context.Context, url, token string) ([]byte, error) {
	if c.remoteClient == nil {
		c.remoteClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				ResponseHeaderTimeout: 10 * time.Second,
			},
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent(c.version))
	if token := os.ExpandEnv(token); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.remoteClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote URL %s returned status %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 5*1024*1024 {
		return nil, fmt.Errorf("response from %s exceeds 5 MiB", url)
	}
	return data, nil
}

func (c *Controller) currentInterval() time.Duration {
	if c.interval > 0 {
		return c.interval
	}
	return config.DefaultInterval
}
