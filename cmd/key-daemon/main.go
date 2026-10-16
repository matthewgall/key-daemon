package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/matthewgall/key-daemon/internal/config"
	"github.com/matthewgall/key-daemon/internal/controller"
	"github.com/matthewgall/key-daemon/internal/logger"
	"github.com/matthewgall/key-daemon/internal/selfupdate"
	"github.com/matthewgall/key-daemon/internal/update"
)

var version = "dev"

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// parseCommon registers the flags shared by every subcommand.
func parseCommon(fs *flag.FlagSet, cfgPath, logLevel *string) {
	fs.StringVar(cfgPath, "config", config.DefaultConfigPath, "Path to configuration file")
	fs.StringVar(logLevel, "log-level", "info", "Log level: debug, info, warn, error")
}

// wantsHelp reports whether any argument asks for usage information.
func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "-help" || a == "help" {
			return true
		}
	}
	return false
}

func run(args []string) error {
	// Determine subcommand. Default is "run" for backward compatibility with
	// flag-only invocations like `key-daemon --config ...`.
	subcommand := "run"
	flagArgs := args[1:]
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") && !strings.HasPrefix(args[1], "--") {
		subcommand = args[1]
		flagArgs = args[2:]
	}

	if subcommand == "help" || wantsHelp(flagArgs) {
		if subcommand == "help" {
			printTopLevelHelp()
		} else {
			printSubcommandHelp(subcommand)
		}
		return nil
	}

	var cfgPath, logLevel string
	fs := flag.NewFlagSet("key-daemon "+subcommand, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	parseCommon(fs, &cfgPath, &logLevel)

	var dryRun bool
	var check bool

	switch subcommand {
	case "version":
		fs.BoolVar(&check, "check", false, "Check GitHub Releases for a newer version")
		fs.Usage = func() { printSubcommandHelp("version") }
	case "sync":
		fs.BoolVar(&dryRun, "dry-run", false, "Show what would change without writing to disk")
		fs.Usage = func() { printSubcommandHelp("sync") }
	case "restore":
		fs.Usage = func() { printSubcommandHelp("restore") }
	case "self-update":
		fs.Usage = func() { printSubcommandHelp("self-update") }
	case "run":
		fs.Usage = func() { printSubcommandHelp("run") }
	}

	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	level, err := logger.ParseLevel(logLevel)
	if err != nil {
		return err
	}
	log := logger.New(level)

	switch subcommand {
	case "version":
		if !check {
			fmt.Println(version)
			return nil
		}
		info, err := update.NewChecker().LatestRelease(context.Background())
		if err != nil {
			return fmt.Errorf("check for updates: %w", err)
		}
		if update.IsNewer(version, info.Version) {
			fmt.Printf("Current version: %s\nLatest version:  %s\nDownload:        %s\n", version, info.Version, info.URL)
		} else {
			fmt.Printf("key-daemon %s is up to date\n", version)
		}
		return nil

	case "sync":
		ctrl := controller.New(cfgPath, log, version)
		ctrl.SetDryRun(dryRun)
		return ctrl.Sync(context.Background())

	case "restore":
		username := ""
		if len(fs.Args()) > 0 {
			username = fs.Args()[0]
		}
		ctrl := controller.New(cfgPath, log, version)
		if err := ctrl.Restore(context.Background(), username); err != nil {
			return err
		}
		fmt.Printf("Restored authorized_keys for %s\n", username)
		return nil

	case "self-update":
		updater, err := selfupdate.New()
		if err != nil {
			return fmt.Errorf("initialise self-update: %w", err)
		}
		updater.SetUserAgent(fmt.Sprintf("key-daemon/%s (self-update)", version))
		newVersion, err := updater.Run(context.Background(), version)
		if err != nil {
			return err
		}
		fmt.Printf("Updated to %s at %s\n", newVersion, updater.InstallPath())
		fmt.Println("Restarting key-daemon service...")
		if err := selfupdate.RestartService(); err != nil {
			return fmt.Errorf("restart service: %w", err)
		}
		return nil

	case "run":
		ctrl := controller.New(cfgPath, log, version)
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
		defer stop()
		return ctrl.Run(ctx)

	default:
		return fmt.Errorf("unknown subcommand %q (expected run, sync, restore, version, or self-update)", subcommand)
	}
}

// printSubcommandHelp writes detailed help for a command to stdout.
func printSubcommandHelp(cmd string) {
	if cmd == "" || cmd == "run" {
		printTopLevelHelp()
		return
	}

	switch cmd {
	case "run":
		fmt.Println(`Usage: key-daemon run [flags]

Run the daemon that continuously synchronizes authorized_keys from the
configured sources. The daemon reloads its configuration when the config file
changes or when SIGHUP is received.

Flags:`)
		fmt.Println(`  -config string
        Path to configuration file (default "/etc/key-daemon/config.yaml")`)
		fmt.Println(`  -log-level string
        Log level: debug, info, warn, error (default "info")`)

	case "sync":
		fmt.Println(`Usage: key-daemon sync [flags]

Run a one-shot synchronization and exit. By default the configured
authorized_keys files are updated. Use -dry-run to preview what would change
without writing to disk.

Flags:`)
		fmt.Println(`  -config string
        Path to configuration file (default "/etc/key-daemon/config.yaml")`)
		fmt.Println(`  -dry-run
        Show what would change without writing to disk`)
		fmt.Println(`  -log-level string
        Log level: debug, info, warn, error (default "info")`)
		fmt.Println(`
Examples:
  key-daemon sync
  key-daemon sync -config /etc/key-daemon/config.yaml -dry-run`)

	case "restore":
		fmt.Println(`Usage: key-daemon restore [flags] [username]

Replace a user's authorized_keys with the most recent backup. When running as
root a username must be supplied. When running as a non-root user, the current
user is restored if no username is given.

Flags:`)
		fmt.Println(`  -config string
        Path to configuration file (default "/etc/key-daemon/config.yaml")`)
		fmt.Println(`  -log-level string
        Log level: debug, info, warn, error (default "info")`)
		fmt.Println(`
Examples:
  sudo key-daemon restore alice
  sudo key-daemon restore -log-level debug root
  key-daemon restore   # restores the current user when not root`)

	case "version":
		fmt.Println(`Usage: key-daemon version [flags]

Print the running version. With -check, query GitHub Releases for a newer
version and report whether an update is available.

Flags:`)
		fmt.Println(`  -check
        Check GitHub Releases for a newer version`)
		fmt.Println(`  -log-level string
        Log level: debug, info, warn, error (default "info")`)

	case "self-update":
		fmt.Println(`Usage: key-daemon self-update [flags]

Explicitly opt-in command that downloads the latest release from GitHub,
verifies its SHA-256 checksum, atomically replaces /usr/local/bin/key-daemon,
and restarts the init service. The daemon never updates itself automatically.

Flags:`)
		fmt.Println(`  -log-level string
        Log level: debug, info, warn, error (default "info")`)

	default:
		printTopLevelHelp()
	}
}

// printTopLevelHelp writes the root usage message to stdout.
func printTopLevelHelp() {
	fmt.Println(`key-daemon - Synchronize SSH authorized_keys from remote sources.

Usage:
  key-daemon [global flags] <command> [command flags] [args]

Global flags:
  -config string
        Path to configuration file (default "/etc/key-daemon/config.yaml")
  -log-level string
        Log level: debug, info, warn, error (default "info")

Commands:
  run           Run the continuous synchronization daemon
  sync          Run a one-shot synchronization
  restore       Restore authorized_keys from the most recent backup
  version       Print version information
  self-update   Explicitly update the binary to the latest release

Use "key-daemon <command> --help" for more information about a command.

Examples:
  Run the daemon:
    key-daemon run

  Preview a sync without writing:
    key-daemon sync -dry-run

  Restore a user's authorized_keys:
    sudo key-daemon restore alice

  Check for a newer release:
    key-daemon version -check`)
}
