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

func run(args []string) error {
	// Determine subcommand. Default is "run" for backward compatibility with
	// flag-only invocations like `key-daemon --config ...`.
	subcommand := "run"
	flagArgs := args[1:]
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		subcommand = args[1]
		flagArgs = args[2:]
	}

	var cfgPath, logLevel string
	fs := flag.NewFlagSet("key-daemon"+" "+subcommand, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	parseCommon(fs, &cfgPath, &logLevel)

	var dryRun bool
	var check bool

	switch subcommand {
	case "version":
		fs.BoolVar(&check, "check", false, "Check GitHub Releases for a newer version")
	case "sync":
		fs.BoolVar(&dryRun, "dry-run", false, "Show what would change without writing to disk")
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
		ctrl := controller.New(cfgPath, log)
		ctrl.SetVersion(version)
		ctrl.SetDryRun(dryRun)
		return ctrl.Sync(context.Background())

	case "restore":
		username := ""
		if len(fs.Args()) > 0 {
			username = fs.Args()[0]
		}
		ctrl := controller.New(cfgPath, log)
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
		ctrl := controller.New(cfgPath, log)
		ctrl.SetVersion(version)
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
		defer stop()
		return ctrl.Run(ctx)

	default:
		return fmt.Errorf("unknown subcommand %q (expected run, sync, restore, version, or self-update)", subcommand)
	}
}
