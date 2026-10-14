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
	fs := flag.NewFlagSet("key-daemon", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&cfgPath, "config", config.DefaultConfigPath, "Path to configuration file")
	fs.StringVar(&logLevel, "log-level", "info", "Log level: debug, info, warn, error")

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
		var check bool
		fs.BoolVar(&check, "check", false, "Check GitHub Releases for a newer version")
		if err := fs.Parse(flagArgs); err != nil {
			return err
		}
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
		return ctrl.Sync(context.Background())

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
		return fmt.Errorf("unknown subcommand %q (expected run, sync, version, or self-update)", subcommand)
	}
}
