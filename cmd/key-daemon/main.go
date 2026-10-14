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
		fmt.Println(version)
		return nil

	case "sync":
		ctrl := controller.New(cfgPath, log)
		return ctrl.Sync(context.Background())

	case "run":
		ctrl := controller.New(cfgPath, log)
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
		defer stop()
		return ctrl.Run(ctx)

	default:
		return fmt.Errorf("unknown subcommand %q (expected run, sync, or version)", subcommand)
	}
}
