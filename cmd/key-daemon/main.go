package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/matthewgall/key-daemon/internal/config"
	"github.com/matthewgall/key-daemon/internal/controller"
	"github.com/matthewgall/key-daemon/internal/logger"
	"github.com/matthewgall/key-daemon/internal/selfupdate"
	"github.com/matthewgall/key-daemon/internal/signconfig"
	"github.com/matthewgall/key-daemon/internal/update"

	"golang.org/x/crypto/ssh"
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
	// First, scan arguments to find the subcommand while tolerating global
	// flags before or after the command name (e.g. "key-daemon -config x
	// status" and "key-daemon status -config x" both work).
	subcommand := "run"
	var leadingFlags []string
	flagArgs := args[1:]
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
			leadingFlags = append(leadingFlags, arg)
			// If the flag takes a value, consume the next argument as well.
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				leadingFlags = append(leadingFlags, args[i+1])
				i++
			}
			continue
		}
		subcommand = arg
		flagArgs = args[i+1:]
		break
	}

	if subcommand == "help" || wantsHelp(append(leadingFlags, flagArgs...)) {
		if subcommand == "help" {
			printTopLevelHelp()
		} else {
			printSubcommandHelp(subcommand)
		}
		return nil
	}

	var cfgPath, logLevel string

	// Apply any leading global flags so defaults are set before the command
	// flag set is created. We keep these values to seed the command flag set,
	// which would otherwise reset them to defaults when it registers the same
	// flags.
	preCfgPath := config.DefaultConfigPath
	preLogLevel := "info"
	if len(leadingFlags) > 0 {
		pre := flag.NewFlagSet("key-daemon", flag.ContinueOnError)
		pre.SetOutput(os.Stderr)
		parseCommon(pre, &preCfgPath, &preLogLevel)
		_ = pre.Parse(leadingFlags)
	}
	cfgPath = preCfgPath
	logLevel = preLogLevel

	fs := flag.NewFlagSet("key-daemon "+subcommand, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	parseCommon(fs, &cfgPath, &logLevel)
	// Re-apply leading flag values; command-specific flags will override them
	// during fs.Parse if provided there as well.
	cfgPath = preCfgPath
	logLevel = preLogLevel

	var dryRun bool
	var check bool
	var validate, pull bool
	var configDryRun bool
	var (
		signKeyPath   string
		signNamespace string
		signHashAlg   string
	)

	switch subcommand {
	case "version":
		fs.BoolVar(&check, "check", false, "Check GitHub Releases for a newer version")
		fs.Usage = func() { printSubcommandHelp("version") }
	case "sync":
		fs.BoolVar(&dryRun, "dry-run", false, "Show what would change without writing to disk")
		fs.Usage = func() { printSubcommandHelp("sync") }
	case "restore":
		fs.Usage = func() { printSubcommandHelp("restore") }
	case "config":
		fs.BoolVar(&validate, "validate", false, "Validate the configuration file")
		fs.BoolVar(&pull, "pull", false, "Force a remote config fetch")
		fs.BoolVar(&configDryRun, "dry-run", false, "Preview remote config changes without writing")
		fs.Usage = func() { printSubcommandHelp("config") }
	case "sign":
		fs.StringVar(&signKeyPath, "key", os.Getenv("KEY_DAEMON_SIGN_KEY"), "Path to the SSH private key used to sign")
		fs.StringVar(&signNamespace, "namespace", signconfig.DefaultNamespace, "SSHSIG namespace")
		fs.StringVar(&signHashAlg, "hash", signconfig.DefaultHash, "Hash algorithm used for the signed digest")
		fs.Usage = func() { printSubcommandHelp("sign") }
	case "status":
		fs.Usage = func() { printSubcommandHelp("status") }
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
	case "sign":
		if signKeyPath == "" {
			return errors.New("-key is required (or set KEY_DAEMON_SIGN_KEY)")
		}
		args := fs.Args()
		if len(args) != 2 {
			return errors.New("usage: key-daemon sign [flags] <input.yaml> <output.sig>")
		}
		if err := signConfig(signKeyPath, args[0], args[1], signNamespace, signHashAlg); err != nil {
			return err
		}
		fmt.Printf("Signed %s -> %s\n", args[0], args[1])
		return nil

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

	case "config":
		if !validate && !pull {
			printSubcommandHelp("config")
			return nil
		}
		ctrl := controller.New(cfgPath, log, version)
		if pull {
			if err := ctrl.RemoteConfigPull(context.Background(), configDryRun); err != nil {
				return err
			}
		}
		if validate {
			if err := ctrl.Validate(context.Background()); err != nil {
				return err
			}
		}
		return nil

	case "status":
		ctrl := controller.New(cfgPath, log, version)
		status, err := ctrl.Status()
		if err != nil {
			return err
		}
		fmt.Printf("config:        %s\n", status.ConfigPath)
		if status.RemoteURL != "" {
			fmt.Printf("remote config: %s\n", status.RemoteURL)
		}
		fmt.Printf("last sync:     %s\n", status.LastSync.Format(time.RFC3339))
		if status.LastSyncOK {
			fmt.Println("last result:   success")
		} else {
			fmt.Println("last result:   failure")
		}
		fmt.Printf("users:         %d\n", status.Users)
		fmt.Printf("keys:          %d\n", status.Keys)
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
		return fmt.Errorf("unknown subcommand %q (expected run, sync, restore, config, sign, status, version, or self-update)", subcommand)
	}
}

func signConfig(keyPath, inputPath, outputPath, namespace, hashAlg string) error {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}

	var signer ssh.Signer
	signer, err = ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		var passphraseErr *ssh.PassphraseMissingError
		if errors.As(err, &passphraseErr) {
			passphrase := os.Getenv("KEY_DAEMON_SIGN_PASSPHRASE")
			if passphrase == "" {
				return fmt.Errorf("private key is encrypted; set KEY_DAEMON_SIGN_PASSPHRASE")
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
			if err != nil {
				return fmt.Errorf("decrypt private key: %w", err)
			}
		} else {
			return fmt.Errorf("parse private key: %w", err)
		}
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read input file: %w", err)
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer out.Close()

	return signconfig.SignTo(signer, data, signconfig.SignerOptions{
		Namespace: namespace,
		HashAlg:   hashAlg,
	}, out)
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

	case "config":
		fmt.Println(`Usage: key-daemon config [flags]

Inspect and manage the key-daemon configuration file.

Flags:
  -config string
        Path to configuration file (default "/etc/key-daemon/config.yaml")
  -dry-run
        Preview a remote config pull without overwriting the local file
  -log-level string
        Log level: debug, info, warn, error (default "info")
  -pull
        Force an immediate remote config fetch and overwrite the local file
  -validate
        Load and validate the configuration file

Examples:
  key-daemon config --validate
  key-daemon config --pull --validate
  key-daemon config --pull --dry-run
  key-daemon config -config /tmp/config.yaml --validate`)

	case "status":
		fmt.Println(`Usage: key-daemon status [flags]

Print the most recent sync status persisted by the daemon. The status file is
updated after every sync cycle and is readable without running a sync.

Flags:
  -config string
        Path to configuration file (default "/etc/key-daemon/config.yaml")
  -log-level string
        Log level: debug, info, warn, error (default "info")`)

	case "sign":
		fmt.Println(`Usage: key-daemon sign [flags] <input.yaml> <output.sig>

Sign a remote configuration file using the OpenSSH SSHSIG detached signature
format. The resulting signature can be verified by nodes with remote_config.

Flags:
  -hash string
        Hash algorithm used for the signed digest (default "sha512")
  -key string
        Path to the SSH private key (or KEY_DAEMON_SIGN_KEY environment var)
  -namespace string
        SSHSIG namespace (default "key-daemon")

Environment:
  KEY_DAEMON_SIGN_KEY
        Default private key path
  KEY_DAEMON_SIGN_PASSPHRASE
        Passphrase for encrypted private keys

Examples:
  key-daemon sign -key ~/.ssh/id_ed25519 config.yaml config.yaml.sig
  KEY_DAEMON_SIGN_KEY=~/.ssh/id_ed25519 key-daemon sign config.yaml config.yaml.sig`)

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
  config        Validate or pull the configuration file
  sign          Sign a remote configuration file
  status        Show the most recent sync status
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

  Validate the config:
    key-daemon config --validate

  Force a remote config pull:
    key-daemon config --pull

  Show the latest sync status:
    key-daemon status

  Check for a newer release:
    key-daemon version -check`)
}
