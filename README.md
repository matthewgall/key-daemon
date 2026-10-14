# key-daemon

A small, statically-linked daemon that keeps your servers' `authorized_keys` files in sync with remote SSH key sources. It replaces the need to re-run an installer script every time keys change.

## Features

- **Static Go binary** — no runtime dependencies.
- **Config-driven** — define users, sources, and sync intervals in YAML.
- **Multiple source types** — raw HTTPS URLs, GitHub usernames (`github:yourusername`), and sshid.io handles (`sshid:yourusername`).
- **Safe updates** — only rewrites a marked section inside `~/.ssh/authorized_keys`, leaving manually added keys untouched.
- **Pre-commit validation** — every candidate file is checked with `sshd -t` before it goes live.
- **Automated backups** — previous `authorized_keys` files are backed up and pruned by count and age.
- **Fail-open** — if a source is unreachable or returns bad data, existing managed keys are kept and the daemon retries later.
- **Signal-friendly** — reload config and sync immediately on `SIGHUP`; shut down cleanly on `SIGTERM`.

## Installation

The fastest way is the curl-pipeable install script:

```bash
curl -fsSL https://raw.githubusercontent.com/matthewgall/key-daemon/main/scripts/install.sh | sudo bash
```

Or install from a local release binary:

```bash
make static
sudo LOCAL_BINARY=./key-daemon-linux-amd64 ./scripts/install.sh
```

Pre-built binaries are provided for linux/amd64, linux/arm64, linux/386,
linux/arm, linux/ppc64le, linux/s390x, and linux/riscv64.

### Removing existing keys during install

If you are replacing an old key installer and want key-daemon to start with a
fresh `authorized_keys` file, use `--reset-keys`:

```bash
curl -fsSL https://raw.githubusercontent.com/matthewgall/key-daemon/main/scripts/install.sh | sudo bash -s -- --reset-keys
```

Or with an environment variable:

```bash
RESET_KEYS=1 curl -fsSL https://raw.githubusercontent.com/matthewgall/key-daemon/main/scripts/install.sh | sudo bash
```

The current file is copied to `~/.ssh/authorized_keys.install-backup.<timestamp>`
before being removed; key-daemon recreates it on the next sync. To reset a
user other than root, pass `--reset-keys-user`:

```bash
curl -fsSL https://raw.githubusercontent.com/matthewgall/key-daemon/main/scripts/install.sh | sudo bash -s -- --reset-keys --reset-keys-user=alice
```

This installs:

- `/usr/local/bin/key-daemon`
- `/etc/key-daemon/config.yaml` (only if it does not already exist)
- A service for your init system:
  - systemd: `/etc/systemd/system/key-daemon.service`
  - OpenRC (Alpine): `/etc/init.d/key-daemon`

The install script auto-detects systemd vs OpenRC. Then start the daemon:

```bash
# systemd
sudo systemctl enable --now key-daemon

# OpenRC
sudo rc-service key-daemon start
sudo rc-update add key-daemon default
```

## Configuration

### Global config

Edit `/etc/key-daemon/config.yaml`:

```yaml
interval: 5m
markers:
  begin: "# BEGIN key-daemon"
  end: "# END key-daemon"
backups:
  max_count: 10
  max_age: 7d

# Sources applied to any user that does not define its own.
default_sources:
  - url:https://example.com/keys

# When true, root scans /etc/passwd and honors per-user config files.
discover_user_configs: false

# Per-user configs may only use these source types.
allowed_user_sources:
  - github
  - sshid

users:
  - name: root
    sources:
      - url:https://example.com/keys
      - github:yourusername
      - sshid:yourusername

  - name: alice
    sources:
      - github:alice
```

### Per-user config

Users can place their own config in `~/.config/key-daemon/config.yaml`. Root still runs the daemon and performs all fetches, but the user controls their own sources. Per-user sources are **added to** the global sources for that user; they do not replace them.

```yaml
sources:
  - github:yourusername
  - sshid:yourusername
```

A per-user config file must:

- Be owned by the user or root.
- Not be writable by group or other.
- Only contain sources whose types are in the global `allowed_user_sources` list.

Users whose shell is `/bin/false`, `/usr/sbin/nologin`, or `/usr/bin/nologin` are skipped.

## Running without root

`key-daemon` can be run by an individual user without root privileges. In this **single-user mode** it only manages the user running it, and skipped users are logged with the reason.

If no global config exists, a non-root invocation automatically uses sensible defaults with per-user discovery enabled, so you can run:

```bash
key-daemon sync
```

from your own account and it will update your own `~/.ssh/authorized_keys` from `~/.config/key-daemon/config.yaml`.

To manage multiple users, run `key-daemon` as root or via a systemd service:

```bash
sudo key-daemon sync -config /etc/key-daemon/config.yaml
```

When running as root, files are written as root and immediately `chown`ed to the target user. `key-daemon` does not permanently drop privileges, but it only holds root privileges as necessary and applies the target ownership to every produced file.

After editing the config, either reload the daemon or run a one-shot sync:

```bash
sudo systemctl kill -s HUP key-daemon
# or
sudo key-daemon sync -config /etc/key-daemon/config.yaml
```

## Usage

### Daemon mode

```bash
key-daemon run -config /etc/key-daemon/config.yaml -log-level info
```

### One-shot mode

```bash
key-daemon sync -config /etc/key-daemon/config.yaml
```

### Logging

Log levels are `debug`, `info`, `warn`, `error`. The daemon logs structured lines to stderr, which are captured by systemd/journald when run as a service.

### Update checks

To be notified when a new release is available, enable GitHub Releases checks
in the config:

```yaml
check_for_updates: true
update_check_interval: 24h
```

When enabled, the daemon logs a warning with the latest version and download
URL. To check manually from the command line:

```bash
key-daemon version --check
```

## Building

Requirements: Go 1.23+

```bash
make test          # run all tests
make build         # build ./key-daemon for the current platform
make static        # build static binaries for all supported architectures
make clean         # remove built artifacts
```

## How it works

1. The daemon reads `/etc/key-daemon/config.yaml`.
2. On every interval it resolves each configured user, fetches every source, validates and deduplicates the keys.
3. It writes a candidate `authorized_keys` file preserving everything outside the configured markers.
4. The candidate is validated with `sshd -t`.
5. If validation passes, the existing `authorized_keys` is backed up and the candidate is atomically promoted.
6. Old backups are pruned according to `backups.max_count` and `backups.max_age`.

## SSH server compatibility

`sshd -t` validation is used by default to verify the candidate
`authorized_keys` file before promoting it. If your system uses a different
SSH server such as **dropbear**, set `validate: false` in the config:

```yaml
validate: false
```

The install script automatically detects missing `sshd` and writes a default
config with validation disabled.

## License

MIT
