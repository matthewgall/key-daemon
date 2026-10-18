# key-daemon

A small, statically-linked daemon that keeps your servers' `authorized_keys` files in sync with remote SSH key sources. It replaces the need to re-run an installer script every time keys change.

## Features

- **Static Go binary** — no runtime dependencies.
- **Config-driven** — define users, sources, and sync intervals in YAML.
- **Multiple source types** — raw HTTPS URLs, and shorthand handles for GitHub (`github:`), GitLab (`gitlab:`), Codeberg (`codeberg:`), SourceHut (`sourcehut:`), Launchpad (`launchpad:`), and sshid.io (`sshid:`).
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

# Random jitter added to each interval. Spreads out syncs on a fleet of nodes
# that boot or restart at the same time. Must be less than interval.
jitter: 30s

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
  - gitlab
  - codeberg
  - sourcehut
  - launchpad
  - sshid

users:
  - name: root
    sources:
      - url:https://example.com/keys
      - github:yourusername
      - gitlab:yourusername
      - codeberg:yourusername
      - sourcehut:yourusername
      - launchpad:yourusername
      - sshid:yourusername

  - name: alice
    sources:
      - github:alice
      - gitlab:alice
      - codeberg:alice
```

### Per-user config

Users can place their own config in `~/.config/key-daemon/config.yaml`. Root still runs the daemon and performs all fetches, but the user controls their own sources. Per-user sources are **added to** the global sources for that user; they do not replace them.

```yaml
sources:
  - github:yourusername
  - gitlab:yourusername
  - codeberg:yourusername
  - sourcehut:yourusername
  - launchpad:yourusername
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

### Restricting key algorithms

Only accept specific key types:

```yaml
allowed_key_types:
  - ssh-ed25519
  - sk-ssh-ed25519@openssh.com
```

Supported values: `ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp256`,
`ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`,
`sk-ssh-ed25519@openssh.com`, and `sk-ecdsa-sha2-nistp256@openssh.com`.

When running as root, files are written as root and immediately `chown`ed to the target user. `key-daemon` does not permanently drop privileges, but it only holds root privileges as necessary and applies the target ownership to every produced file.

After editing the config, key-daemon automatically reloads it when the file
changes, or you can reload it manually:

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

Preview changes without writing:

```bash
key-daemon sync -config /etc/key-daemon/config.yaml -dry-run
```

### Restore from backup

Restore the most recent backup for a specific user:

```bash
sudo key-daemon restore alice
```

When not running as root, the current user is restored if no username is
supplied.

### Logging

Log levels are `debug`, `info`, `warn`, `error`. The daemon logs structured lines to stderr, which are captured by systemd/journald when run as a service.

### Metrics

key-daemon can expose a small Prometheus-style metrics endpoint. It is
disabled by default and binds to localhost only:

```yaml
metrics:
  enabled: true
  address: 127.0.0.1:9123
  path: /metrics
```

Available metrics:

- `key_daemon_sync_count_total`
- `key_daemon_last_sync_timestamp_seconds`
- `key_daemon_last_sync_success`
- `key_daemon_users`
- `key_daemon_keys`

### Status file

After each sync cycle the daemon writes a small JSON status file:

```yaml
status_file: /var/lib/key-daemon/status.json
```

Default paths:

- **root:** `/var/lib/key-daemon/status.json`
- **non-root:** `~/.cache/key-daemon/status.json`

Query it with:

```bash
key-daemon status
```

### Remote configuration

If you run many nodes, you can point them at a central HTTPS endpoint that
serves the same `config.yaml`. Each node fetches it on its configured interval,
validates it, and overwrites its local file before reloading.

```yaml
remote_config:
  url: https://key-daemon.example.com/config.yaml
  token: "your-secret-token"    # optional, sent as Bearer token
  interval: 5m
```

The remote URL must use HTTPS and the downloaded config is validated before it
replaces the local file. If the remote endpoint is unreachable or returns an
invalid config, the node keeps running from the last known local config.

#### Signed remote configs

You can sign the central config with an SSH key so nodes can verify it before
installing it. Use `key-daemon sign` (or `ssh-keygen -Y sign`) to produce a
detached signature:

```bash
key-daemon sign -key ~/.ssh/id_ed25519 config.yaml config.yaml.sig
```

Then host the signature next to the config and configure each node with the
matching public key:

```yaml
remote_config:
  url: https://key-daemon.example.com/config.yaml
  signature_url: https://key-daemon.example.com/config.yaml.sig
  public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIhz2GKHuG2bJ55x2wv5F_qDFLZxFKL3ZGe1kqx93Gf"
  interval: 5m
```

`signature_url` defaults to `<url>.sig` when omitted. If the signature is
missing, invalid, or signed by a different key, the daemon refuses the update
and keeps the existing local config.

### Operations commands

Validate the configuration before pushing it to your fleet:

```bash
key-daemon config --validate
key-daemon config --validate -config /tmp/config.yaml
```

Force a remote config pull immediately:

```bash
key-daemon config --pull
key-daemon config --pull --validate
```

Show the latest sync status:

```bash
key-daemon status
```

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

### Self-update

From a root shell you can replace the running binary with the latest release
and restart the service in one step:

```bash
sudo key-daemon self-update
```

This downloads the correct architecture binary, verifies its SHA-256 checksum,
replaces `/usr/local/bin/key-daemon`, and runs `systemctl restart` or
`rc-service restart` as appropriate.

> Self-update is **never automatic**. It must be invoked explicitly.

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
