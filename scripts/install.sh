#!/usr/bin/env bash
set -euo pipefail

REPO="matthewgall/key-daemon"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/key-daemon"
SYSTEMD_DIR="/etc/systemd/system"
OPENRC_DIR="/etc/init.d"

log() { echo "[key-daemon] $*"; }
warn() { echo "[key-daemon] warning: $*" >&2; }
die() { echo "[key-daemon] error: $*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Install or upgrade key-daemon.

Options:
  -h, --help                Show this help message and exit
      --reset-keys          Back up and remove the target user's existing
                            authorized_keys before starting key-daemon
      --reset-keys-user=U   Target user for --reset-keys (default: root)

Environment variables:
  VERSION                   Release to install, e.g. v1.0.6 (default: latest)
  LOCAL_BINARY              Path to a local binary to install instead of
                            downloading a release
  RESET_KEYS                Set to 1 to enable --reset-keys behaviour
  RESET_KEYS_USER           User to reset when RESET_KEYS is set
                            (default: root)
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      --reset-keys)
        RESET_KEYS=1
        shift
        ;;
      --reset-keys-user)
        if [ -z "${2:-}" ]; then
          die "--reset-keys-user requires a value"
        fi
        RESET_KEYS_USER="$2"
        RESET_KEYS=1
        shift 2
        ;;
      --reset-keys-user=*)
        RESET_KEYS_USER="${1#*=}"
        RESET_KEYS=1
        shift
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done
}

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)
    BINARY="key-daemon-linux-amd64"
    ;;
  aarch64|arm64)
    BINARY="key-daemon-linux-arm64"
    ;;
  i?86|x86)
    BINARY="key-daemon-linux-386"
    ;;
  armv7l|armv6l|arm)
    BINARY="key-daemon-linux-arm"
    ;;
  ppc64le)
    BINARY="key-daemon-linux-ppc64le"
    ;;
  s390x)
    BINARY="key-daemon-linux-s390x"
    ;;
  riscv64)
    BINARY="key-daemon-linux-riscv64"
    ;;
  *)
    die "unsupported architecture: $ARCH"
    ;;
esac

VERSION="${VERSION:-latest}"
if [ "$VERSION" = "latest" ]; then
  DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${BINARY}"
  CHECKSUMS_URL="https://github.com/${REPO}/releases/latest/download/checksums.txt"
else
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}"
  CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
fi

# Allow local override for development.
LOCAL_BINARY="${LOCAL_BINARY:-}"

# Set RESET_KEYS=1 to back up and remove the target user's existing
# authorized_keys before starting key-daemon. The daemon will recreate the
# file with managed keys on its next sync. RESET_KEYS_USER defaults to root.
RESET_KEYS="${RESET_KEYS:-}"
RESET_KEYS_USER="${RESET_KEYS_USER:-root}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

maybe_reset_keys() {
  [ -n "${RESET_KEYS}" ] || return 0

  local target_user home ssh_dir auth_keys backup
  target_user="${RESET_KEYS_USER:-root}"
  home=$(getent passwd "$target_user" | cut -d: -f6) || true

  if [ -z "$home" ]; then
    warn "cannot reset keys for '$target_user': user not found"
    return 0
  fi

  ssh_dir="$home/.ssh"
  auth_keys="$ssh_dir/authorized_keys"

  if [ ! -f "$auth_keys" ]; then
    log "no existing authorized_keys for $target_user; nothing to reset"
    return 0
  fi

  backup="$auth_keys.install-backup.$(date +%Y%m%d%H%M%S)"
  cp "$auth_keys" "$backup"
  chmod 0600 "$backup"
  rm -f "$auth_keys"
  log "reset authorized_keys for $target_user (backed up to $backup)"
}

init_system() {
  if [ -d "/run/systemd/system" ] || command -v systemctl >/dev/null 2>&1; then
    echo "systemd"
  elif [ -f "/sbin/openrc-run" ] || command -v rc-service >/dev/null 2>&1; then
    echo "openrc"
  else
    echo "none"
  fi
}

main() {
  parse_args "$@"

  require_cmd curl
  require_cmd sha256sum

  if [ "$(id -u)" -ne 0 ]; then
    die "this script must be run as root"
  fi

  INIT=$(init_system)
  if [ "$INIT" = "none" ]; then
    warn "no supported init system detected (systemd or OpenRC); binary will be installed but no service will be started"
  fi

  log "stopping any running key-daemon service"
  case "$INIT" in
    systemd)
      systemctl stop key-daemon.service 2>/dev/null || true
      ;;
    openrc)
      rc-service key-daemon stop 2>/dev/null || true
      ;;
  esac

  log "installing key-daemon binary to ${INSTALL_DIR}"
  if [ -n "$LOCAL_BINARY" ]; then
    cp "$LOCAL_BINARY" "${INSTALL_DIR}/key-daemon"
  else
    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"; rm -f "${INSTALL_DIR}/key-daemon"' EXIT

    curl -fsSL --retry 3 --retry-delay 1 -o "${INSTALL_DIR}/key-daemon" "$DOWNLOAD_URL"
    curl -fsSL --retry 3 --retry-delay 1 -o "${TMP_DIR}/checksums.txt" "$CHECKSUMS_URL"

    log "verifying binary checksum"
    EXPECTED=$(awk -v b="$BINARY" '$2 == b {print $1}' "${TMP_DIR}/checksums.txt")
    if [ -z "$EXPECTED" ]; then
      die "checksum not found for ${BINARY}"
    fi
    COMPUTED=$(sha256sum "${INSTALL_DIR}/key-daemon" | awk '{print $1}')
    if [ "$COMPUTED" != "$EXPECTED" ]; then
      die "checksum verification failed for ${BINARY}"
    fi

    rm -rf "$TMP_DIR"
    trap - EXIT
  fi
  chmod 0755 "${INSTALL_DIR}/key-daemon"

  log "creating config directory ${CONFIG_DIR}"
  mkdir -p "$CONFIG_DIR"
  chmod 0755 "$CONFIG_DIR"

  maybe_reset_keys

  if [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
    log "writing default config"

    # Dropbear systems do not ship an OpenSSH sshd binary, so sshd -t
    # validation cannot run. Detect that and disable validation.
    VALIDATE_LINE="validate: true"
    if ! command -v sshd >/dev/null 2>&1 && [ ! -x "/usr/sbin/sshd" ] && [ ! -x "/usr/local/sbin/sshd" ] && [ ! -x "/sbin/sshd" ]; then
      warn "OpenSSH sshd not found; disabling sshd -t validation in default config"
      VALIDATE_LINE="validate: false"
    fi

    cat > "${CONFIG_DIR}/config.yaml" <<EOF
interval: 5m
${VALIDATE_LINE}
users:
  - name: root
    sources: []
    # Add your own sources below, for example:
    #   - url:https://example.com/keys
    #   - github:yourusername
    #   - gitlab:yourusername
    #   - codeberg:yourusername
    #   - sourcehut:yourusername
    #   - launchpad:yourusername
    #   - sshid:yourusername
EOF
    chmod 0644 "${CONFIG_DIR}/config.yaml"
  else
    log "config already exists, not overwriting"
  fi

  case "$INIT" in
    systemd)
      log "installing systemd unit"
      if [ -f "key-daemon.service" ]; then
        cp "key-daemon.service" "${SYSTEMD_DIR}/key-daemon.service"
      else
        curl -fsSL --retry 3 --retry-delay 1 \
          -o "${SYSTEMD_DIR}/key-daemon.service" \
          "https://raw.githubusercontent.com/${REPO}/main/key-daemon.service"
      fi
      chmod 0644 "${SYSTEMD_DIR}/key-daemon.service"

      log "reloading systemd and starting service"
      systemctl daemon-reload
      systemctl enable key-daemon.service
      systemctl restart key-daemon.service
      ;;

    openrc)
      log "installing OpenRC init script"
      if [ -f "key-daemon.openrc" ]; then
        cp "key-daemon.openrc" "${OPENRC_DIR}/key-daemon"
      else
        curl -fsSL --retry 3 --retry-delay 1 \
          -o "${OPENRC_DIR}/key-daemon" \
          "https://raw.githubusercontent.com/${REPO}/main/key-daemon.openrc"
      fi
      chmod 0755 "${OPENRC_DIR}/key-daemon"

      log "starting service"
      rc-update add key-daemon default
      rc-service key-daemon restart
      ;;

    *)
      log "binary installed; please start key-daemon manually"
      ;;
  esac

  log "key-daemon installed"
}

main "$@"
