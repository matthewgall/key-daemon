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

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)
    BINARY="key-daemon-linux-amd64"
    ;;
  aarch64|arm64)
    BINARY="key-daemon-linux-arm64"
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

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
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

  if [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
    log "writing default config"
    cat > "${CONFIG_DIR}/config.yaml" <<'EOF'
interval: 5m
users:
  - name: root
    sources:
      - url:https://download.matthewgall.dev/ssh/keys
      - github:matthewgall
      - sshid:matthewgall
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
