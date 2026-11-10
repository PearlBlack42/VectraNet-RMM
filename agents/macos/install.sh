#!/usr/bin/env bash
# ============================================================================
# VectraNet RMM macOS Silent Agent Installer & LaunchDaemon Provisioner
# File: agents/macos/install.sh
# Supports: Apple Silicon (M1/M2/M3/M4 darwin-arm64) & Intel Mac (darwin-amd64)
# Usage:
#   curl -fsSL https://rmm.internal.corp:8443/agents/macos/install.sh | sudo bash -s -- \
#     --server "https://rmm.internal.corp:8443" \
#     --token "vn_live_macos_98a7bc65"
# ============================================================================
set -euo pipefail

SERVER_URL="${VECTRANET_SERVER_URL:-https://rmm.internal.corp:8443}"
AGENT_TOKEN="${VECTRANET_AGENT_TOKEN:-vn_default_bootstrap_token}"
EXPECTED_SHA256=""
INSTALL_DIR="/Library/Application Support/VectraNet"
BINARY_PATH="${INSTALL_DIR}/vectranet-agent"
LOG_DIR="/Library/Logs/VectraNet"
PLIST_LABEL="com.vectranet.agent"
PLIST_PATH="/Library/LaunchDaemons/${PLIST_LABEL}.plist"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      SERVER_URL="$2"
      shift 2
      ;;
    --token)
      AGENT_TOKEN="$2"
      shift 2
      ;;
    --sha256)
      EXPECTED_SHA256="$2"
      shift 2
      ;;
    *)
      echo "[ERROR] Argumen tidak dikenal: $1" >&2
      exit 1
      ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[ERROR] Skrip instalasi macOS harus dijalankan sebagai root (sudo)." >&2
  exit 1
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "[ERROR] Skrip ini khusus untuk sistem operasi macOS (Darwin)." >&2
  exit 1
fi

# 1. Deteksi Arsitektur Apple Silicon (arm64) vs Intel (amd64)
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  arm64)
    TARGET_ARCH="darwin-arm64"
    ;;
  x86_64)
    # Cek apakah berjalan di bawah Rosetta 2 pada Mac Apple Silicon
    if [[ "$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" == "1" ]]; then
      TARGET_ARCH="darwin-arm64"
    else
      TARGET_ARCH="darwin-amd64"
    fi
    ;;
  *)
    echo "[ERROR] Arsitektur macOS tidak didukung: $ARCH_RAW" >&2
    exit 1
    ;;
esac

DOWNLOAD_URL="${SERVER_URL%/}/downloads/macos/vectranet-agent-${TARGET_ARCH}"
TMP_BIN="$(mktemp /tmp/vectranet-agent-macos.XXXXXX)"
trap 'rm -f "$TMP_BIN"' EXIT

echo "[1/5] Mengunduh binary agen (${TARGET_ARCH}) dari ${DOWNLOAD_URL}..."
/usr/bin/curl -fsSL --retry 3 --connect-timeout 10 "$DOWNLOAD_URL" -o "$TMP_BIN"

if [[ -n "$EXPECTED_SHA256" ]]; then
  echo "[2/5] Memverifikasi checksum SHA-256..."
  ACTUAL_SHA256="$(/usr/bin/shasum -a 256 "$TMP_BIN" | awk '{print $1}')"
  if [[ "$(echo "$ACTUAL_SHA256" | tr '[:upper:]' '[:lower:]')" != "$(echo "$EXPECTED_SHA256" | tr '[:upper:]' '[:lower:]')" ]]; then
    echo "[ERROR] Checksum SHA-256 tidak cocok! Expected: $EXPECTED_SHA256, Actual: $ACTUAL_SHA256" >&2
    exit 1
  fi
else
  echo "[2/5] Melewati verifikasi SHA-256 (parameter --sha256 tidak diberikan)."
fi

echo "[3/5] Menyiapkan direktori '${INSTALL_DIR}' dan menghapus atribut karantina Gatekeeper..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"
chmod 0755 "$INSTALL_DIR" "$LOG_DIR"

# Hentikan LaunchDaemon lama jika sedang berjalan
if /bin/launchctl print "system/${PLIST_LABEL}" >/dev/null 2>&1; then
  /bin/launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true
fi

install -o root -g wheel -m 0755 "$TMP_BIN" "$BINARY_PATH"
/usr/bin/xattr -dr com.apple.quarantine "$BINARY_PATH" >/dev/null 2>&1 || true

echo "[4/5] Menulis konfigurasi LaunchDaemon di ${PLIST_PATH}..."
cat <<EOF > "$PLIST_PATH"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${BINARY_PATH}</string>
        <string>-server</string>
        <string>${SERVER_URL}</string>
        <string>-token</string>
        <string>${AGENT_TOKEN}</string>
        <string>-interval</string>
        <string>60</string>
    </array>

    <key>EnvironmentVariables</key>
    <dict>
        <key>VECTRANET_SERVER_URL</key>
        <string>${SERVER_URL}</string>
        <key>VECTRANET_AGENT_TOKEN</key>
        <string>${AGENT_TOKEN}</string>
    </dict>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>ProcessType</key>
    <string>Background</string>

    <key>LowPriorityIO</key>
    <true/>

    <key>Nice</key>
    <integer>10</integer>

    <key>SoftResourceLimits</key>
    <dict>
        <key>ResidentSetSize</key>
        <integer>18874368</integer>
    </dict>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/agent.log</string>

    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/agent.err.log</string>
</dict>
</plist>
EOF

chown root:wheel "$PLIST_PATH"
chmod 0644 "$PLIST_PATH"

echo "[5/5] Memvalidasi dan memuat LaunchDaemon (${PLIST_LABEL})..."
/usr/bin/plutil -lint "$PLIST_PATH"

if ! /bin/launchctl bootstrap system "$PLIST_PATH" 2>/dev/null; then
  /bin/launchctl load -w "$PLIST_PATH"
fi
/bin/launchctl kickstart -k "system/${PLIST_LABEL}" >/dev/null 2>&1 || true

echo "[SUCCESS] VectraNet macOS Agent (${TARGET_ARCH}) aktif sebagai LaunchDaemon persisten."
