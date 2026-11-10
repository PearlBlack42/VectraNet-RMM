#!/usr/bin/env bash
# ============================================================================
# VectraNet RMM Silent Agent Installer & Systemd Service Provisioner
# File: agents/linux/install.sh
# Usage:
#   curl -fsSL https://rmm.internal.corp:8443/agents/linux/install.sh | sudo bash -s -- \
#     --server "https://rmm.internal.corp:8443" \
#     --token "vn_live_98a7bc6512f4"
# ============================================================================
set -euo pipefail

SERVER_URL="${VECTRANET_SERVER_URL:-https://rmm.internal.corp:8443}"
AGENT_TOKEN="${VECTRANET_AGENT_TOKEN:-vn_default_bootstrap_token}"
EXPECTED_SHA256=""
INSTALL_BIN="/usr/local/bin/vectranet-agent"
ENV_FILE="/etc/default/vectranet-agent"
SERVICE_FILE="/etc/systemd/system/vectranet-agent.service"

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
      echo "[ERROR] Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[ERROR] Script ini harus dijalankan sebagai root (gunakan sudo)." >&2
  exit 1
fi

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64)
    ARCH="amd64"
    ;;
  aarch64|arm64)
    ARCH="arm64"
    ;;
  *)
    echo "[ERROR] Arsitektur CPU tidak didukung: $ARCH_RAW" >&2
    exit 1
    ;;
esac

BINARY_URL="${SERVER_URL%/}/downloads/linux/vectranet-agent-linux-${ARCH}"
TMP_BIN="$(mktemp /tmp/vectranet-agent.XXXXXX)"
trap 'rm -f "$TMP_BIN"' EXIT

echo "[1/5] Mengunduh binary agen untuk linux/${ARCH} dari ${BINARY_URL}..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --retry 3 --connect-timeout 10 "$BINARY_URL" -o "$TMP_BIN"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP_BIN" "$BINARY_URL"
else
  echo "[ERROR] curl atau wget diperlukan untuk mengunduh binary agen." >&2
  exit 1
fi

if [[ -n "$EXPECTED_SHA256" ]]; then
  echo "[2/5] Memverifikasi integritas SHA-256..."
  echo "${EXPECTED_SHA256}  ${TMP_BIN}" | sha256sum -c -
else
  echo "[2/5] Melewati verifikasi SHA-256 (parameter --sha256 tidak diberikan)."
fi

echo "[3/5] Menginstal binary ke ${INSTALL_BIN}..."
systemctl stop vectranet-agent.service >/dev/null 2>&1 || true
install -o root -g root -m 0755 "$TMP_BIN" "$INSTALL_BIN"

echo "[4/5] Menulis file kredensial ${ENV_FILE} (chmod 0600) & unit Systemd..."
cat <<EOF > "$ENV_FILE"
VECTRANET_SERVER_URL="${SERVER_URL}"
VECTRANET_AGENT_TOKEN="${AGENT_TOKEN}"
EOF
chmod 0600 "$ENV_FILE"

cat <<'EOF' > "$SERVICE_FILE"
[Unit]
Description=VectraNet Ultra-Lightweight Discovery & Telemetry Agent
Documentation=https://vectranet.internal/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/default/vectranet-agent
ExecStart=/usr/local/bin/vectranet-agent -server=${VECTRANET_SERVER_URL} -token=${VECTRANET_AGENT_TOKEN} -interval=60
Restart=always
RestartSec=5
Nice=10
MemoryAccounting=true
MemoryHigh=15M
MemoryMax=20M
CPUAccounting=true
CPUQuota=2%
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

echo "[5/5] Mengaktifkan dan menjalankan layanan vectranet-agent.service..."
systemctl daemon-reload
systemctl enable --now vectranet-agent.service

systemctl --no-pager --full status vectranet-agent.service | head -n 12
echo "[SUCCESS] Agen VectraNet berhasil terpasang dan berjalan."
