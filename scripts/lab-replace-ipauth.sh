#!/bin/bash
# Replace an incomplete ipauth install with db-ip-access-manager (target v1).
#
# This script does NOT remove legacy PgBouncer UFW access (default port 6432).
# Retire that rule in a later, explicit step after the SSH tunnel is validated:
#   prod_* → :SSH_PORT → FORWARD_DESTINATIONS (datacorp: 127.0.0.1:6432)
#
# Required (no defaults for host-specific values):
#   SRC          unpacked db-ip-access-manager tree on the target host
#   LAB_HOST     public/DNS name used in TLS CN and portal SSH instructions
#
# Optional:
#   LEGACY_ALLOWED_IP     documented only; never used to delete UFW rules
#   ENSURE_USERS          space-separated Unix accounts to create (e.g. prod_jlar)
#   IPAUTH_PORT           old HTTP portal port to drop from UFW if different (8889)
#   PORTAL_PORT           new portal listen port (8889 HTTP lab / 8443 TLS)
#   USE_TLS               1 to bind gunicorn with tls.crt/tls.key
#   SSH_PORT              tunnel SSH port (2224)
#   ADMIN_SSH_PORT        admin SSH port (22)
#   LEGACY_DB_PORT        pgbouncer/legacy port that must not be deleted (6432)
#   FORWARD_DESTINATIONS  CSV host:port for PermitOpen (default 127.0.0.1:5432)
#   BACKUP_ROOT           backup parent directory (/root)
#
# Usage (as root on the lab host):
#   SRC=/path/to/db-ip-access-manager \
#   LAB_HOST=lab.example.internal \
#   ENSURE_USERS=prod_example \
#   LEGACY_ALLOWED_IP=192.0.2.10 \
#   FORWARD_DESTINATIONS=127.0.0.1:6432 \
#   bash scripts/lab-replace-ipauth.sh
set -euo pipefail

SRC="${SRC:?required}"
LAB_HOST="${LAB_HOST:?required}"
LEGACY_ALLOWED_IP="${LEGACY_ALLOWED_IP:-}"
ENSURE_USERS="${ENSURE_USERS:-}"
IPAUTH_PORT="${IPAUTH_PORT:-8889}"
PORTAL_PORT="${PORTAL_PORT:-8889}"
USE_TLS="${USE_TLS:-0}"
SSH_PORT="${SSH_PORT:-2224}"
ADMIN_SSH_PORT="${ADMIN_SSH_PORT:-22}"
LEGACY_DB_PORT="${LEGACY_DB_PORT:-6432}"
FORWARD_DESTINATIONS="${FORWARD_DESTINATIONS:-127.0.0.1:5432}"
FORWARD_DESTINATIONS="${FORWARD_DESTINATIONS// /}"
BACKUP_ROOT="${BACKUP_ROOT:-/root}"

export SRC FORWARD_DESTINATIONS
eval "$(
  python3 - <<'PY'
import os
import sys

sys.path.insert(0, os.path.join(os.environ["SRC"], "portal"))
from permit_open import format_csv, format_sshd_permitopen, parse_permit_open

dests = parse_permit_open(os.environ["FORWARD_DESTINATIONS"])
print("PERMIT_OPEN_CSV='%s'" % format_csv(dests))
print("PERMIT_OPEN_SPACES='%s'" % format_sshd_permitopen(dests))
PY
)"
: "${PERMIT_OPEN_CSV:?invalid FORWARD_DESTINATIONS}"
: "${PERMIT_OPEN_SPACES:?invalid FORWARD_DESTINATIONS}"

PORTAL_USER=dbipportal
PORTAL_GROUP=dbipportal
INSTALL_ROOT=/opt/db-ip-portal
ETC=/etc/db-ip-portal
STATE=/var/lib/db-ip-portal
LOGDIR=/var/log/db-ip-portal

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP="${BACKUP_ROOT}/ipauth-backup-${STAMP}"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi
if [[ ! -d "${SRC}/portal" || ! -f "${SRC}/portal/permit_open.py" || ! -f "${SRC}/roles/db_ip_access_manager/files/dbip-firewall" ]]; then
  echo "Source tree missing at ${SRC}" >&2
  exit 1
fi

echo "==> Backup incomplete ipauth to ${BACKUP}"
mkdir -p "${BACKUP}"
cp -a /etc/systemd/system/ipauth.service "${BACKUP}/" 2>/dev/null || true
cp -a /etc/sudoers.d/ipauth "${BACKUP}/" 2>/dev/null || true
cp -a /usr/local/sbin/ufw-ipauth-helper "${BACKUP}/" 2>/dev/null || true
cp -a /etc/nginx/sites-available/ipauth "${BACKUP}/" 2>/dev/null || true
cp -a /var/lib/pgbouncer-ip-auth "${BACKUP}/pgbouncer-ip-auth" 2>/dev/null || true
cp -a /var/log/pgbouncer-ip-auth.log "${BACKUP}/" 2>/dev/null || true
if [[ -d /opt/ipauth ]]; then
  mkdir -p "${BACKUP}/opt-ipauth"
  cp -a /opt/ipauth/app.py /opt/ipauth/ipauth.sqlite3 "${BACKUP}/opt-ipauth/" 2>/dev/null || true
fi
ufw status numbered > "${BACKUP}/ufw-status.txt" || true
systemctl cat ipauth.service > "${BACKUP}/ipauth.service.cat" 2>/dev/null || true

echo "==> Stop and disable ipauth"
systemctl stop ipauth.service 2>/dev/null || true
systemctl disable ipauth.service 2>/dev/null || true
rm -f /etc/systemd/system/multi-user.target.wants/ipauth.service
rm -f /etc/systemd/system/ipauth.service

echo "==> Remove nginx site (if present)"
rm -f /etc/nginx/sites-enabled/ipauth
if [[ -f /etc/nginx/sites-available/ipauth ]]; then
  mv /etc/nginx/sites-available/ipauth "${BACKUP}/ipauth.nginx"
fi

echo "==> Remove sudoers + helper (kept in backup)"
rm -f /etc/sudoers.d/ipauth
rm -f /usr/local/sbin/ufw-ipauth-helper

if [[ "${IPAUTH_PORT}" != "${PORTAL_PORT}" ]]; then
  echo "==> Remove UFW rules for old portal port ${IPAUTH_PORT} only"
  echo "    (never touching ${LEGACY_DB_PORT})"
  while ufw status numbered | grep -E -q "[^0-9]${IPAUTH_PORT}/tcp"; do
    NUM=$(ufw status numbered | sed -n "s/^\[\\s*\\([0-9]\\+\\)\\].* ${IPAUTH_PORT}\\/tcp.*/\\1/p" | head -1)
    [[ -n "${NUM}" ]] || break
    # Safety: refuse to delete a rule whose destination port is the legacy DB port
    RULE_LINE=$(ufw status numbered | sed -n "s/^\[\\s*${NUM}\\] //p" | head -1)
    if echo "${RULE_LINE}" | grep -E -q "(^|[[:space:]])${LEGACY_DB_PORT}/tcp"; then
      echo "Refusing to delete legacy DB port rule #${NUM}" >&2
      break
    fi
    ufw --force delete "${NUM}"
  done
else
  echo "==> Keeping UFW port ${PORTAL_PORT} (same as new portal listen port)"
fi

if [[ -n "${LEGACY_ALLOWED_IP}" ]]; then
  echo "==> Legacy access left in place: ${LEGACY_DB_PORT}/tcp from ${LEGACY_ALLOWED_IP}"
  echo "    Do not remove until tunnel prod_* -> :${SSH_PORT} -> ${PERMIT_OPEN_CSV} is validated."
fi

if [[ -d /opt/ipauth ]]; then
  mv /opt/ipauth "${BACKUP}/opt-ipauth-full"
fi

systemctl daemon-reload

echo "==> Install packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip openssh-server ufw fail2ban openssl sqlite3 >/dev/null

echo "==> System users"
getent group "${PORTAL_GROUP}" >/dev/null || groupadd --system "${PORTAL_GROUP}"
if ! id -u "${PORTAL_USER}" >/dev/null 2>&1; then
  useradd --system --gid "${PORTAL_GROUP}" --home "${INSTALL_ROOT}" --shell /usr/sbin/nologin "${PORTAL_USER}"
fi
# shellcheck disable=SC2086
for _user in ${ENSURE_USERS}; do
  if ! id -u "${_user}" >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash --groups users "${_user}"
  fi
done

echo "==> Directories"
install -d -o root -g "${PORTAL_GROUP}" -m 0750 "${INSTALL_ROOT}" "${ETC}" "${STATE}" "${LOGDIR}"

echo "==> Portal files + venv"
install -o root -g "${PORTAL_GROUP}" -m 0640 "${SRC}/portal/app.py" "${INSTALL_ROOT}/app.py"
install -o root -g "${PORTAL_GROUP}" -m 0750 "${SRC}/portal/add_user.py" "${INSTALL_ROOT}/add_user.py"
install -o root -g "${PORTAL_GROUP}" -m 0640 "${SRC}/portal/permit_open.py" "${INSTALL_ROOT}/permit_open.py"
install -o root -g "${PORTAL_GROUP}" -m 0640 "${SRC}/portal/requirements.txt" "${INSTALL_ROOT}/requirements.txt"
if [[ ! -x "${INSTALL_ROOT}/venv/bin/python" ]]; then
  python3 -m venv "${INSTALL_ROOT}/venv"
fi
"${INSTALL_ROOT}/venv/bin/pip" install -q --upgrade pip
"${INSTALL_ROOT}/venv/bin/pip" install -q -r "${INSTALL_ROOT}/requirements.txt"
chown -R "${PORTAL_USER}:${PORTAL_GROUP}" "${INSTALL_ROOT}/venv"

echo "==> Helpers"
install -o root -g root -m 0750 \
  "${SRC}/roles/db_ip_access_manager/files/dbip-firewall" /usr/local/sbin/dbip-firewall
install -o root -g root -m 0750 \
  "${SRC}/roles/db_ip_access_manager/files/dbip-sshkey" /usr/local/sbin/dbip-sshkey

echo "==> sudoers"
cat >/etc/sudoers.d/db-ip-portal <<'EOF'
dbipportal ALL=(root) NOPASSWD: /usr/local/sbin/dbip-firewall, /usr/local/sbin/dbip-sshkey
EOF
chmod 0440 /etc/sudoers.d/db-ip-portal
visudo -cf /etc/sudoers.d/db-ip-portal

echo "==> TLS (self-signed) + secret file"
if [[ ! -f "${ETC}/tls.key" ]]; then
  openssl req -x509 -newkey rsa:2048 -days 825 -nodes \
    -keyout "${ETC}/tls.key" -out "${ETC}/tls.crt" \
    -subj "/CN=${LAB_HOST}/O=db-ip-lab"
fi
chmod 0640 "${ETC}/tls.key" "${ETC}/tls.crt"
chown root:"${PORTAL_GROUP}" "${ETC}/tls.key" "${ETC}/tls.crt"

if [[ ! -f "${ETC}/db-ip-portal.env" ]]; then
  umask 077
  generated_secret=$(openssl rand -hex 32)
  cat >"${ETC}/db-ip-portal.env" <<EOF
DBIP_SECRET=${generated_secret}
DBIP_SSH_HOST=${LAB_HOST}
DBIP_SSH_PORT=${SSH_PORT}
DBIP_SESSION_MINUTES=5
DBIP_PERMIT_OPEN=${PERMIT_OPEN_CSV}
EOF
  unset generated_secret
fi
if grep -q '^DBIP_PERMIT_OPEN=' "${ETC}/db-ip-portal.env"; then
  sed -i "s|^DBIP_PERMIT_OPEN=.*|DBIP_PERMIT_OPEN=${PERMIT_OPEN_CSV}|" "${ETC}/db-ip-portal.env"
else
  printf 'DBIP_PERMIT_OPEN=%s\n' "${PERMIT_OPEN_CSV}" >>"${ETC}/db-ip-portal.env"
fi
cat >"${ETC}/permit-open.conf" <<EOF
DBIP_PERMIT_OPEN=${PERMIT_OPEN_CSV}
EOF
chown root:"${PORTAL_GROUP}" "${ETC}/db-ip-portal.env" "${ETC}/permit-open.conf"
chmod 0640 "${ETC}/db-ip-portal.env" "${ETC}/permit-open.conf"

echo "==> Migrate portal password hashes from ipauth sqlite (prod_ prefix)"
python3 - <<PY
import json, os, sqlite3, grp

candidates = [
    os.path.join("${BACKUP}", "opt-ipauth", "ipauth.sqlite3"),
    os.path.join("${BACKUP}", "opt-ipauth-full", "ipauth.sqlite3"),
]
src_db = next((p for p in candidates if os.path.exists(p)), None)
users = {}
if src_db:
    conn = sqlite3.connect(src_db)
    for username, pw_hash, active in conn.execute(
        "SELECT username, password_hash, active FROM users"
    ):
        if not active:
            continue
        key = username if username.startswith("prod_") else "prod_" + username
        users[key] = pw_hash
    conn.close()
path = "${ETC}/users.json"
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w", encoding="utf-8") as f:
    json.dump(users, f, indent=2, sort_keys=True)
    f.write("\n")
os.chmod(path, 0o640)
os.chown(path, 0, grp.getgrnam("${PORTAL_GROUP}").gr_gid)
print("migrated_users", sorted(users))
PY

if [[ ! -f "${STATE}/state.json" ]]; then
  cat >"${STATE}/state.json" <<'EOF'
{
  "version": 1,
  "registrations": {}
}
EOF
  chown root:"${PORTAL_GROUP}" "${STATE}/state.json"
  chmod 0640 "${STATE}/state.json"
fi
chown "${PORTAL_USER}:${PORTAL_GROUP}" "${LOGDIR}"
chmod 0750 "${LOGDIR}"

echo "==> sshd drop-in (tunnel port + Match prod_*)"
cat >/etc/ssh/sshd_config.d/00-dbip-ports.conf <<EOF
Port ${ADMIN_SSH_PORT}
Port ${SSH_PORT}
EOF
cat >/etc/ssh/sshd_config.d/50-dbip-prod.conf <<EOF
Match User prod_*
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    AllowTcpForwarding local
    GatewayPorts no
    PermitOpen ${PERMIT_OPEN_SPACES}
    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
    ForceCommand /bin/false
EOF
sshd -t

echo "==> fail2ban sshd ports ${ADMIN_SSH_PORT},${SSH_PORT}"
cat >/etc/fail2ban/jail.d/sshd-dbip.local <<EOF
[sshd]
enabled = true
backend = systemd
port = ${ADMIN_SSH_PORT},${SSH_PORT}
maxretry = 4
findtime = 10m
bantime = 24h
ignoreip = 127.0.0.1/8 ::1
EOF

GUNICORN_BIND="--bind 0.0.0.0:${PORTAL_PORT}"
if [[ "${USE_TLS}" == "1" ]]; then
  GUNICORN_BIND="${GUNICORN_BIND} --certfile ${ETC}/tls.crt --keyfile ${ETC}/tls.key"
fi

echo "==> systemd units"
cat >/etc/systemd/system/db-ip-portal.service <<EOF
[Unit]
Description=DB IP Portal
After=network-online.target
Wants=network-online.target

[Service]
User=${PORTAL_USER}
Group=${PORTAL_GROUP}
WorkingDirectory=${INSTALL_ROOT}
EnvironmentFile=-${ETC}/db-ip-portal.env
Environment=DBIP_SSH_PORT=${SSH_PORT}
Environment=DBIP_SSH_HOST=${LAB_HOST}
Environment=DBIP_DYNAMIC_PORTS=${SSH_PORT}
Environment=DBIP_FIREWALL_PROVIDER=ufw
Environment=DBIP_PERMIT_OPEN=${PERMIT_OPEN_CSV}
Environment=DBIP_INSTALL_ROOT=${INSTALL_ROOT}
Environment=DBIP_STATE_FILE=${STATE}/state.json
Environment=DBIP_AUDIT_FILE=${LOGDIR}/audit.jsonl
Environment=DBIP_USERS_FILE=${ETC}/users.json
ExecStart=${INSTALL_ROOT}/venv/bin/gunicorn --workers 2 ${GUNICORN_BIND} app:app
Restart=always
RestartSec=3
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=full
ProtectHome=false
ReadWritePaths=${STATE} ${LOGDIR} /etc/ufw /home

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/dbip-reset.service <<EOF
[Unit]
Description=Reset DB IP Portal managed firewall rules

[Service]
Type=oneshot
Environment=DBIP_DYNAMIC_PORTS=${SSH_PORT}
Environment=DBIP_FIREWALL_PROVIDER=ufw
Environment=DBIP_STATE_FILE=${STATE}/state.json
ExecStart=/usr/local/sbin/dbip-firewall reset
EOF

cat >/etc/systemd/system/dbip-reset.timer <<'EOF'
[Unit]
Description=Run DB IP Portal firewall reset on schedule

[Timer]
OnCalendar=Sat *-*-* 00:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now db-ip-portal.service
systemctl enable --now dbip-reset.timer
systemctl reload ssh || systemctl reload sshd || true
if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
  echo "==> ssh.socket detected; restart so extra SSH_PORT is actually listening"
  systemctl restart ssh.socket || true
fi
systemctl restart fail2ban || true

echo "==> UFW allow portal ${PORTAL_PORT} (not ${SSH_PORT} globally; not ${LEGACY_DB_PORT})"
ufw allow "${PORTAL_PORT}/tcp" comment 'dbip-portal' || true

echo "==> Verify"
systemctl is-active db-ip-portal
sshd -t && echo sshd_ok
visudo -cf /etc/sudoers.d/db-ip-portal
ss -ltn | grep -E ":(${ADMIN_SSH_PORT}|${SSH_PORT}|${PORTAL_PORT}|5432|${LEGACY_DB_PORT}|${IPAUTH_PORT})\\b" || true
echo "==> UFW numbered (legacy ${LEGACY_DB_PORT} must still be present if it existed)"
ufw status numbered
echo "BACKUP=${BACKUP}"
echo "DONE"
echo "Next (manual, after tunnel validation): remove legacy ${LEGACY_DB_PORT} allow — not done by this script."
