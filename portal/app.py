"""DB IP Portal — target v1 (packaged).

Differences vs DeximDB baseline:
- SSH_PORT / DBIP_SSH_PORT drives all UI tunnel instructions (no hardcoded 2222/2224).
- Calls dbip-firewall (not dbip-ufw); dynamic port is SSH tunnel only.
- DBIP_SECRET only from environment (EnvironmentFile).
- Auth failures emit DBIP_AUTH_FAIL lines for fail2ban.
- Audit JSONL under /var/log/db-ip-portal/ when available.
"""
from __future__ import annotations

import json
import os
import pwd
import re
import secrets
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, flash, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash

USERS_FILE = os.environ.get("DBIP_USERS_FILE", "/etc/db-ip-portal/users.json")
AUDIT_LOG_FILE = os.environ.get(
    "DBIP_AUDIT_FILE", "/var/log/db-ip-portal/audit.jsonl"
)
# Fallback to baseline path if new dir not present yet
LEGACY_AUDIT = "/var/lib/db-ip-portal/audit.log"
STATE_FILE = os.environ.get("DBIP_STATE_FILE", "/var/lib/db-ip-portal/state.json")
FIREWALL_BIN = os.environ.get("DBIP_FIREWALL_BIN", "/usr/local/sbin/dbip-firewall")
SSHKEY_BIN = os.environ.get("DBIP_SSHKEY_BIN", "/usr/local/sbin/dbip-sshkey")

SSH_PORT = int(os.environ.get("DBIP_SSH_PORT", os.environ.get("SSH_PORT", "2224")))
SSH_HOST = os.environ.get("DBIP_SSH_HOST", "195.114.216.26")
FORWARD_MYSQL = os.environ.get("DBIP_FORWARD_MYSQL", "127.0.0.1:3306")
FORWARD_PG = os.environ.get("DBIP_FORWARD_POSTGRES", "127.0.0.1:5432")
LOCAL_MYSQL_PORT = int(os.environ.get("DBIP_LOCAL_MYSQL_PORT", "3307"))
LOCAL_PG_PORT = int(os.environ.get("DBIP_LOCAL_PG_PORT", "15432"))

LOGIN_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
PORTAL_USER_RE = re.compile(r"^prod_[A-Za-z0-9_.-]{1,64}$")

app = Flask(__name__)
_secret = os.environ.get("DBIP_SECRET")
if not _secret:
    # Refuse silent random secret in production-like paths; allow only for tests.
    if os.environ.get("DBIP_ALLOW_EPHEMERAL_SECRET") == "1":
        _secret = secrets.token_hex(32)
    else:
        raise RuntimeError("DBIP_SECRET must be set via EnvironmentFile")
app.secret_key = _secret
app.permanent_session_lifetime = timedelta(
    minutes=int(os.environ.get("DBIP_SESSION_MINUTES", "5"))
)

HTML = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Acceso temporal DB</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 35px; max-width: 980px; }
    .box { border: 1px solid #ddd; padding: 24px; border-radius: 8px; }
    .ok { color: #0a7a0a; }
    .err { color: #b00020; }
    input, button, textarea { padding: 10px; margin: 6px 0; width: 100%; box-sizing: border-box; }
    button { cursor: pointer; font-weight: bold; }
    code, pre { background: #f3f3f3; padding: 3px 6px; }
    pre { white-space: pre-wrap; padding: 14px; overflow-x: auto; }
    .section { border-top: 1px solid #ddd; margin-top: 24px; padding-top: 18px; }
  </style>
</head>
<body>
  <h1>Acceso temporal a bases de datos</h1>
  <div class="box">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}
        <p class="{{ category }}">{{ message }}</p>
      {% endfor %}
    {% endwith %}

    {% if not user %}
      <form method="post" action="/login">
        <label>Usuario</label>
        <input name="username" autocomplete="username" placeholder="usuario" required>
        <label>Contraseña</label>
        <input name="password" type="password" autocomplete="current-password" required>
        <button type="submit">Entrar</button>
      </form>
    {% else %}
      <p>Usuario autenticado: <strong>{{ user }}</strong></p>
      <p>IP detectada: <code>{{ ip }}</code></p>
      <p>IP registrada actualmente: <code>{{ registered_ip or "ninguna" }}</code></p>

      <form method="post" action="/update">
        <button type="submit">Actualizar mi IP para SSH túnel (puerto {{ ssh_port }})</button>
      </form>

      <div class="section">
        <h2>Llave SSH para túnel</h2>

        {% if key_status and key_status.has_key %}
          <p class="ok">Llave SSH configurada para <strong>{{ user }}</strong>.</p>
          <p>Comando recomendado (solo túnel local; sin shell):</p>
          <pre>ssh -p {{ ssh_port }} -i ~/.ssh/{{ user }}_deximdb -N \\
  -L {{ local_mysql }}:{{ forward_mysql }} \\
  -L {{ local_pg }}:{{ forward_pg }} \\
  {{ user }}@{{ ssh_host }}</pre>

          <p>Luego conecta tus clientes así:</p>
          <pre>MariaDB/MySQL: 127.0.0.1 puerto {{ local_mysql }}
PostgreSQL:   127.0.0.1 puerto {{ local_pg }}</pre>
        {% else %}
          <p class="err">No tienes llave SSH configurada.</p>
          <p>En tu equipo ejecuta:</p>
          <pre>ssh-keygen -t ed25519 -f ~/.ssh/{{ user }}_deximdb -C "{{ user }}@db-ip"
cat ~/.ssh/{{ user }}_deximdb.pub</pre>

          <p>Pega aquí el contenido de la llave pública:</p>
          <form method="post" action="/ssh-key">
            <textarea name="public_key" rows="5" placeholder="ssh-ed25519 AAAA... {{ user }}@db-ip" required></textarea>
            <button type="submit">Guardar mi llave pública</button>
          </form>
        {% endif %}
      </div>

      <form method="post" action="/logout">
        <button type="submit">Salir</button>
      </form>
    {% endif %}
  </div>
</body>
</html>
"""


def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    if "registrations" in data:
        return data["registrations"]
    return data


def audit_log(event, user=None, ip=None, ok=True, detail=None, **extra):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": str(uuid.uuid4()),
        "event": event,
        "actor": user,
        "source_ip": ip,
        "result": "success" if ok else "failure",
        "detail": detail,
        **extra,
    }
    for path in (AUDIT_LOG_FILE, LEGACY_AUDIT):
        try:
            os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            break
        except Exception:
            continue


def emit_auth_fail(ip: str, username: str) -> None:
    # Machine-parseable for fail2ban filter
    app.logger.warning(
        "DBIP_AUTH_FAIL remote_ip=%s username=%s", ip, username.replace(" ", "_")
    )


def normalize_username(username):
    username = username.strip()
    if username.startswith("prod_"):
        username = username[5:]
    if not LOGIN_USER_RE.match(username):
        return None
    return "prod_" + username


def valid_system_user(username):
    if not PORTAL_USER_RE.match(username):
        return False
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def get_client_ip():
    return request.remote_addr


def get_key_status(username):
    result = subprocess.run(
        ["sudo", SSHKEY_BIN, "status", username],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return {"ok": False, "has_key": False, "error": result.stderr or result.stdout}
    try:
        return json.loads(result.stdout)
    except Exception:
        return {"ok": False, "has_key": False, "error": result.stdout}


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect("/")
        return fn(*args, **kwargs)

    return wrapper


@app.route("/", methods=["GET"])
def index():
    user = session.get("user")
    state = load_state()
    registered_ip = state.get(user, {}).get("ip") if user else None
    key_status = get_key_status(user) if user else None
    return render_template_string(
        HTML,
        user=user,
        ip=get_client_ip(),
        registered_ip=registered_ip,
        key_status=key_status,
        ssh_port=SSH_PORT,
        ssh_host=SSH_HOST,
        forward_mysql=FORWARD_MYSQL,
        forward_pg=FORWARD_PG,
        local_mysql=LOCAL_MYSQL_PORT,
        local_pg=LOCAL_PG_PORT,
    )


@app.route("/login", methods=["POST"])
def login():
    login_username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    ip = get_client_ip()
    username = normalize_username(login_username)

    if not username or not valid_system_user(username):
        emit_auth_fail(ip, login_username or "unknown")
        audit_log(
            "login_fail",
            user=username or login_username,
            ip=ip,
            ok=False,
            detail="invalid_or_unauthorized_user",
        )
        flash("Usuario inválido o no autorizado.", "err")
        return redirect("/")

    users = load_users()
    password_hash = users.get(username)
    if not password_hash or not check_password_hash(password_hash, password):
        emit_auth_fail(ip, username)
        audit_log(
            "login_fail", user=username, ip=ip, ok=False, detail="bad_credentials"
        )
        flash("Usuario o contraseña incorrectos.", "err")
        return redirect("/")

    session.clear()
    session.permanent = True
    session["user"] = username
    audit_log("login_ok", user=username, ip=ip, ok=True)
    flash("Sesión iniciada correctamente.", "ok")
    return redirect("/")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    user = session.get("user")
    ip = get_client_ip()
    audit_log("logout", user=user, ip=ip, ok=True)
    session.clear()
    flash("Sesión cerrada.", "ok")
    return redirect("/")


@app.route("/update", methods=["POST"])
@login_required
def update():
    user = session["user"]
    ip = get_client_ip()
    result = subprocess.run(
        ["sudo", FIREWALL_BIN, "update", user, ip],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        audit_log(
            "firewall_update_fail",
            user=user,
            ip=ip,
            ok=False,
            detail=(result.stderr or result.stdout)[-500:],
        )
        flash(
            "Error actualizando firewall: " + (result.stderr or result.stdout)[-700:],
            "err",
        )
        return redirect("/")

    audit_log(
        "firewall_ip_update",
        user=user,
        ip=ip,
        ok=True,
        action="firewall_ip_update",
        target_user=user,
        new_ip=ip,
    )
    flash(f"IP {ip} autorizada para SSH túnel (puerto {SSH_PORT}).", "ok")
    return redirect("/")


@app.route("/ssh-key", methods=["POST"])
@login_required
def ssh_key():
    user = session["user"]
    ip = get_client_ip()
    public_key = request.form.get("public_key", "").strip()
    result = subprocess.run(
        ["sudo", SSHKEY_BIN, "install", user],
        input=public_key,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        audit_log(
            "ssh_key_install_fail",
            user=user,
            ip=ip,
            ok=False,
            detail=(result.stderr or result.stdout)[-500:],
        )
        flash(
            "Error guardando llave: " + (result.stderr or result.stdout)[-700:], "err"
        )
        return redirect("/")

    audit_log("ssh_key_install_ok", user=user, ip=ip, ok=True)
    flash("Llave SSH configurada correctamente.", "ok")
    return redirect("/")
