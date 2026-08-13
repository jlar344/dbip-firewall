# Architecture — specification v1

## 1. Baseline vs target

| | Baseline (DeximDB today) | Target (new installs) |
|---|---|---|
| Portal | HTTPS :8443 Flask/Gunicorn | Same |
| Dynamic firewall ports | 2224 + 5432 | **2224 only** |
| Helper name | `dbip-ufw` | `dbip-firewall` (provider: ufw \| firewalld) |
| Secret | `Environment=` in unit | `EnvironmentFile=` `db-ip-portal.env` |
| SSH UI port | hardcoded 2222 (bug) | `dbip_ssh_port` / `SSH_PORT` |
| Unix users | Manual / existing | Ansible `dbip_users` (portal cannot create) |
| DB bind | 0.0.0.0 + UFW | Prefer loopback / private only |
| State | flat `{user: {ip, updated_at}}` | `{version, registrations}` + reconcile |
| Reset | `dbip-ufw reset` | Managed comments `dbip-portal:*` on port 2224 only |
| Fail2ban | `port = ssh` | `22,2224` + future portal jail |

Baseline remains the **migration reference**. Target is what Ansible installs.

## 2. Baseline flow (DeximDB)

```
HTTPS :8443
    ↓
Flask / Gunicorn
    ↓
users.json
    ↓
sesión 5 min
    ↓
request.remote_addr
    ↓
sudo NOPASSWD
    ├── dbip-ufw → UFW :2224 + :5432 + state.json
    └── dbip-sshkey → prod_*/authorized_keys
           ↓
        sshd :2224
           ↓
     PermitOpen 127.0.0.1:3306 / 127.0.0.1:5432
```

## 3. Target flow

```
                 Internet
                    │
                    │ HTTPS :8443
                    ▼
            ┌─────────────────┐
            │  DB IP Portal   │
            │   dbipportal    │
            └────────┬────────┘
                     │
              sudo restringido
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
    dbip-firewall          dbip-sshkey
          │                     │
          ▼                     ▼
   Firewall :2224           prod_*
          │              authorized_keys
          └──── SSH :2224 ◄─────┘
                     │
                     ▼
                  sshd Match
                     │
              local forwarding
                     │
                     ▼
          dbip_forward_destinations
          (inventory → PermitOpen)
```

**Important:** the portal opens **only** SSH port `2224` dynamically.
Databases are reached exclusively via local forwarding (`PermitOpen`).

Single source of truth: `dbip_forward_destinations` in inventory feeds:

```
inventory
   ├── sshd Match User prod_* → PermitOpen
   ├── dbip-sshkey → permitopen="host:port" in authorized_keys
   └── portal → ssh -L instructions (local port = dest + 10000)
```

Examples:

```yaml
# DeximDB-style both engines
dbip_forward_destinations:
  - host: "127.0.0.1"
    port: 3306
  - host: "127.0.0.1"
    port: 5432

# datacorp-bbdd (PgBouncer; do not use 5432 — that bypasses the pooler)
dbip_forward_destinations:
  - host: "127.0.0.1"
    port: 6432
```

Runtime copy: `/etc/db-ip-portal/permit-open.conf` (`DBIP_PERMIT_OPEN=127.0.0.1:6432`).
`dbip-sshkey` parses CSV `host:port` only and rejects SSH options.

## 4. Network policy (new DB hosts)

| Port | Role | Exposure |
|---|---|---|
| 22 | Admin SSH | Administrative IPs |
| 2224 | prod_* tunnel SSH | Portal-registered IP |
| 8443 | Portal | Per defined policy |
| 3306 | MariaDB | **Not public** (prefer 127.0.0.1) |
| 5432 | PostgreSQL | **Not public** (prefer 127.0.0.1) |
| 6432 | PgBouncer (datacorp) | **Not public** via portal; legacy IP allow stays until gate |

DeximDB’s current `5432 ALLOW Anywhere` is **out of scope for v1 packaging**.
Document and remediate after the reproducible system is tested (P1).

datacorp-bbdd target path (do **not** forward to `:5432`):

```
Cliente
   │ SSH :2224
   ▼
prod_*
   │ PermitOpen
   ▼
127.0.0.1:6432  PgBouncer (transaction)
   ▼
127.0.0.1:5432  PostgreSQL
```

### Post-tunnel gate (later — not this commit)

Do not remove the legacy public/IP allow on `:6432` until all of these pass,
then keep a short coexistence window and only then an explicit reversible revert:

1. `sshd -t`
2. `sshd -T` for a `prod_*` user → `permitopen 127.0.0.1:6432`
3. `authorized_keys` → `permitopen="127.0.0.1:6432"`
4. Portal opens only `2224`
5. `ssh -p 2224` as `prod_*`
6. Local tunnel → `127.0.0.1:6432`
7. `psql` through PgBouncer
8. Real app through the tunnel
9. A non-allowed dest (e.g. `:9999`) is rejected

## 5. Component contracts

### `dbip-firewall`

```
dbip-firewall add <ip>
dbip-firewall remove <ip>
dbip-firewall check <ip>
dbip-firewall list
dbip-firewall reset
dbip-firewall reconcile   # report only unless --apply
```

Provider: `dbip_firewall_provider: ufw` (firewalld later).

Managed rule (UFW):

```text
ufw allow from IP to any port 2224 proto tcp comment 'dbip-portal:2224'
```

### `dbip-sshkey`

- Managed block markers preserved.
- **Multiple keys** allowed inside the block.
- Each key: `restrict,port-forwarding,permitopen="host:port"` from `DBIP_PERMIT_OPEN`.
- Depth-in-defense with identical `Match User prod_*` `PermitOpen` in sshd.

### Portal

- Does **not** create Unix users.
- Uses `SSH_PORT` / `DBIP_SSH_PORT` and `DBIP_PERMIT_OPEN` for UI commands.
- Auth failures emit machine-parseable lines for fail2ban (`DBIP_AUTH_FAIL ...`).
- Secret from env file only.

### Ansible

- Declares `dbip_users`.
- Installs portal, helpers, sshd drop-in, fail2ban, systemd, sudoers.
- Never commits `tls.key`, `users.json`, `*.env`, `state.json`.

## 6. State format (target)

```json
{
  "version": 1,
  "registrations": {
    "prod_jlar": {
      "ip": "186.175.165.153",
      "updated_at": "2026-08-12T22:30:00Z"
    }
  }
}
```

`state.json` is **not** sole source of truth; reconcile against live firewall.

## 7. Priority backlog

**P0 (v1 ready):** rotate secret on deploy · UI port via variable · fail2ban 22,2224 · EnvironmentFile · sshd -t / sudoers tests · no private keys in Git.

**P1 (network):** remove 5432 Anywhere after dependency check · loopback DB binds · drop orphan `dbip-portal:3306` · portal manages 2224 only.

**P2 (hardening):** reconcile · JSONL audit · portal fail2ban jail · firewalld · backups.
