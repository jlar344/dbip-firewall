# Migration (DeximDB → managed package)

## Goals

1. Package current behaviour as **baseline** (already under `baseline/`).
2. Install **target** design on new hosts without guessing.
3. Migrate DeximDB later with explicit playbooks — **no blind overwrite**.

## What we will NOT touch during package build

- Live UFW rules
- Live `sshd_config` / drop-ins already in production
- Live fail2ban jails
- `prod_*` accounts / `authorized_keys`
- Live systemd units on DeximDB

Work happens in `/home/jlar/db-ip-access-manager` only until a controlled apply.

Lab (`scripts/lab-replace-ipauth.sh`): never deletes `LEGACY_DB_PORT` (6432).
For datacorp run with `FORWARD_DESTINATIONS=127.0.0.1:6432` so PermitOpen
matches PgBouncer. Default in the script is `127.0.0.1:5432` for hosts that
are not pooler-fronted.

## Suggested migrate steps (later)

1. Backup: unit, sudoers, helpers, `state.json`, `users.json`, `user.rules`, sshd Match, fail2ban.
2. Generate new `DBIP_SECRET`; write `db-ip-portal.env`.
3. Deploy target portal + `dbip-firewall` + `dbip-sshkey` beside or replacing helpers.
4. Update sudoers to call `dbip-firewall` (keep temporary alias/wrapper if needed).
5. Import flat `state.json` → `{version:1, registrations:{...}}` via `scripts/migrate-current-state.py`.
6. Run `dbip-firewall reconcile` (report-only); decide on orphans.
7. Switch systemd to `EnvironmentFile=`; restart portal; verify login + update IP + tunnel.
8. Only then change dynamic ports to **2224-only** and plan P1 network lockdown.

## Orphans observed on DeximDB

- UFW `#dbip-portal:3306` for `200.104.189.252` (code no longer manages 3306).
- UFW `#dbip-portal:2224` for `186.175.165.153` without `state.json` entry.
