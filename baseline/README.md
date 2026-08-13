# Baseline — DeximDB (as found)

Sanitized snapshot of the **live** DeximDB installation used as migration
reference. This is **not** the install target.

| Path in tree | Source on DeximDB |
|---|---|
| `portal/app.py` | `/opt/db-ip-portal/app.py` |
| `portal/add_user.py` | `/opt/db-ip-portal/add_user.py` |
| `sbin/dbip-ufw` | `/usr/local/sbin/dbip-ufw` |
| `sbin/dbip-sshkey` | `/usr/local/sbin/dbip-sshkey` |
| `systemd/*` | `/etc/systemd/system/db-ip-portal.service`, `dbip-reset.*` |
| `sudoers/db-ip-portal` | `/etc/sudoers.d/db-ip-portal` |
| `ssh/*` | Match `prod_*` + external `jumper.conf` |
| `fail2ban/sshd.local` | `/etc/fail2ban/jail.d/sshd.local` |

## Sanitization

- `DBIP_SECRET` in the unit was replaced with `<REDACTED_ROTATE_ON_MIGRATE>`.
- `tls.key`, `users.json`, and live `state.json` were **not** copied.
- Port **1033** and `Match User prodjumper` are documented as **external** to the portal.

## Known baseline inconsistencies (do not copy into target)

1. UI hardcodes `ssh -p 2222` while sshd listens on **2224**.
2. `dbip-ufw` opens **2224 + 5432** (not 3306); orphan `#dbip-portal:3306` exists in UFW.
3. UFW has `5432 ALLOW Anywhere` — outside portal management.
4. Secret embedded in systemd unit `Environment=`.
5. fail2ban `port = ssh` (likely only 22).
6. `state.json` can drift from UFW (e.g. rule without state entry).
7. MariaDB/PgBouncer listen on `0.0.0.0`.

Target design lives under `portal/`, `roles/`, and `docs/architecture.md`.
