# Security notes (v1)

## Threat model (summary)

Portal grants temporary network path to SSH tunnel port and installs restricted
SSH public keys so users can forward only to local DB ports.

## Hard requirements

1. **Never** commit `tls.key`, `users.json`, `db-ip-portal.env`, `state.json`.
2. `DBIP_SECRET` only via `EnvironmentFile=` mode `0640` `root:dbipportal`.
3. Rotate any secret that appeared in chat, units, or logs before production cutover.
4. Portal process user `dbipportal` may only sudo listed helpers (NOPASSWD).
5. Helpers validate username (`^prod_[A-Za-z0-9_.-]{1,64}$`) and IP (`ipaddress`).
6. Reset removes **only** managed comments `dbip-portal:*` on configured dynamic ports.
7. Dual restriction: `authorized_keys` options **and** `sshd` `Match User prod_*`.

## DeximDB findings to remediate (not in this package’s first apply)

| Finding | Priority |
|---|---|
| Secret in unit (already exposed) | P0 rotate on migrate |
| UI port 2222 vs 2224 | P0 fixed in target portal |
| fail2ban `port=ssh` | P0 fixed in templates |
| `5432 ALLOW Anywhere` | P1 after dependency audit |
| DB listeners on `0.0.0.0` | P1 |
| Orphan `#dbip-portal:3306` | P1 |
| state ↔ UFW drift | P2 reconcile |

## Port 1033 / prodjumper

External to this role. Do not auto-install. Document on each host inventory.
