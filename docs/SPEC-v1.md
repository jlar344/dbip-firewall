# Specification v1 — accepted decisions

Frozen from the DeximDB inventory + design review.

1. Baseline documents DeximDB; target does not copy insecure quirks.
2. Dynamic firewall ports: **2224 only**.
3. Helper rename: `dbip-ufw` → `dbip-firewall` (provider ufw, later firewalld).
4. `state.json` → `{version, registrations}` + reconcile (report-first).
5. Weekly reset: managed `dbip-portal:*` on dynamic ports only.
6. Unix users via Ansible; portal does not create accounts.
7. Multi-key managed `authorized_keys` + sshd Match (defense in depth).
8. UI / config use `dbip_ssh_port` (fix 2222 bug).
9. fail2ban sshd ports `22,2224`; portal jail deferred until filter stable.
10. Secret via `EnvironmentFile`; rotate exposed secret on migrate.
11. TLS key never in Git.
12. DeximDB `5432 Anywhere` / `0.0.0.0` binds = P1 after package works.
13. Build package offline from production; no live mutation until verify.
