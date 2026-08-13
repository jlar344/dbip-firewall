# Recovery (draft)

1. Restore `/etc/db-ip-portal/` (`users.json`, TLS, env) from backup.
2. Restore `/var/lib/db-ip-portal/state.json` if needed.
3. Restore helpers under `/usr/local/sbin/`.
4. `systemctl daemon-reload && systemctl restart db-ip-portal`.
5. `dbip-firewall reconcile` then decide whether to `--apply`.
6. `sshd -t` before any sshd restart.
7. Prefer restoring UFW `user.rules` from known-good backup over ad-hoc deletes.
