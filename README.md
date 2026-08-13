# DB IP Access Manager

Paquete reproducible para el portal de acceso temporal a bases de datos
(túnel SSH restringido + IP dinámica en firewall).

## Baseline vs target

- **Baseline** (`baseline/`): copia sanitizada de DeximDB tal como está hoy.
- **Target** (`portal/`, `roles/`, `docs/`): especificación v1 — portal abre
  **solo** el puerto SSH de túnel (`dbip_ssh_port`, default 2224); las DB se
  alcanzan únicamente vía `PermitOpen` a `127.0.0.1:3306/5432`.

Ver [docs/architecture.md](docs/architecture.md).

## Estado del repo

| Área | Estado |
|---|---|
| Baseline sanitizado | Listo |
| Spec docs v1 | Listo |
| `dbip-firewall` / `dbip-sshkey` target | Listo (código; no desplegado) |
| Portal target (`SSH_PORT`, EnvironmentFile, AUTH_FAIL) | Listo (código) |
| Rol Ansible + templates | Scaffold listo |
| Apply a DeximDB | **No** — producción intacta |

## No tocar en producción todavía

UFW · sshd · fail2ban · prod_* · authorized_keys · units vivos en DeximDB.

## Próximos pasos

1. Lab host: `ansible-playbook playbooks/install.yml --check`
2. Pruebas: login portal · update IP · túnel · `dbip-firewall reconcile`
3. Rotar `DBIP_SECRET` en el cutover (P0)
4. Playbook `migrate.yml` controlado para DeximDB

## Layout

```
db-ip-access-manager/
├── baseline/          # DeximDB snapshot (sanitized)
├── portal/            # target app
├── roles/db_ip_access_manager/
├── playbooks/
├── inventories/
├── scripts/
└── docs/
```
