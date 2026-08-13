# Installation (draft)

Package is under construction. Do **not** run against DeximDB until verify playbook passes on a lab host.

```bash
cd db-ip-access-manager
# fill inventories/example/group_vars and TLS/secret paths
ansible-playbook playbooks/install.yml --check
ansible-playbook playbooks/verify.yml
```

Required inventory variables: see `roles/db_ip_access_manager/defaults/main.yml`.
