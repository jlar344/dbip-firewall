#!/usr/bin/env python3
import json
import os
import getpass
import sys
from werkzeug.security import generate_password_hash

USERS_FILE = "/etc/db-ip-portal/users.json"

if len(sys.argv) != 2:
    raise SystemExit("Uso: add_user.py <usuario>")

user = sys.argv[1].strip()
password = getpass.getpass("Contraseña del portal: ")
password2 = getpass.getpass("Repetir contraseña: ")

if password != password2:
    raise SystemExit("Las contraseñas no coinciden")

users = {}
if os.path.exists(USERS_FILE):
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)

users[user] = generate_password_hash(password)

with open(USERS_FILE, "w", encoding="utf-8") as f:
    json.dump(users, f, indent=2, sort_keys=True)
    f.write("\n")

os.chmod(USERS_FILE, 0o640)
print(f"Usuario {user} creado/actualizado")
