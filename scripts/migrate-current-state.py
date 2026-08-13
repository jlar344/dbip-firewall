#!/usr/bin/env python3
"""Migrate flat DeximDB state.json → target {version, registrations}."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def migrate(data: dict) -> dict:
    if "registrations" in data:
        out = dict(data)
        out.setdefault("version", 1)
        return out
    regs = {}
    for user, meta in data.items():
        if not isinstance(meta, dict):
            continue
        if not meta.get("ip"):
            continue
        regs[user] = {
            "ip": meta["ip"],
            "updated_at": meta.get("updated_at"),
        }
    return {"version": 1, "registrations": regs}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--output", type=Path, required=True)
    args = p.parse_args()
    data = json.loads(args.input.read_text(encoding="utf-8"))
    out = migrate(data)
    args.output.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "users": len(out["registrations"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
