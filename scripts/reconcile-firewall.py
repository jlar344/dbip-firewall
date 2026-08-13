#!/usr/bin/env python3
"""Wrapper: call installed dbip-firewall reconcile (report-only)."""
from __future__ import annotations

import json
import subprocess
import sys


def main() -> int:
    bin_path = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/sbin/dbip-firewall"
    p = subprocess.run([bin_path, "reconcile"], text=True, capture_output=True)
    sys.stdout.write(p.stdout)
    sys.stderr.write(p.stderr)
    if p.returncode != 0:
        return p.returncode
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        return 0
    findings = data.get("findings") or []
    print(f"# findings: {len(findings)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
