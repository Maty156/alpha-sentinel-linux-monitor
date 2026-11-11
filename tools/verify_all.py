#!/usr/bin/env python3
"""One command to check the port: unit tests + strict oracle replay. Exit 0 = all good.

    python tools/verify_all.py
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(label, cmd):
    print(f"\n=== {label} ===", flush=True)
    rc = subprocess.run(cmd, cwd=ROOT).returncode
    print(f"-> {'OK' if rc == 0 else 'FAILED'}")
    return rc == 0


def main():
    results = [
        run("pytest", [sys.executable, "-m", "pytest", "-q"]),
        run("oracle replay (rule, severity, account, host, alert count)", [sys.executable, "tools/diff_replay.py"]),
    ]
    print("\nALL CHECKS PASSED" if all(results) else "\nSOME CHECKS FAILED")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
