"""Log-source readiness checks (the Linux counterpart of the Windows audit-policy preflight).

A detection can only fire if the log it reads exists, is readable by this process and
actually records the event. Each check returns a state:
  ok          - will work
  blind       - cannot work as configured (file missing / unreadable / journal unusable)
  unverified  - could not be determined
and, when not ok, the command that fixes it. Nothing here changes the system.
"""

import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List

AUTH_CANDIDATES = ["/var/log/auth.log", "/var/log/secure"]


def _file_check(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"state": "blind", "detail": "file does not exist",
                "fix": "install/enable rsyslog (sudo apt install rsyslog) or point log_sources at the right file"}
    if not os.access(path, os.R_OK):
        group = "adm"
        return {"state": "blind", "detail": "file exists but this process cannot read it",
                "fix": f"run as root, or: sudo usermod -aG {group} $USER   (then log in again)"}
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    return {"state": "ok", "detail": f"readable, {size} bytes"}


def _journal_check(units: List[str]) -> Dict[str, Any]:
    if not shutil.which("journalctl"):
        return {"state": "blind", "detail": "journalctl not found (no systemd)", "fix": "use a syslog source instead"}
    try:
        r = subprocess.run(["journalctl", "-n", "1", "--no-pager", "-o", "cat"] + [a for u in units for a in ("-u", u)],
                           capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"state": "unverified", "detail": f"could not run journalctl: {exc}"}
    text = (r.stdout + r.stderr).lower()
    if "no journal files were opened" in text or "not seeing messages" in text or "permission" in text:
        return {"state": "blind", "detail": "the journal exists but this user may not read it",
                "fix": "run as root, or: sudo usermod -aG systemd-journal,adm $USER   (then log in again)"}
    if r.returncode != 0:
        return {"state": "unverified", "detail": (r.stderr or "journalctl failed").strip()[:120]}
    return {"state": "ok", "detail": "journal readable"}


def _sshd_loglevel() -> Dict[str, Any]:
    """SSH logins are only recorded at INFO or above (QUIET/FATAL/ERROR hide failed logins)."""
    cfg = "/etc/ssh/sshd_config"
    if not os.access(cfg, os.R_OK):
        return {"state": "unverified", "detail": f"{cfg} not readable"}
    level = "INFO"  # sshd default
    try:
        with open(cfg, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(r"\s*LogLevel\s+(\S+)", line, re.I)
                if m:
                    level = m.group(1).upper()
    except OSError:
        return {"state": "unverified", "detail": f"could not read {cfg}"}
    if level in ("QUIET", "FATAL", "ERROR"):
        return {"state": "blind", "detail": f"LogLevel {level} hides failed and accepted logins",
                "fix": "set 'LogLevel INFO' in /etc/ssh/sshd_config and run: sudo systemctl reload ssh"}
    return {"state": "ok", "detail": f"LogLevel {level}"}


def check_log_sources(sources: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for src in sources:
        kind = src.get("type")
        if kind in ("syslog", "auditd"):
            path = src.get("path", "/var/log/auth.log")
            rows.append({"name": os.path.basename(path), "type": kind, "target": path, **_file_check(path)})
        elif kind == "journal":
            units = src.get("units", ["sshd", "sudo"])
            rows.append({"name": "systemd journal", "type": kind, "target": ", ".join(units), **_journal_check(units)})
    if any(r["type"] == "journal" and r["state"] == "ok" for r in rows):
        for r in rows:
            if r["type"] in ("syslog", "auditd") and r["state"] == "blind" and r["detail"] == "file does not exist":
                r["state"], r["detail"] = "ok", "not present - not needed, the systemd journal is being read instead"
                r.pop("fix", None)
    rows.append({"name": "sshd logging", "type": "setting", "target": "/etc/ssh/sshd_config", **_sshd_loglevel()})
    counts = {s: sum(1 for r in rows if r["state"] == s) for s in ("ok", "blind", "unverified")}
    return {"checkedAt": datetime.now(timezone.utc).isoformat(), "sources": rows, "counts": counts,
            "elevated": hasattr(os, "geteuid") and os.geteuid() == 0}
