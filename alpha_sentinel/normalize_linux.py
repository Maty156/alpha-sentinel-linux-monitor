"""Linux event normalization helper functions."""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from alpha_sentinel.models import Event

_ISO_PREFIX = re.compile(r"^(\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+")
_SYSLOG_PREFIX = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_IP = r"([0-9A-Fa-f:.]+)"  # IPv4 or IPv6


def _split_prefix(line: str) -> Tuple[str, str, str]:
    """Return (iso_timestamp, hostname, message) for an auth.log / syslog line.

    Handles both rsyslog formats: ISO-8601 ("2026-10-29T18:32:01+03:00 host ...")
    and classic ("Oct 29 18:32:01 host ..." - no year, so the current year is
    used, rolling back one year if that would put the line in the future).
    A line with no recognisable prefix gets an empty timestamp; the collector
    stamps it with the time it was read.
    """
    m = _ISO_PREFIX.match(line)
    if m:
        return m.group(1), m.group(2), line[m.end():]
    m = _SYSLOG_PREFIX.match(line)
    if m:
        now = datetime.now(timezone.utc)
        mon, day, hms, host = _MONTHS[m.group(1)], int(m.group(2)), m.group(3), m.group(4)
        try:
            dt = datetime.strptime(f"{now.year} {mon} {day} {hms}", "%Y %m %d %H:%M:%S").replace(tzinfo=timezone.utc)
            if dt - now > timedelta(days=1):
                dt = dt.replace(year=now.year - 1)
            return dt.isoformat(), host, line[m.end():]
        except ValueError:
            pass
    return "", "linux-host", line


def _failed_login(msg: str):
    """Parse 'Failed password for [invalid user] NAME from IP port N' -> (user, ip)."""
    m = re.search(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from " + _IP, msg)
    if not m:
        m = re.search(r"Invalid user (\S+) from " + _IP, msg)
    return (m.group(1), m.group(2)) if m else None


def _accepted_login(msg: str):
    m = re.search(r"Accepted (password|publickey|keyboard-interactive/pam) for (\S+) from " + _IP, msg)
    return (m.group(1), m.group(2), m.group(3)) if m else None


def _build(line: str, channel: str, has_prefix: bool) -> Optional[Event]:
    line = line.strip()
    if not line:
        return None
    ts, host, msg = _split_prefix(line) if has_prefix else ("", "linux-host", line)

    failed = _failed_login(msg)
    if failed:
        account, ip = failed
        return Event(eventId="4625", hostname=host, accountName=account, sourceIp=ip, timestamp=ts,
                     channel=channel, logonType="ssh", targetUserName=account,
                     command="Failed SSH login", exe="sshd", osFamily="linux")

    accepted = _accepted_login(msg)
    if accepted:
        method, account, ip = accepted
        return Event(eventId="4624", hostname=host, accountName=account, sourceIp=ip, timestamp=ts,
                     channel=channel, logonType="ssh", targetUserName=account,
                     command=f"Successful SSH login ({method})", exe="sshd", osFamily="linux")

    if "COMMAND=" in msg:
        user_m = re.search(r"sudo:\s+(\S+)\s*:", msg)
        cmd_m = re.search(r"COMMAND=(.+)", msg)
        account = user_m.group(1) if user_m else "unknown"
        command = cmd_m.group(1).strip() if cmd_m else ""
        return Event(eventId="4672", hostname=host, accountName=account, sourceIp="", timestamp=ts,
                     channel=channel, logonType="sudo", targetUserName=account,
                     command=command, commandLine=command, exe="sudo", osFamily="linux")
    return None


def normalize_auth_log_line(line: str) -> Optional[Event]:
    """Normalize a /var/log/auth.log (or syslog) line into an Event."""
    return _build(line, "auth", has_prefix=True)


def normalize_journal_line(line: str) -> Optional[Event]:
    """Normalize a `journalctl -o cat` line (message only, no timestamp/host)."""
    return _build(line, "journal", has_prefix=False)
