"""Linux System rule evaluators."""

import re
from typing import Optional
from alpha_sentinel.engine import Engine, _parse_timestamp
from alpha_sentinel.models import Event, Alert


def _get_account_from_event(event: Event) -> str:
    """Extract target account from event."""
    return event.targetUserName or event.accountName or ""


def _get_command_from_event(event: Event) -> str:
    """Extract command from event."""
    return event.command or event.commandLine or ""


def _get_event_time(event: Event):
    """Get parsed datetime from event timestamp."""
    return _parse_timestamp(event.timestamp)


def evaluate_sudo_privilege_escalation(engine: Engine, event: Event) -> Optional[Alert]:
    """Detect sudo usage for privilege escalation.
    
    Rule: Sudo command execution by non-root user
    MITRE: T1548.003 (Create or Modify System Process: Sudo)
    """
    if event.eventId != "4672" or event.logonType != "sudo":
        return None

    account = _get_account_from_event(event)
    if not account:
        return None

    # Skip root user (already root, not escalation)
    if account.lower() == "root":
        return None

    command = _get_command_from_event(event)
    
    # Check for dangerous commands
    dangerous_commands = ["chmod", "chown", "bash -c", "sh -c", "wget", "curl", "python", "perl"]
    is_dangerous = any(cmd in command for cmd in dangerous_commands)
    
    severity = "High" if is_dangerous else "Medium"

    entity = f"{account}|{command[:100]}"
    if engine.should_dedupe("sudo_privilege_escalation", entity, minutes=15, new_severity=severity):
        return None

    return engine.new_alert(
        rule_key="sudo_privilege_escalation",
        description=f"Sudo privilege escalation by {account}: {command}",
        severity=severity,
        event=event,
        dedupe_key=f"sudo_privilege_escalation|{entity}",
        event_time=_get_event_time(event)
    )


def evaluate_user_account_changed(engine: Engine, event: Event) -> Optional[Alert]:
    """Detect user account add/disable/modify.
    
    Rule: useradd, usermod, userdel execution
    MITRE: T1098 (Account Manipulation)
    """
    # Check for user management commands
    command = _get_command_from_event(event).lower()
    account_mgmt_cmds = {"useradd", "usermod", "userdel", "adduser", "deluser", "passwd",
                         "chpasswd", "groupadd", "groupmod", "groupdel", "gpasswd", "chage"}
    tokens = command.split()
    # the program is the first token, or the one after sudo/env-style prefixes
    program = next((t.rsplit("/", 1)[-1] for t in tokens if t not in ("sudo", "env", "-u", "-E")), "")
    if program not in account_mgmt_cmds:
        return None

    account = _get_account_from_event(event)
    
    if engine.should_dedupe("user_account_changed", account or "unknown", minutes=30):
        return None

    return engine.new_alert(
        rule_key="user_account_changed",
        description=f"User account modification detected: {command}",
        severity="High",
        event=event,
        dedupe_key=f"user_account_changed|{account}",
        event_time=_get_event_time(event)
    )


def evaluate_suspicious_command_execution(engine: Engine, event: Event) -> Optional[Alert]:
    """Detect suspicious shell commands.
    
    Rule: curl|wget|bash -c|base64 -d|echo | bash patterns
    MITRE: T1059 (Command and Scripting Interpreter)
    """
    command = _get_command_from_event(event).lower()
    
    if not command:
        return None

    # Suspicious patterns - use regex for more flexible matching
    suspicious_patterns = [
        (r"curl\s+.*\|\s*bash", "curl piped to bash"),
        (r"wget\s+.*\|\s*bash", "wget piped to bash"),
        (r"bash\s+-c", "bash -c"),
        (r"(?<![\w-])sh\s+-c", "sh -c"),
        (r"base64\s+-d", "base64 decode"),
        (r"base64\s+-D", "base64 decode (BSD)"),
        (r"echo\s+.*\|\s*bash", "echo piped to bash"),
        (r"echo\s+.*\|\s*sh", "echo piped to sh"),
        (r"\beval\s+", "eval"),
        (r"python\s+-c", "python -c"),
        (r"perl\s+-e", "perl -e"),
    ]
    
    matched = None
    for pattern, desc in suspicious_patterns:
        if re.search(pattern, command):
            matched = desc
            break
    
    if not matched:
        return None

    account = _get_account_from_event(event)
    
    entity = f"{account}|{command[:100]}"
    if engine.should_dedupe("suspicious_command_execution", entity, minutes=30):
        return None

    return engine.new_alert(
        rule_key="suspicious_command_execution",
        description=f"Suspicious command execution by {account}: {matched} - {command[:100]}",
        severity="High",
        event=event,
        dedupe_key=f"suspicious_command_execution|{entity}",
        event_time=_get_event_time(event)
    )


def evaluate_cron_or_systemd_persistence(engine: Engine, event: Event) -> Optional[Alert]:
    """Detect persistence mechanisms via cron/systemd.
    
    Rule: New cron jobs or systemd units created/modified
    MITRE: T1053.003 (Cron)
    """
    command = _get_command_from_event(event).lower()

    persistence_patterns = [
        r"\bcrontab\s+(?!-l\b)(-e|-r|-u\s+\S+\s+-e|\S+)",        # crontab -e / crontab file (not -l)
        r"(/etc/cron\.\w+|/etc/cron\.d|/etc/crontab|/var/spool/cron)",  # direct writes to cron dirs
        r"\bsystemctl\s+(enable|edit|link|preset)\b",                  # enabling / creating units
        r"(/etc/systemd/system|/lib/systemd/system|/usr/lib/systemd/system)/\S+\.(service|timer)",
    ]
    if not any(re.search(pat, command) for pat in persistence_patterns):
        return None

    account = _get_account_from_event(event)
    
    if engine.should_dedupe("cron_or_systemd_persistence", account or "unknown", minutes=60):
        return None

    return engine.new_alert(
        rule_key="cron_or_systemd_persistence",
        description=f"Persistence mechanism modified by {account}: {command[:100]}",
        severity="Critical",
        event=event,
        dedupe_key=f"cron_or_systemd_persistence|{account}",
        event_time=_get_event_time(event)
    )


def evaluate_sshd_config_modified(engine: Engine, event: Event) -> Optional[Alert]:
    """Detect sshd_config modification.
    
    Rule: /etc/ssh/sshd_config modified (auditd event)
    MITRE: T1562.004 (Impair Defenses: Disable or Modify System Firewall)
    """
    command = _get_command_from_event(event).lower()
    exe = (event.exe or "").lower()
    
    # Check for sshd_config modification
    if "sshd_config" not in command and "sshd_config" not in exe:
        return None

    account = _get_account_from_event(event)
    
    if engine.should_dedupe("sshd_config_modified", account or "unknown", minutes=60):
        return None

    return engine.new_alert(
        rule_key="sshd_config_modified",
        description=f"SSHD configuration modified by {account}",
        severity="High",
        event=event,
        dedupe_key=f"sshd_config_modified|{account}",
        event_time=_get_event_time(event)
    )


def evaluate_ssh_authorized_keys_modified(engine: Engine, event: Event) -> Optional[Alert]:
    """Detect SSH authorized_keys modification.
    
    Rule: ~/.ssh/authorized_keys written to (auditd event)
    MITRE: T1098.004 (Account Manipulation: SSH Authorized Keys)
    """
    command = _get_command_from_event(event).lower()
    
    # Check for authorized_keys modification
    if "authorized_keys" not in command:
        return None

    account = _get_account_from_event(event)
    
    if engine.should_dedupe("ssh_authorized_keys_modified", account or "unknown", minutes=60):
        return None

    return engine.new_alert(
        rule_key="ssh_authorized_keys_modified",
        description=f"SSH authorized_keys modified by {account}",
        severity="Critical",
        event=event,
        dedupe_key=f"ssh_authorized_keys_modified|{account}",
        event_time=_get_event_time(event)
    )