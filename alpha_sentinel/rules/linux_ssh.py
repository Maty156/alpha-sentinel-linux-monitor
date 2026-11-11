"""Linux SSH rule evaluators."""

from datetime import timedelta
from typing import Optional
from alpha_sentinel.engine import Engine, _parse_timestamp
from alpha_sentinel.models import Event, Alert


def _get_ip_from_event(event: Event) -> str:
    """Extract source IP from event."""
    return event.sourceIp or ""


def _get_account_from_event(event: Event) -> str:
    """Extract target account from event."""
    return event.targetUserName or event.accountName or ""


def _get_event_time(event: Event):
    """Get parsed datetime from event timestamp."""
    return _parse_timestamp(event.timestamp)


# ==============================
# SSH Brute Force Detection
# Maps to Windows Event 4625 (Failed Logon)
# ==============================

def evaluate_ssh_bruteforce(engine: Engine, event: Event) -> Optional[Alert]:
    """Detect repeated failed SSH logins from same IP.
    
    Rule: 5+ failed SSH logins from same IP within 5 minutes
    MITRE: T1110.001 (Password Spraying)
    """
    if event.eventId != "4625" or event.logonType != "ssh":
        return None

    source_ip = _get_ip_from_event(event)
    if not source_ip:
        return None

    event_time = _get_event_time(event)

    # Add hit to rolling window (5 minutes)
    window = engine.add_window_hit(
        rule_key="ssh_bruteforce",
        bucket=source_ip,
        value=event.targetUserName,
        minutes=5,
        event_time=event_time
    )

    # Count total attempts in window (not distinct accounts)
    total_attempts = len(window)
    
    if total_attempts >= 5:
        # Check dedupe
        if engine.should_dedupe("ssh_bruteforce", source_ip, minutes=15):
            return None
        
        return engine.new_alert(
            rule_key="ssh_bruteforce",
            description=f"SSH brute force detected: {total_attempts} failed attempts from {source_ip}",
            severity="High",
            event=event,
            dedupe_key=f"ssh_bruteforce|{source_ip}",
            event_time=event_time
        )

    return None


# ==============================
# SSH Success After Failures
# Maps to Windows Event 4624 (Successful Logon) 
# ==============================

def evaluate_ssh_success_after_failures(engine: Engine, event: Event) -> Optional[Alert]:
    """Detect successful SSH login after multiple failures from same IP.
    
    Rule: Successful SSH login from IP that had 3+ failed attempts in last 10 min
    MITRE: T1110.001
    """
    if event.eventId != "4624" or event.logonType != "ssh":
        return None

    source_ip = _get_ip_from_event(event)
    if not source_ip:
        return None

    event_time = _get_event_time(event)

    # Check if we had recent brute force hits from this IP
    key = f"ssh_bruteforce|{source_ip}"
    cutoff = event_time - timedelta(minutes=10)
    recent = [h for h in engine.windows.get(key, []) if cutoff < h["time"] <= event_time]
    if recent:
        failed_attempts = len(recent)
        if failed_attempts >= 3:
            if engine.should_dedupe("ssh_success_after_failures", source_ip, minutes=15):
                return None
            
            return engine.new_alert(
                rule_key="ssh_success_after_failures",
                description=f"Successful SSH login after {failed_attempts} failed attempts from {source_ip}",
                severity="Critical",
                event=event,
                dedupe_key=f"ssh_success_after_failures|{source_ip}",
                event_time=event_time
            )

    return None


# ==============================
# Root SSH Login Detection
# ==============================

def evaluate_root_ssh_login(engine: Engine, event: Event) -> Optional[Alert]:
    """Detect direct root SSH login.
    
    Rule: Successful SSH login as root user
    MITRE: T1078 (Valid Accounts)
    """
    if event.eventId != "4624" or event.logonType != "ssh":
        return None

    account = _get_account_from_event(event).lower()
    if account != "root":
        return None

    source_ip = _get_ip_from_event(event)
    event_time = _get_event_time(event)
    
    if engine.should_dedupe("root_ssh_login", source_ip or "unknown", minutes=60):
        return None

    return engine.new_alert(
        rule_key="root_ssh_login",
        description=f"Direct root SSH login from {source_ip}",
        severity="Critical",
        event=event,
        dedupe_key=f"root_ssh_login|{source_ip}",
        event_time=event_time
    )


# ==============================
# SSH Key-based Auth Success
# ==============================

def evaluate_ssh_key_auth(engine: Engine, event: Event) -> Optional[Alert]:
    """Detect SSH key-based authentication (potential lateral movement).
    
    Rule: Successful SSH login using public key (not password)
    MITRE: T1078.004 (Valid Accounts: SSH Keys)
    """
    if event.eventId != "4624" or event.logonType != "ssh":
        return None

    # Check if command mentions publickey
    cmd = (event.command or "").lower()
    if "publickey" not in cmd and "ssh-key" not in cmd:
        return None

    source_ip = _get_ip_from_event(event)
    account = _get_account_from_event(event)
    event_time = _get_event_time(event)
    
    if engine.should_dedupe("ssh_key_auth", f"{source_ip}|{account}", minutes=60):
        return None

    return engine.new_alert(
        rule_key="ssh_key_auth",
        description=f"SSH key-based login for {account} from {source_ip}",
        severity="Medium",
        event=event,
        dedupe_key=f"ssh_key_auth|{source_ip}|{account}",
        event_time=event_time
    )