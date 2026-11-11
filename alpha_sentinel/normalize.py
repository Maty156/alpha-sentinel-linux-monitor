"""Event normalization - convert Windows event XML to normalized Event."""

import re
import xml.etree.ElementTree as ET
from typing import Optional, Dict, Any
from alpha_sentinel.models import Event


NS = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}


def get_field(xml_elem: ET.Element, name: str) -> Optional[str]:
    """Extract field value from event XML."""
    elem = xml_elem.find(f".//ns:Data[@Name='{name}']", NS)
    if elem is not None and elem.text:
        return elem.text.strip()
    return None


def convert_to_account_name(value: str) -> str:
    """Convert DN to simple account name.
    
    e.g. 'CN=userA,CN=Users,DC=corp,DC=local' -> 'userA'
    """
    if not value:
        return value
    import re
    match = re.match(r'^\s*CN\s*=\s*([^,]+)', value)
    if match:
        return match.group(1).strip()
    return value


def _find_with_namespace(root: ET.Element, path: str) -> Optional[ET.Element]:
    """Find element trying both with and without namespace."""
    # Try with namespace first
    result = root.find(path, NS)
    if result is not None:
        return result
    # Try without namespace (for extracted events that lost namespace)
    path_no_ns = path.replace("ns:", "")
    return root.find(path_no_ns)


def _findall_with_namespace(root: ET.Element, path: str) -> list:
    """Find all elements trying both with and without namespace."""
    result = root.findall(path, NS)
    if result:
        return result
    path_no_ns = path.replace("ns:", "")
    return root.findall(path_no_ns)


_ACCOUNT_FIELD = {
    **{i: "TargetUserName" for i in ("4624", "4625", "4720", "4722", "4724", "4725", "4726",
                                    "4738", "4740", "4741", "4742", "4794", "4768", "4769",
                                    "4771", "4776")},
    **{i: "MemberName" for i in ("4728", "4729", "4732", "4733", "4756")},
    **{i: "SubjectUserName" for i in ("4688", "4672", "4648", "5136")},
    "4104": "User",
}
_IP_EVENTS = {"4625", "4624", "4768", "4769", "4771"}


def _priv_list(value: Optional[str]) -> Optional[str]:
    """4672 PrivilegeList is newline/tab separated; the rules expect a comma list."""
    if not value:
        return None
    return ",".join(p.strip() for p in re.split(r"[\r\n\t,]+", value) if p.strip())


def normalize_windows_event(xml_str: str) -> Optional[Event]:
    """
    Convert Windows event XML to normalized Event.
    Returns None if event cannot be parsed.
    """
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    # Try with namespace first, then without
    system = _find_with_namespace(root, "ns:System")
    if system is None:
        return None

    event_id_elem = _find_with_namespace(system, "ns:EventID")
    if event_id_elem is None:
        return None

    event_id = event_id_elem.text

    # Extract timestamp
    time_elem = _find_with_namespace(system, "ns:TimeCreated")
    timestamp = time_elem.get("SystemTime") if time_elem is not None else ""

    # Extract computer name
    comp_elem = _find_with_namespace(system, "ns:Computer")
    hostname = comp_elem.text if comp_elem is not None else ""

    event_data = _find_with_namespace(root, "ns:EventData")

    fields: Dict[str, Any] = {
        "eventId": event_id,
        "timestamp": timestamp,
        "hostname": hostname,
        "channel": "Security",  # default
    }

    if event_data is not None:
        for data in _findall_with_namespace(event_data, "ns:Data"):
            name = data.get("Name")
            value = data.text
            if name and value:
                fields[name] = value.strip()

    # accountName / sourceIp follow the PowerShell normalizer per event ID. Event
    # IDs that name no account (1100/1102/4616/4657/4698/4719/4946-4950/Defender)
    # deliberately leave it empty - guessing "TargetUserName or SubjectUserName"
    # for them put the wrong principal (often SYSTEM) on the alert.
    account_field = _ACCOUNT_FIELD.get(event_id)
    if event_id in ("4697", "7045"):
        account_name = fields.get("SubjectUserName") or fields.get("AccountName") or ""
    elif account_field:
        account_name = fields.get(account_field) or ""
    else:
        account_name = ""
    source_ip = fields.get("IpAddress") or "" if event_id in _IP_EVENTS else ""

    event = Event(
        eventId=event_id,
        hostname=hostname,
        accountName=account_name,
        sourceIp=source_ip,
        timestamp=timestamp,
        channel="Security",
        logonType=fields.get("LogonType"),
        statusCode=fields.get("Status"),
        targetUserName=fields.get("TargetUserName"),
        subjectUserName=fields.get("SubjectUserName"),
        targetUserSid=fields.get("TargetUserSid"),
        workstationName=fields.get("WorkstationName") or fields.get("Workstation"),
        serviceName=fields.get("ServiceName"),
        encryptionType=fields.get("TicketEncryptionType"),
        status=fields.get("Status"),
        preAuthType=fields.get("PreAuthType"),
        ticketOptions=fields.get("TicketOptions"),
        objectType=fields.get("ObjectType"),
        objectName=fields.get("ObjectName"),
        properties=fields.get("Properties"),
        accessMask=fields.get("AccessMask"),
        attributeLDAPDisplayName=fields.get("AttributeLDAPDisplayName"),
        attributeValue=fields.get("AttributeValue"),
        operationType=fields.get("OperationType"),
        operationCount=fields.get("OperationCount"),
        scriptBlockText=fields.get("Message") or fields.get("ScriptBlockText"),
        processId=fields.get("ProcessId"),
        parentProcessName=fields.get("ParentProcessName"),
        parentProcessId=fields.get("ParentProcessId"),
        newProcessName=fields.get("NewProcessName"),
        commandLine=fields.get("CommandLine"),
        tokenElevationType=fields.get("TokenElevationType"),
        logonId=fields.get("LogonId"),
        user=account_name,
        authenticationPackageName=fields.get("AuthenticationPackageName"),
        keyLength=fields.get("KeyLength"),
        # Group membership / account management fields
        memberName=convert_to_account_name(fields.get("MemberName")) if fields.get("MemberName") else None,
        memberSid=fields.get("MemberSid"),
        targetDomainName=fields.get("TargetDomainName"),
        subjectDomainName=fields.get("SubjectDomainName"),
        # DSRM / account control
        oldUserAccountControl=fields.get("OldUacValue"),
        newUserAccountControl=fields.get("NewUacValue"),
        # Process creation
        imagePath=fields.get("ImagePath"),
        serviceFileName=fields.get("ServiceFileName"),
        # Firewall
        settingType=fields.get("SettingType"),
        settingValue=fields.get("SettingValue"),
        profileChanged=fields.get("ProfileChanged"),
        ruleName=fields.get("RuleName"),
        # Defender
        eventSource=fields.get("EventSource"),
        # System time
        newTime=fields.get("NewTime"),
        subcategory=fields.get("SubcategoryId") or fields.get("CategoryId"),
        objectClass=fields.get("ObjectClass"),
        privilegeList=_priv_list(fields.get("PrivilegeList")),
        processName=fields.get("ProcessName"),
        targetServerName=fields.get("TargetServerName"),
        taskName=fields.get("TaskName"),
        registryKey=fields.get("ObjectName") if event_id == "4657" else None,
        registryValueName=fields.get("ObjectValueName"),
        targetGroup=fields.get("TargetUserName") if event_id in ("4728", "4732", "4756") else None,
        # For Linux (placeholder)
        command=None,
        exe=None,
        auditd_type=None,
        # Additional fields
        extra=fields,
    )

    return event


def normalize_linux_event(line: str) -> Optional[Event]:
    """Normalize a Linux event line into an Event.

    Supports:
    - /var/log/auth.log (SSH/sudo authentication logs)
    - journalctl -o cat output (systemd journal)
    """
    line = line.strip()
    if not line:
        return None

    # Try auth.log normalizer first
    try:
        from alpha_sentinel.normalize_linux import normalize_auth_log_line
        event = normalize_auth_log_line(line)
        if event:
            event.osFamily = "linux"
            return event
    except ImportError:
        pass

    # Try journal normalizer
    try:
        from alpha_sentinel.normalize_linux import normalize_journal_line
        event = normalize_journal_line(line)
        if event:
            event.osFamily = "linux"
            return event
    except ImportError:
        pass

    return None


def normalize_event(xml_or_line: str, platform: str = "windows") -> Optional[Event]:
    """Route to appropriate normalizer based on platform."""
    if platform == "windows":
        return normalize_windows_event(xml_or_line)
    elif platform == "linux":
        return normalize_linux_event(xml_or_line)
    return None