"""Computer account abuse / GPO admin object / Special privileges detection."""

from typing import Optional
from alpha_sentinel.engine import Engine, parse_event_time
from alpha_sentinel.models import Event, Alert
from datetime import datetime, timezone
import re


def evaluate_4741_4742(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Events 4741 (computer created) / 4742 (computer changed).
    
    Alert on: non-admin creating computer accounts, or delegation attribute changes.
    """
    account = event.accountName or event.targetUserName or ""  # the computer account
    subject = event.subjectUserName or ""
    props = event.properties or ""
    
    # Skip if subject is machine account or system account
    system_accounts = ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON')
    if subject.upper() in system_accounts or subject.endswith('$'):
        return None
    
    # Check if subject is admin
    is_admin = any(p in subject.lower() for p in ['admin', 'da_', 'root', 'administrator'])
    is_delegation_change = 'msDS-AllowedToActOnBehalfOfOtherIdentity' in props
    
    if not is_admin or is_delegation_change:
        sev = 'High' if is_delegation_change else 'Medium'
        action = 'created' if event.eventId == '4741' else 'modified'
        desc = f"Computer account \"{account}\" was {action} by \"{subject}\"."
        if is_delegation_change:
            desc += " Delegation attribute (msDS-AllowedToActOnBehalfOfOtherIdentity) was modified - potential RBCD attack."
        elif not is_admin:
            desc += " The creator is not a privileged account - unauthorized computer account creation."
        
        ent = f"{account}|{subject}"
        
        evt_time = parse_event_time(event)
        
        if not engine.should_dedupe('computer_account_abuse', ent, 30, sev, desc):
            return engine.new_alert('computer_account_abuse', desc, sev, event, f'computer_account_abuse|{ent}', evt_time)
    
    return None


def evaluate_5136(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 5136 (Directory Service Changes).
    
    Detects changes to:
    - Group Policy objects (groupPolicyContainer)
    - GPO links (gPLink)
    - AdminSDHolder nTSecurityDescriptor
    - sIDHistory attribute (Golden Ticket indicator)
    """
    obj_class = event.objectClass or event.objectType or ""
    attr_name = event.attributeLDAPDisplayName or ""
    attr_value = event.attributeValue or ""
    subject = event.subjectUserName or ""
    account = event.accountName or event.targetUserName or ""
    obj_name = event.objectName or ""
    
    # Skip machine accounts
    if subject.endswith('$') or account.endswith('$'):
        return None
    
    evt_time = parse_event_time(event)
    
    is_critical = False
    desc = ""
    
    # Check for GPO object modification
    if 'grouppolicycontainer' in obj_class.lower():
        desc = f"Group Policy Object \"{obj_name}\" was modified by \"{subject}\" (attribute: {attr_name})."
    # Check for GPO link modification
    elif attr_name.lower() == 'gplink':
        desc = f"GPO link on \"{obj_name}\" was changed by \"{subject}\" - potential GPO-based persistence or privilege escalation."
    # Check for AdminSDHolder modification
    elif attr_name.lower() == 'ntsecuritydescriptor' and 'adminsdholder' in obj_name.lower():
        is_critical = True
        desc = f"AdminSDHolder nTSecurityDescriptor was modified by \"{subject}\" - this controls the default security descriptor for all protected admin groups (SDProp). Backdoor ACLs may have been added."
    # Check for sIDHistory modification
    elif attr_name.lower() == 'sidhistory':
        is_critical = True
        desc = f"sIDHistory was modified on account \"{account}\" by \"{subject}\" - this is a Golden Ticket / SID History injection indicator."
    else:
        return None
    
    sev = 'Critical' if is_critical else 'High'
    ent = f"{account}|{attr_name}"
    
    if not engine.should_dedupe('gpo_or_admin_object_modified', ent, 30, sev, desc):
        return engine.new_alert('gpo_or_admin_object_modified', desc, sev, event, f'gpo_or_admin_object_modified|{ent}', evt_time)
    
    return None


def evaluate_4672(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4672 (Special Privileges Assigned).
    
    Logon was granted sensitive privileges. Used to inventory administrative sessions.
    """
    account = event.accountName or ""
    
    # Skip system accounts
    system_accounts = ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON')
    if account.upper() in system_accounts:
        return None
    
    evt_time = parse_event_time(event)
    
    priv_list = event.privilegeList or ""
    privs = [p.strip() for p in priv_list.split(',') if p.strip()]
    
    sensitive_privs = [
        'sedebugprivilege', 'setcbprivilege', 'sebackupprivilege', 'serestoreprivilege',
        'seloaddriverprivilege', 'setakeownershipprivilege', 'seimpersonateprivilege',
        'seassignprimarytokenprivilege', 'secreatetokenprivilege', 'sedenydebugprivilege'
    ]
    
    sensitive = [p for p in privs if p.lower() in sensitive_privs]
    sev = 'Medium' if sensitive else 'Low'
    note = f", including {', '.join(sensitive)}" if sensitive else ""
    
    desc = f"Logon by \"{account}\" on {event.hostname} was granted {len(privs)} privilege(s){note}."
    
    if not engine.should_dedupe('special_privileges_assigned', account, 60, sev, desc):
        return engine.new_alert('special_privileges_assigned', desc, sev, event, f'special_privileges_assigned|{account}', evt_time)
    
    return None