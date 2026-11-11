"""Rule metadata (title, severity, MITRE, remediation) - generated from the
PowerShell $RuleMeta table in AlphaSentinel.ps1 so both ports stay in sync."""

WINDOWS_RULE_META = {
    "password_spraying": {
        "title": "Suspicious Password Spraying Activity",
        "severity": "High",
        "event_ids": [
            "4625"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1110.003",
        "mitre_name": "Brute Force: Password Spraying",
        "category": "Credential Access",
        "description": "One source tried a small number of passwords across many different accounts - the classic spray pattern that stays under per-account lockout thresholds.",
        "remediation": "Enable an account lockout threshold, block the source IP at the perimeter, and move the targeted accounts to smart-card or MFA-backed authentication."
    },
    "brute_force_single_account": {
        "title": "Repeated Failed Logons Against One Account",
        "severity": "Medium",
        "event_ids": [
            "4625"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1110.001",
        "mitre_name": "Brute Force: Password Guessing",
        "category": "Credential Access",
        "description": "A single account accumulated a high number of failed logons in a short window - concentrated guessing rather than a broad spray.",
        "remediation": "Confirm the account is not locked out while an attack continues, check whether the source is internal, and enforce lockout plus MFA on the account."
    },
    "kerberos_preauth_spraying": {
        "title": "Kerberos Pre-Authentication Spraying",
        "severity": "High",
        "event_ids": [
            "4771"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1110.003",
        "mitre_name": "Brute Force: Password Spraying",
        "category": "Credential Access",
        "description": "Multiple accounts failed Kerberos pre-authentication from the same client address - spraying against the Kerberos AS instead of NTLM, which 4625-based rules miss.",
        "remediation": "Apply the same lockout and MFA hardening as for NTLM spraying, and monitor 4771 alongside 4625 - attackers switch protocols to dodge single-event-id rules."
    },
    "ntlm_failed_auth": {
        "title": "NTLM Authentication Failure Burst",
        "severity": "High",
        "event_ids": [
            "4776"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1110.001",
        "mitre_name": "Brute Force: Password Guessing",
        "category": "Credential Access",
        "description": "A workstation produced a burst of FAILED NTLM credential validations - either guessing locally from that host or relayed attempts to it. Only non-zero status codes count: 4776 also logs SUCCESSFUL validations (Status 0x0), which are normal NTLM traffic and are now ignored instead of being counted as a failure burst.",
        "remediation": "Isolate the source workstation, review its running processes for credential-access tooling, and work toward disabling NTLM where the environment allows it."
    },
    "account_lockout_storm": {
        "title": "Account Lockout Storm",
        "severity": "High",
        "event_ids": [
            "4740"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1110",
        "mitre_name": "Brute Force",
        "category": "Credential Access",
        "description": "Several distinct accounts locked out inside the same window - sprays that overshoot the lockout threshold leave this fingerprint behind.",
        "remediation": "Treat as an in-progress password spraying campaign: find and block the source, and raise the lockout observation window in your SIEM."
    },
    "privilege_escalation": {
        "title": "User Added to Privileged Group",
        "severity": "Critical",
        "event_ids": [
            "4728",
            "4732",
            "4756"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1078.002",
        "mitre_name": "Valid Accounts: Domain Accounts",
        "category": "Privilege Escalation",
        "description": "An account was added to a group that carries administrative rights over the domain or its member servers - a primary way an intruder converts a normal account into a lasting foothold.",
        "remediation": "Verify the change was an approved ticket, remove the membership if it was not, reset the added account password, and hunt for lateral movement from that account."
    },
    "account_created": {
        "title": "New Account Created",
        "severity": "High",
        "event_ids": [
            "4720"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1136.002",
        "mitre_name": "Create Account: Domain Account",
        "category": "Persistence",
        "description": "A new USER account was created. Computer accounts (names ending in $) are excluded - they are created every time a workstation or server joins the domain, which made this rule fire on routine provisioning. Attackers use throwaway user accounts as a persistence mechanism that survives password resets on the original victim account.",
        "remediation": "Confirm the account against your joiner/mover/leaver process, and disable it immediately if there is no matching request. Watch for it being added to a privileged group next."
    },
    "account_control_changed": {
        "title": "Account Security Flags Weakened",
        "severity": "High",
        "event_ids": [
            "4738"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1098",
        "mitre_name": "Account Manipulation",
        "category": "Defense Evasion",
        "description": "An account had a risky security flag turned ON. Only flags that actually CHANGED are considered (new value AND NOT old value), so editing an account that already carried the flag no longer fires. The risky transitions are do-not-require-Kerberos-pre-auth (AS-REP roastable), password-not-required, and clearing the Account-Disabled bit (re-enable).",
        "remediation": "Revert the flag. For \"do not require Kerberos pre-authentication\", treat it as credential theft prep: rotate the account password after clearing the flag."
    },
    "account_enabled_disabled": {
        "title": "Account Enabled or Disabled",
        "severity": "Medium",
        "event_ids": [
            "4722",
            "4725"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1098",
        "mitre_name": "Account Manipulation",
        "category": "Identity Abuse",
        "description": "An account was enabled or disabled. Re-enabling a dormant or terminated employee account is a common re-entry technique.",
        "remediation": "Check that the account belongs to an active employee and that the change came from an authorized administrator session."
    },
    "password_reset_by_admin": {
        "title": "Password Reset by an Administrator",
        "severity": "Medium",
        "event_ids": [
            "4724"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1098",
        "mitre_name": "Account Manipulation",
        "category": "Identity Abuse",
        "description": "An administrator reset another account password - legitimate for helpdesk, but also how an intruder takes over an account they cannot crack.",
        "remediation": "Confirm the reset against a helpdesk ticket, and verify the administrator session that performed it was not itself compromised."
    },
    "group_membership_removed": {
        "title": "Account Removed from Privileged Group",
        "severity": "Medium",
        "event_ids": [
            "4729",
            "4733"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1531",
        "mitre_name": "Account Access Removal",
        "category": "Impact",
        "description": "An account was removed from a privileged group. Beyond plain de-provisioning, this is used to lock the real incident responders out during an intrusion.",
        "remediation": "Verify the removal was authorized and that no legitimate administrator lost access unexpectedly during an active incident."
    },
    "account_deleted": {
        "title": "Account Deleted",
        "severity": "Medium",
        "event_ids": [
            "4726"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1531",
        "mitre_name": "Account Access Removal",
        "category": "Impact",
        "description": "An account was deleted. Used to clean up attacker-created accounts before an engagement ends, or to destroy a record of who had access.",
        "remediation": "Confirm the deletion matches an offboarding request, check whether the account was created recently (a sign it was attacker-owned), and review what it accessed."
    },
    "kerberoasting": {
        "title": "Kerberos Service Ticket Request (Kerberoasting)",
        "severity": "Medium",
        "event_ids": [
            "4769"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1558.003",
        "mitre_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "category": "Credential Access",
        "description": "A SUCCESSFUL service ticket request used weak RC4 (0x17) encryption for a user-owned service principal - that ticket is then cracked offline for the service account password. Machine accounts ($), krbtgt and failed requests are excluded. One ticket is Medium; three or more distinct service principals requested by the same account inside 10 minutes raises the alert to High.",
        "remediation": "Move service accounts to group-managed service accounts (gMSA) with AES keys, disable RC4 where possible, and rotate the targeted service account password."
    },
    "asrep_roasting": {
        "title": "AS-REP Roasting (No-Preauth Ticket Request)",
        "severity": "High",
        "event_ids": [
            "4768"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1558.004",
        "mitre_name": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
        "category": "Credential Access",
        "description": "A TGT was issued for an account with Kerberos pre-authentication disabled (PreAuthType 0). That response is encrypted with the account password hash and can be cracked offline, so a SINGLE successful request is enough to alert - the old rule waited for 3 hits on the same account and so missed a normal one-shot roast.",
        "remediation": "Turn \"Do not require Kerberos pre-authentication\" back on for the account, rotate its password, and report on any other account with pre-auth disabled."
    },
    "dcsync_replication": {
        "title": "Directory Replication Rights Used (DCSync)",
        "severity": "Critical",
        "event_ids": [
            "4662"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1003.006",
        "mitre_name": "OS Credential Dumping: DCSync",
        "category": "Credential Access",
        "description": "A NON-MACHINE account exercised Active Directory replication extended rights. On a real 4662 the right that was used is listed in the Properties field (ObjectType holds the object class), so the replication GUIDs are matched there. Domain controllers replicate as their machine account (ending in $) and are excluded - anything else is an attacker pulling password hashes with DCSync.",
        "remediation": "Treat as a confirmed compromise: identify the account and host, disable the account, rotate the KRBTGT password twice, and audit who holds replication rights."
    },
    "ldap_recon": {
        "title": "LDAP / SAMR Domain Enumeration",
        "severity": "Medium",
        "event_ids": [
            "4662",
            "5141"
        ],
        "dedupe_minutes": 30,
        "mitre_id": "T1018",
        "mitre_name": "Remote System Discovery / T1087 - Account Discovery",
        "category": "Discovery",
        "description": "A single source read a large number of directory objects in a short window - the fingerprint of enumeration tooling mapping users, groups and computers before an attack.",
        "remediation": "Restrict anonymous SAMR/LDAP access by GPO, and hunt the source host for BloodHound / SharpHound output and other reconnaissance tooling."
    },
    "suspicious_remote_logon": {
        "title": "Suspicious Remote Logon",
        "severity": "Medium",
        "event_ids": [
            "4624"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1021",
        "mitre_name": "Remote Services",
        "category": "Lateral Movement",
        "description": "A remote desktop logon (type 10) by a non-machine account, or an administrative network logon (type 3) by a non-service account. Machine accounts ($) and service-account naming patterns (svc-, app_, sql*, backup*, ...) are excluded because they log on routinely, and repeats are deduplicated per account + source IP rather than per rule, so a second source is no longer swallowed.",
        "remediation": "Confirm the logon is expected, restrict RDP by firewall/GPO, and require MFA for all administrative remote access."
    },
    "explicit_credential_logon": {
        "title": "Explicit Credential Use (RunAs / Alternate Credentials)",
        "severity": "Medium",
        "event_ids": [
            "4648"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1078.003",
        "mitre_name": "Valid Accounts: Local Accounts",
        "category": "Lateral Movement",
        "description": "A process started with explicitly supplied credentials against a privileged or service account - how runas, PsExec-style tooling and pass-the-hash movement appear.",
        "remediation": "Trace the parent process that launched it, and remove standing local administrator rights from workstations so explicit-credential movement has nothing to harvest."
    },
    "service_abuse": {
        "title": "Suspicious Service Creation/Modification",
        "severity": "Medium",
        "event_ids": [
            "4697",
            "7045"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1543.003",
        "mitre_name": "Create or Modify System Process: Windows Service",
        "category": "Persistence",
        "description": "A new Windows service was installed. Services run as SYSTEM at boot, which makes them a favourite persistence and privilege-escalation mechanism.",
        "remediation": "Audit the service binary path and hash, restrict service creation to administrators, and look for encoded PowerShell or user-writable directories in the path."
    },
    "scheduled_task_created": {
        "title": "Scheduled Task Created",
        "severity": "High",
        "event_ids": [
            "4698"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1053.005",
        "mitre_name": "Scheduled Task/Job: Scheduled Task",
        "category": "Persistence",
        "description": "A new scheduled task was registered - a durable way to re-execute code after reboot or after the original session is gone.",
        "remediation": "Review the task action and its author, delete anything not backed by a change request, and monitor task creation for non-administrative accounts."
    },
    "registry_persistence": {
        "title": "Registry Autorun / Persistence Key Modified",
        "severity": "High",
        "event_ids": [
            "4657"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1547.001",
        "mitre_name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "category": "Persistence",
        "description": "A registry key used for autostart or execution hijacking (Run/RunOnce, IFEO, Winlogon, service parameters) was modified.",
        "remediation": "Inspect the value written, remove it if unauthorized, and restrict registry write access to these keys through GPO."
    },
    "log_tampering": {
        "title": "Security Log Cleared (Anti-Forensics)",
        "severity": "Critical",
        "event_ids": [
            "1102"
        ],
        "dedupe_minutes": 60,
        "mitre_id": "T1070.001",
        "mitre_name": "Indicator Removal: Clear Windows Event Logs",
        "category": "Defense Evasion",
        "description": "The Security event log was cleared. There is almost no benign reason to do this mid-engagement - assume the attacker is destroying evidence of what came before.",
        "remediation": "Treat as an active intrusion: isolate the host, preserve whatever logs remain (forward them off-host first), and review what the cleared window contained."
    },
    "audit_policy_changed": {
        "title": "Audit Policy Changed",
        "severity": "Critical",
        "event_ids": [
            "4719"
        ],
        "dedupe_minutes": 60,
        "mitre_id": "T1562.002",
        "mitre_name": "Impair Defenses: Disable Windows Event Logging",
        "category": "Defense Evasion",
        "description": "The system audit policy was modified - the standard first step before an attack, used to blind the very detections running on this host.",
        "remediation": "Revert the policy to the approved baseline, push audit configuration by GPO rather than locally, and treat the change as intentional preparation for an attack."
    },
    "eventlog_service_stopped": {
        "title": "Event Log Service Stopped",
        "severity": "Medium",
        "event_ids": [
            "1100"
        ],
        "dedupe_minutes": 60,
        "mitre_id": "T1562.001",
        "mitre_name": "Impair Defenses: Disable or Modify Tools",
        "category": "Defense Evasion",
        "description": "The Windows Event Log service shut down, which halts auditing until it restarts. Attackers stop it to operate without generating events.",
        "remediation": "Confirm whether this was a planned service restart, and alert on unexpected stops - a monitor running on the host cannot see events while the service is down."
    },
    "defender_disabled": {
        "title": "Windows Defender Protection Disabled",
        "severity": "Critical",
        "event_ids": [
            "5001",
            "5010",
            "5012"
        ],
        "dedupe_minutes": 60,
        "mitre_id": "T1562.001",
        "mitre_name": "Impair Defenses: Disable or Modify Tools",
        "category": "Defense Evasion",
        "description": "Real-time or on-access antivirus protection was turned off - either by an administrator, a policy problem, or an attacker clearing the way for tooling.",
        "remediation": "Re-enable protection (and check Group Policy is enforcing it), then investigate what ran while it was off. Tamper protection blocks this in most current builds."
    },
    "firewall_disabled": {
        "title": "Windows Firewall Profile Disabled",
        "severity": "Critical",
        "event_ids": [
            "4950"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1562.004",
        "mitre_name": "Impair Defenses: Disable or Modify System Firewall",
        "category": "Defense Evasion",
        "description": "A whole firewall profile was turned OFF (SettingType EnableFirewall, value No). This is the classic pre-attack move - ransomware and lateral-movement tooling disable the firewall before spreading. Individual rule changes are covered by firewall_rule_modified; this rule only fires for the profile on/off switch.",
        "remediation": "Re-enable the profile (netsh advfirewall set <profile> state on), check Group Policy is enforcing the baseline, and investigate what changed it - assume the host was being prepared for lateral movement."
    },
    "anonymous_smb_session": {
        "title": "Anonymous SMB / Network Session",
        "severity": "Medium",
        "event_ids": [
            "4624"
        ],
        "dedupe_minutes": 60,
        "mitre_id": "T1087",
        "mitre_name": "Account Discovery",
        "category": "Discovery",
        "description": "A network logon (type 3) with no account at all - ANONYMOUS LOGON / a null session. Classic pre-auth AD enumeration: SID brute-forcing, RID cycling and null-session tooling all start here.",
        "remediation": "Disable null session access (RestrictAnonymous) unless explicitly required, then hunt the source for enumeration tooling."
    },
    "firewall_rule_modified": {
        "title": "Windows Firewall Rule Added or Modified",
        "severity": "Medium",
        "event_ids": [
            "4946",
            "4947",
            "4948",
            "4949"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1562.004",
        "mitre_name": "Impair Defenses: Disable or Modify System Firewall",
        "category": "Defense Evasion",
        "description": "A local firewall rule was changed. Attackers add inbound rules to open remote-access ports, or disable rules to allow outbound command-and-control.",
        "remediation": "Compare the rule against the managed firewall baseline, remove local rules that are not in the baseline, and manage firewall policy centrally."
    },
    "system_time_changed": {
        "title": "System Time Changed",
        "severity": "Medium",
        "event_ids": [
            "4616"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1099",
        "mitre_name": "Timestomping",
        "category": "Defense Evasion",
        "description": "The system clock was set. On a domain controller this breaks Kerberos and shifts event timestamps, which undermines log correlation and forensic timelines.",
        "remediation": "Ensure DCs sync time from a trusted, authenticated NTP source and that members follow domain time - and investigate manual changes."
    },
    "special_privileges_assigned": {
        "title": "Administrative Privileges Assigned to a Logon",
        "severity": "Low",
        "event_ids": [
            "4672"
        ],
        "dedupe_minutes": 60,
        "mitre_id": "T1078",
        "mitre_name": "Valid Accounts",
        "category": "Privilege Escalation",
        "description": "A logon was granted administrator-equivalent privileges (SeDebugPrivilege and friends). Expected for real administrators - valuable as a baseline of who holds effective admin rights.",
        "remediation": "Use this as an inventory of administrative sessions: compare against the list of people who should hold admin rights and remove standing access where it is not needed."
    },
    "gpo_or_admin_object_modified": {
        "title": "GPO or AdminSDHolder Object Modified",
        "severity": "High",
        "event_ids": [
            "5136"
        ],
        "dedupe_minutes": 30,
        "mitre_id": "T1484",
        "mitre_name": "Group Policy Modification / T1098 - Account Manipulation",
        "category": "Persistence",
        "description": "A change was made to a Group Policy object (groupPolicyContainer), a GPO link (gPLink), the AdminSDHolder nTSecurityDescriptor, or an account's sIDHistory attribute. sIDHistory or AdminSDHolder changes are Critical; GPO/GPO link changes are High. Machine accounts are excluded.",
        "remediation": "Verify the change was authorized. For sIDHistory: this is a Golden Ticket indicator - rotate KRBTGT twice. For AdminSDHolder: check for backdoor ACLs. For GPO: check for malicious scripts/startup commands."
    },
    "computer_account_abuse": {
        "title": "Computer Account Abuse / RBCD",
        "severity": "Medium",
        "event_ids": [
            "4741",
            "4742"
        ],
        "dedupe_minutes": 30,
        "mitre_id": "T1136.002",
        "mitre_name": "Create Account: Domain Account / T1134.001 - Token Impersonation",
        "category": "Persistence",
        "description": "A computer account was created/modified by a non-administrator, or the delegation attribute (msDS-AllowedToActOnBehalfOfOtherIdentity) was modified - a common technique for Resource-Based Constrained Delegation (RBCD) attacks to hijack services.",
        "remediation": "Verify the creation/modification is legitimate. For delegation changes: check if the computer account is now delegated to a rogue principal (RBCD), and revert if unauthorized."
    },
    "suspicious_process_creation": {
        "title": "Suspicious Process Creation",
        "severity": "High",
        "event_ids": [
            "4688"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1059.001",
        "mitre_name": "Command and Scripting Interpreter: PowerShell / T1003.001 - OS Credential Dumping: LSASS Memory / T1505.003 - Server Software Component: Web Shell",
        "category": "Execution",
        "description": "A process was created with a suspicious command line: ntdsutil (AD database tool), vssadmin delete/create shadow (shadow copy abuse), reg save of SAM/SYSTEM/SECURITY hives (credential dumping), rundll32 comsvcs.dll MiniDump (LSASS dumping), certutil -urlcache (download/execute), or encoded PowerShell (-enc). Requires \"Process Creation\" audit + command-line logging registry value ProcessCreationIncludeCmdLine_Enabled.",
        "remediation": "Investigate the parent process and user context. Enable command-line logging (ProcessCreationIncludeCmdLine_Enabled=1) if not already. Block execution of these tools via AppLocker/WDAC where possible."
    },
    "powershell_scriptblock": {
        "title": "PowerShell Script Block Logging - Offensive Content",
        "severity": "High",
        "event_ids": [
            "4104"
        ],
        "dedupe_minutes": 30,
        "mitre_id": "T1059.001",
        "mitre_name": "Command and Scripting Interpreter: PowerShell / T1059.003 - Windows Command Shell",
        "category": "Execution",
        "description": "A PowerShell script block was logged containing offensive strings: Invoke-Mimikatz, DumpCreds, Invoke-Kerberoast, FromBase64String+IEX, AmsiUtils, Invoke-Obfuscation, Invoke-Expression with obfuscated payloads, or known malicious patterns. Requires PowerShell Script Block Logging (Module Logging) enabled. Stored script text is truncated for safety.",
        "remediation": "Review the full script block in the event log. Check if the host/user is compromised. Ensure Script Block Logging is enabled via GPO: Computer Configuration -> Administrative Templates -> Windows Components -> Windows PowerShell -> Turn on PowerShell Script Block Logging."
    },
    "dsrm_password_set": {
        "title": "DSRM Password Set",
        "severity": "Critical",
        "event_ids": [
            "4794"
        ],
        "dedupe_minutes": 60,
        "mitre_id": "T1003.006",
        "mitre_name": "OS Credential Dumping: DCSync / T1556.002 - Modify Authentication Process: Password Filter",
        "category": "Credential Access",
        "description": "The Directory Services Restore Mode (DSRM) password was set on a Domain Controller. This is a critical indicator of compromise - attackers set a known DSRM password to later boot into DSRM and extract the NTDS.dit database.",
        "remediation": "Immediately investigate who changed the DSRM password. If unauthorized, reset the DSRM password from a known-good backup, and rotate KRBTGT twice. Review for signs of DCSync or NTDS.dit extraction."
    },
    "pass_the_hash_logon": {
        "title": "Pass-the-Hash Logon",
        "severity": "Critical",
        "event_ids": [
            "4624"
        ],
        "dedupe_minutes": 15,
        "mitre_id": "T1550.002",
        "mitre_name": "Use Alternate Authentication Material: Pass the Hash",
        "category": "Credential Access",
        "description": "A logon of type 9 (new credentials) or a network logon (type 3) using NTLM with KeyLength=0 from a non-machine account to a non-localhost source - indicates pass-the-hash or pass-the-ticket lateral movement.",
        "remediation": "Immediately isolate the source host. Rotate the target account password and KRBTGT. Verify the source is not a legitimate administrative tool. Enable NTLM auditing and restrict NTLM where possible."
    }
}
