# PORT_STATUS.md

All 36 Windows rule families are ported. "Fixtures" = XML fixtures whose PowerShell result includes that rule
(each is replayed through Python and must match on rule, severity, account, host and alert count).

| # | Rule key | Event IDs | Fixtures | Notes |
|---|----------|-----------|----------|-------|
| 1 | password_spraying | 4625 | 0 | no fixture yet |
| 2 | brute_force_single_account | 4625 | 0 | no fixture yet |
| 3 | kerberos_preauth_spraying | 4771 | 0 | no fixture yet |
| 4 | ntlm_failed_auth | 4776 | 1 |  |
| 5 | account_lockout_storm | 4740 | 0 | no fixture yet |
| 6 | privilege_escalation | 4728, 4732, 4756 | 1 |  |
| 7 | account_created | 4720 | 1 |  |
| 8 | account_control_changed | 4738 | 2 |  |
| 9 | account_enabled_disabled | 4722, 4725 | 0 | no fixture yet |
| 10 | password_reset_by_admin | 4724 | 0 | no fixture yet |
| 11 | group_membership_removed | 4729, 4733 | 0 | no fixture yet - covered by unit tests only |
| 12 | account_deleted | 4726 | 0 | no fixture yet |
| 13 | kerberoasting | 4769 | 2 |  |
| 14 | asrep_roasting | 4768 | 1 |  |
| 15 | dcsync_replication | 4662 | 1 |  |
| 16 | ldap_recon | 4662, 5141 | 0 | no fixture yet |
| 17 | suspicious_remote_logon | 4624 | 3 |  |
| 18 | explicit_credential_logon | 4648 | 0 | no fixture yet |
| 19 | service_abuse | 4697, 7045 | 0 | no fixture yet |
| 20 | scheduled_task_created | 4698 | 0 | no fixture yet |
| 21 | registry_persistence | 4657 | 0 | no fixture yet |
| 22 | log_tampering | 1102 | 0 | no fixture yet |
| 23 | audit_policy_changed | 4719 | 0 | no fixture yet |
| 24 | eventlog_service_stopped | 1100 | 1 |  |
| 25 | defender_disabled | 5001, 5010, 5012 | 0 | no fixture yet |
| 26 | firewall_disabled | 4950 | 1 |  |
| 27 | anonymous_smb_session | 4624 | 1 |  |
| 28 | firewall_rule_modified | 4946, 4947, 4948, 4949 | 0 | no fixture yet |
| 29 | system_time_changed | 4616 | 0 | no fixture yet |
| 30 | special_privileges_assigned | 4672 | 0 | no fixture yet |
| 31 | gpo_or_admin_object_modified | 5136 | 4 |  |
| 32 | computer_account_abuse | 4741, 4742 | 2 |  |
| 33 | suspicious_process_creation | 4688 | 3 |  |
| 34 | powershell_scriptblock | 4104 | 3 |  |
| 35 | dsrm_password_set | 4794 | 1 |  |
| 36 | pass_the_hash_logon | 4624 | 2 |  |

## Linux rules (Python only - no PowerShell oracle)

Covered by `tests/py/test_linux.py` and `tests/py/test_collector.py`.

| # | Rule key |
|---|----------|
| 1 | ssh_bruteforce |
| 2 | ssh_key_auth |
| 3 | ssh_success_after_failures |
| 4 | root_ssh_login |
| 5 | user_account_changed |
| 6 | ssh_authorized_keys_modified |
| 7 | sshd_config_modified |
| 8 | cron_or_systemd_persistence |
| 9 | sudo_privilege_escalation |
| 10 | suspicious_command_execution |

## Not ported yet (dashboard returns HTTP 501 JSON)

Assets and attack paths, attack chains, reports, user management, audit-policy preflight / apply,
the AI bot, and self-test. `/api/assets` and `/api/chains` return empty lists so the pages render.
