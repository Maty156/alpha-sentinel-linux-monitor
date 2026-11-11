"""Tests for platform detection."""

import sys
import pytest
from unittest.mock import patch

from alpha_sentinel.platform import detect, PLATFORM


class TestPlatformDetection:
    """Tests for platform.detect()."""

    def test_detect_windows(self):
        """Test detection of Windows."""
        with patch("sys.platform", "win32"):
            assert detect() == "windows"

    def test_detect_linux(self):
        """Test detection of Linux."""
        with patch("sys.platform", "linux"):
            assert detect() == "linux"

    def test_detect_darwin_raises(self):
        """Test detection of macOS raises error."""
        with patch("sys.platform", "darwin"):
            with pytest.raises(RuntimeError, match="Unsupported OS"):
                detect()

    def test_detect_unknown_raises(self):
        """Test detection of unknown OS raises error."""
        with patch("sys.platform", "freebsd"):
            with pytest.raises(RuntimeError, match="Unsupported OS"):
                detect()

    def test_platform_module_constant(self):
        """Test that PLATFORM constant is set."""
        assert PLATFORM in ("windows", "linux", "unsupported")


class TestCLI:
    """Tests for CLI module."""

    def test_version_flag(self, capsys):
        """Test --version flag."""
        import sys
        from alpha_sentinel.cli import main
        
        with pytest.raises(SystemExit):
            with patch.object(sys, "argv", ["alpha-sentinel", "--version"]):
                main()
        
        captured = capsys.readouterr()
        assert "0.2.0" in captured.out

    def test_help_flag(self, capsys):
        """Test --help flag."""
        import sys
        from alpha_sentinel.cli import main
        
        with pytest.raises(SystemExit):
            with patch.object(sys, "argv", ["alpha-sentinel", "--help"]):
                main()
        
        captured = capsys.readouterr()
        assert "usage:" in captured.out.lower() or "alpha-sentinel" in captured.out.lower()


class TestCatalog:
    """Tests for rule catalog."""

    def test_catalog_has_36_keys(self):
        """Test that catalog has exactly 36 Windows rule keys."""
        from alpha_sentinel.catalog import ALL_WINDOWS_RULE_KEYS
        assert len(ALL_WINDOWS_RULE_KEYS) == 36

    def test_catalog_unique_keys(self):
        """Test that all rule keys are unique."""
        from alpha_sentinel.catalog import ALL_WINDOWS_RULE_KEYS
        assert len(ALL_WINDOWS_RULE_KEYS) == len(set(ALL_WINDOWS_RULE_KEYS))

    def test_catalog_order_matches_ps(self):
        """Test that catalog order matches PowerShell catalog."""
        from alpha_sentinel.catalog import ALL_WINDOWS_RULE_KEYS
        
        expected = [
            "password_spraying", "brute_force_single_account", "kerberos_preauth_spraying",
            "ntlm_failed_auth", "account_lockout_storm", "privilege_escalation",
            "account_created", "account_control_changed", "account_enabled_disabled",
            "password_reset_by_admin", "group_membership_removed", "account_deleted",
            "kerberoasting", "asrep_roasting", "dcsync_replication", "ldap_recon",
            "suspicious_remote_logon", "explicit_credential_logon", "service_abuse",
            "scheduled_task_created", "registry_persistence", "log_tampering",
            "audit_policy_changed", "eventlog_service_stopped", "defender_disabled",
            "firewall_disabled", "anonymous_smb_session", "firewall_rule_modified",
            "system_time_changed", "special_privileges_assigned",
            "gpo_or_admin_object_modified", "computer_account_abuse",
            "suspicious_process_creation", "powershell_scriptblock",
            "dsrm_password_set", "pass_the_hash_logon",
        ]
        assert ALL_WINDOWS_RULE_KEYS == expected
