import pytest

from alpha_sentinel.cli import main


def test_replay_directory(capsys):
    with pytest.raises(SystemExit) as e:
        main(["replay", "tests/fixtures/dsrm-4794.xml"])
    assert e.value.code == 0
    assert "dsrm_password_set" in capsys.readouterr().out


def test_replay_reports_bad_file_with_nonzero_exit(tmp_path, capsys):
    bad = tmp_path / "bad.xml"
    bad.write_text("<not xml")
    with pytest.raises(SystemExit) as e:
        main(["replay", str(bad)])
    assert e.value.code == 1


def test_server_refuses_to_start_without_an_account():
    with pytest.raises(SystemExit) as e:
        main(["server", "--port", "0"])
    assert "create-admin" in str(e.value.code) or e.value.code not in (0, None)


def test_rule_4729_group_removal(tmp_path, capsys):
    xml = tmp_path / "x.xml"
    xml.write_text('<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4729</EventID>'
                   '<TimeCreated SystemTime="2026-03-04T09:15:00.0000000Z"/><Computer>DC01</Computer></System><EventData>'
                   '<Data Name="MemberName">CN=svc,DC=c</Data><Data Name="TargetUserName">Domain Admins</Data>'
                   '<Data Name="SubjectUserName">administrator</Data></EventData></Event></Events>')
    with pytest.raises(SystemExit):
        main(["replay", str(xml)])
    assert "group_membership_removed" in capsys.readouterr().out
