"""Every XML fixture must reproduce the PowerShell oracle (rule, severity, account, host)."""
import glob
import json
import os

import pytest

from tools.replay_oracle import ROOT, replay

FIXTURES = sorted(glob.glob(os.path.join(ROOT, "tests", "fixtures", "*.xml")))


def _expected():
    return json.load(open(os.path.join(ROOT, "tests", "oracle", "ps_alerts.json")))


def _key(a):
    return (a["RuleKey"], a["Account"], a["Severity"])


def test_rules_package_imports_cleanly():
    """Regression: a missing typing import made this fail and every rule silently returned None."""
    import alpha_sentinel.rules as rules
    assert rules.WINDOWS_EVALUATORS and rules.LINUX_EVALUATORS


@pytest.mark.parametrize("path", FIXTURES, ids=[os.path.basename(f) for f in FIXTURES])
def test_fixture_matches_oracle(path):
    expected = _expected().get(os.path.basename(path), [])
    assert sorted(replay(path), key=_key) == sorted(expected, key=_key)


def test_every_windows_rule_key_has_metadata_and_an_evaluator():
    import glob as g
    from alpha_sentinel.catalog import ALL_WINDOWS_RULE_KEYS
    from alpha_sentinel.rule_meta import WINDOWS_RULE_META
    src = "".join(open(p).read() for p in g.glob(os.path.join(ROOT, "alpha_sentinel", "rules", "_*.py")))
    for key in ALL_WINDOWS_RULE_KEYS:
        assert key in WINDOWS_RULE_META, key
        assert f"'{key}'" in src or f'"{key}"' in src, f"no evaluator raises {key}"


def test_event_fields_used_by_rules_exist_on_the_model():
    """Regression: rules read event.objectClass/privilegeList/... that the model lacked."""
    import dataclasses
    import re
    from alpha_sentinel.models import Event
    fields = {f.name for f in dataclasses.fields(Event)}
    used = set()
    for p in glob.glob(os.path.join(ROOT, "alpha_sentinel", "rules", "*.py")):
        used |= set(re.findall(r"\bevent\.(\w+)", open(p).read()))
    assert not (used - fields), used - fields
