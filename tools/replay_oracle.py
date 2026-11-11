"""Replay every XML fixture through the engine and compare against the PowerShell
oracle (tests/oracle/ps_alerts.json). Exit 0 only when every fixture matches on
RuleKey, Severity, Account and Host."""
import glob
import json
import os
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from alpha_sentinel.engine import Engine  # noqa: E402
from alpha_sentinel.normalize import normalize_windows_event  # noqa: E402
from alpha_sentinel.rules import evaluate_event  # noqa: E402


def replay(path):
    engine = Engine(retain_alerts=False)  # replay mode, like AlphaSentinel.ps1 -ReplayPath
    found = []
    for el in ET.parse(path).getroot():
        ev = normalize_windows_event(ET.tostring(el, encoding="unicode"))
        if ev is not None:
            a = evaluate_event(engine, ev)
            if a:
                found.append({"RuleKey": a.RuleKey, "Severity": a.Severity, "Account": a.Account, "Host": a.Host})
    return found


def main():
    oracle = json.load(open(os.path.join(ROOT, "tests", "oracle", "ps_alerts.json")))
    bad = 0
    files = sorted(glob.glob(os.path.join(ROOT, "tests", "fixtures", "*.xml")))
    for f in files:
        name = os.path.basename(f)
        got = sorted(replay(f), key=lambda a: (a["RuleKey"], a["Account"]))
        exp = sorted(oracle.get(name, []), key=lambda a: (a["RuleKey"], a["Account"]))
        if got != exp:
            bad += 1
            print(f"MISMATCH {name}\n  expected {exp}\n  got      {got}")
    print(f"fixtures: {len(files)}  mismatches: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
