#!/usr/bin/env python3
"""
Oracle replay harness: runs every fixture through PS replay and Python replay,
compares alert sets (RuleKey, Severity, Account, Host).
"""

import csv
import json
import os
import subprocess
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Set, Tuple
import xml.etree.ElementTree as ET


# Paths
REPO_ROOT = Path(__file__).parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
ORACLE_DIR = REPO_ROOT / "tests" / "oracle"
ORACLE_FILE = ORACLE_DIR / "ps_alerts.json"
EXPECTED_FILE = FIXTURES_DIR / "expected.json"
PWSH = os.environ.get("PWSH", "pwsh")


def find_pwsh() -> str:
    """Find pwsh executable."""
    # Check env var
    if "PWSH" in os.environ:
        return os.environ["PWSH"]
    # Check PATH
    pwsh = shutil.which("pwsh")
    if pwsh:
        return pwsh
    # Check known location
    known = Path.home() / ".hermes" / "tools" / "pwsh-7.4.6" / "pwsh"
    if known.exists():
        return str(known)
    raise RuntimeError("pwsh not found. Set PWSH env var or install PowerShell 7+.")


def run_ps_replay(fixture_path: Path, pwsh: str, alpha_sentinel_path: Path) -> List[Dict]:
    """Run PS replay on a fixture and return list of alerts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_fixture = Path(tmpdir) / fixture_path.name
        shutil.copy2(fixture_path, tmp_fixture)
        
        # Run PS replay
        cmd = [
            pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(alpha_sentinel_path),
            "-ReplayPath", str(tmp_fixture)
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        # Find the .alerts.csv output
        csv_files = list(Path(tmpdir).glob("*.alerts.csv"))
        if not csv_files:
            return []
        
        alerts = []
        with open(csv_files[0], "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                alerts.append({
                    "RuleKey": row.get("RuleKey", ""),
                    "Severity": row.get("Severity", ""),
                    "Account": row.get("Account", ""),
                    "Host": row.get("Host", ""),
                })
        return alerts


def load_oracle() -> Dict[str, List[Dict]]:
    """Load PS oracle alerts from JSON."""
    if not ORACLE_FILE.exists():
        return {}
    with open(ORACLE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_oracle(oracle: Dict[str, List[Dict]]) -> None:
    """Save PS oracle alerts to JSON."""
    ORACLE_DIR.mkdir(parents=True, exist_ok=True)
    with open(ORACLE_FILE, "w", encoding="utf-8") as f:
        json.dump(oracle, f, indent=2)


def load_expected() -> Dict:
    """Load expected.json."""
    if not EXPECTED_FILE.exists():
        return {}
    with open(EXPECTED_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def alert_key(alert: Dict) -> Tuple[str, str, str, str]:
    """Create comparable key for alert."""
    return (
        alert.get("RuleKey", ""),
        alert.get("Severity", ""),
        alert.get("Account", ""),
        alert.get("Host", ""),
    )


def compare_sets(ps_alerts: List[Dict], py_alerts: List[Dict]) -> Tuple[Set, Set]:
    """Compare two alert sets, return (ps_only, py_only)."""
    ps_set = {alert_key(a) for a in ps_alerts}
    py_set = {alert_key(a) for a in py_alerts}
    return ps_set - py_set, py_set - ps_set


# --- Python replay ---

def run_python_replay(fixture_path: Path) -> List[Dict]:
    """Run Python replay on a fixture and return list of alerts."""
    sys.path.insert(0, str(REPO_ROOT))
    
    from alpha_sentinel.normalize import normalize_windows_event
    from alpha_sentinel.engine import Engine
    from alpha_sentinel.rules import evaluate_event
    
    engine = Engine(retain_alerts=False)  # replay mode: matches PowerShell -ReplayPath
    alerts = []
    
    try:
        # Parse fixture - could be single event or multiple in <Events> wrapper
        with open(fixture_path, "r", encoding="utf-8") as f:
            xml_content = f.read()
        
        root = ET.fromstring(xml_content)
        
        # Handle both <Events><Event>...</Event></Events> and bare <Event>...</Event>
        events = []
        if root.tag.endswith("Events"):
            events = list(root)
        else:
            events = [root]
        
        for event_elem in events:
            single_xml = ET.tostring(event_elem, encoding="unicode")
            event = normalize_windows_event(single_xml)
            if event:
                alert = evaluate_event(engine, event)
                if alert:
                    alerts.append({
                        "RuleKey": alert.RuleKey,
                        "Severity": alert.Severity,
                        "Account": alert.Account,
                        "Host": alert.Host,
                    })
    except Exception as e:  # noqa: BLE001
        print(f"  Python error on {fixture_path.name}: {e}")
        raise
    
    return alerts


def run_oracle(refresh: bool = False) -> None:
    """Generate or refresh PS oracle data."""
    pwsh = find_pwsh()
    alpha_sentinel = Path(__file__).parent.parent / "AlphaSentinel.ps1"
    
    if not alpha_sentinel.exists():
        raise FileNotFoundError(f"AlphaSentinel.ps1 not found at {alpha_sentinel}")
    
    fixtures = sorted(FIXTURES_DIR.glob("*.xml"))
    oracle = {}
    
    for fixture in fixtures:
        print(f"Processing {fixture.name}...")
        alerts = run_ps_replay(fixture, pwsh, alpha_sentinel)
        oracle[fixture.name] = alerts
        print(f"  -> {len(alerts)} alerts")
    
    save_oracle(oracle)
    print(f"Oracle saved to {ORACLE_FILE}")


def run_diff(refresh_oracle: bool = False, run_python: bool = True) -> int:
    """Run diff between PS oracle and Python alerts."""
    if refresh_oracle:
        run_oracle(refresh=True)
    
    oracle = load_oracle()
    expected = load_expected()
    
    print("\n=== Diff Replay Report ===")
    print(f"{'Fixture':<50} {'PS Alerts':>10} {'PY Alerts':>10} {'Match':>6}")
    print("-" * 80)
    
    total_mismatches = 0
    fixtures = sorted(FIXTURES_DIR.glob("*.xml"))
    
    for fixture in fixtures:
        ps_alerts = oracle.get(fixture.name, [])
        
        # Run Python replay
        py_alert_list = []
        if run_python:
            py_alert_list = run_python_replay(fixture)
        
        # compare as sorted lists (not sets) so a missing or extra duplicate alert is a mismatch
        ps_set = sorted(alert_key(a) for a in ps_alerts)
        py_set = sorted(alert_key(a) for a in py_alert_list)
        
        match = "YES" if ps_set == py_set else "NO"
        if match == "NO":
            total_mismatches += 1
        
        print(f"{fixture.name:<50} {len(ps_alerts):>10} {len(py_alert_list):>10} {match:>6}")
        
        # Check expected.json
        if fixture.name in expected:
            exp = expected[fixture.name]
            ps_keys = {a["RuleKey"] for a in ps_alerts}
            expect_keys = set(exp.get("expect", []))
            forbid_keys = set(exp.get("forbid", []))
            
            if not expect_keys.issubset(ps_keys):
                print(f"  ⚠ ORACLE MISSING EXPECT: {expect_keys - ps_keys}")
            if forbid_keys & ps_keys:
                print(f"  ⚠ ORACLE HAS FORBIDDEN: {forbid_keys & ps_keys}")
    
    print("-" * 80)
    print(f"Total fixtures: {len(fixtures)}")
    print(f"Mismatches: {total_mismatches}")
    
    return 1 if total_mismatches > 0 else 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Alpha Sentinel diff_replay oracle harness")
    parser.add_argument("--refresh-oracle", action="store_true", help="Regenerate PS oracle")
    parser.add_argument("--run-python", action="store_true", default=True, help=argparse.SUPPRESS)  # kept for old callers
    parser.add_argument("--skip-python", action="store_true", help="Only print the PowerShell oracle")
    args = parser.parse_args()
    
    sys.exit(run_diff(refresh_oracle=args.refresh_oracle, run_python=not args.skip_python))


if __name__ == "__main__":
    main()