"""CLI entry point for Alpha Sentinel."""

import argparse
import getpass
import os
import sys
import xml.etree.ElementTree as ET

from alpha_sentinel import __version__

DEFAULT_CONFIG = "/etc/alpha-sentinel/config.yaml"


def cmd_server(args) -> int:
    from alpha_sentinel.server import run_server
    run_server(host=args.host, port=args.port, config=args.config, collect=args.collect)
    return 0


def cmd_collector(args) -> int:
    from alpha_sentinel.collectors import run_collector
    run_collector(config=args.config, once=args.once, server=args.server, key=args.key)
    return 0


def cmd_create_admin(args) -> int:
    from alpha_sentinel import store
    username = args.username or input("Username (3-32 chars, A-Z a-z 0-9 . _ -): ").strip()
    password = getpass.getpass("Password (min 12 chars): ")
    if password != getpass.getpass("Confirm password: "):
        print("Passwords do not match.", file=sys.stderr)
        return 1
    try:
        store.create_user(username, password)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Created dashboard account '{username}' in {store.state_dir()}")
    return 0


def _replay_file(path, engine) -> int:
    from alpha_sentinel.normalize import normalize_windows_event
    from alpha_sentinel.rules import evaluate_event
    found = 0
    root = ET.parse(path).getroot()
    events = list(root) if root.tag.split("}")[-1] == "Events" else [root]
    for el in events:
        event = normalize_windows_event(ET.tostring(el, encoding="unicode"))
        if event is None:
            continue
        alert = evaluate_event(engine, event)
        if alert:
            found += 1
            print(f"  ALERT {alert.Severity:<8} {alert.RuleKey}: {alert.Description}")
    return found


def cmd_replay(args) -> int:
    """Replay exported Windows event XML (wevtutil) through the rule engine."""
    from alpha_sentinel.engine import Engine
    engine = Engine()
    total = errors = 0
    for path in args.files:
        files = ([os.path.join(path, f) for f in sorted(os.listdir(path)) if f.lower().endswith(".xml")]
                 if os.path.isdir(path) else [path])
        for f in files:
            print(f"Processing {f}...")
            try:
                total += _replay_file(f, engine)
            except (ET.ParseError, OSError) as exc:
                errors += 1
                print(f"  Error: {exc}", file=sys.stderr)
    print(f"\nTotal alerts: {len(engine.alerts)}  (file errors: {errors})")
    return 1 if errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="alpha-sentinel",
                                     description="Alpha Sentinel - AD / Linux attack monitor")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    sp = sub.add_parser("server", help="Start the dashboard and API")
    sp.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    sp.add_argument("--port", type=int, default=8443)
    sp.add_argument("--config", default=DEFAULT_CONFIG)
    sp.add_argument("--collect", action="store_true", help="Also tail the configured logs in this process")
    sp.set_defaults(func=cmd_server)

    cp = sub.add_parser("collector", help="Tail logs and detect (optionally forward to a dashboard)")
    cp.add_argument("--config", default=DEFAULT_CONFIG)
    cp.add_argument("--once", action="store_true", help="Process new lines once and exit (for cron)")
    cp.add_argument("--server", help="Dashboard URL to forward alerts to, e.g. http://127.0.0.1:8443")
    cp.add_argument("--key", help="Collector key (or set ALPHA_SENTINEL_COLLECTOR_KEY)")
    cp.set_defaults(func=cmd_collector)

    ap = sub.add_parser("create-admin", help="Create a dashboard login")
    ap.add_argument("--username")
    ap.set_defaults(func=cmd_create_admin)

    rp = sub.add_parser("replay", help="Replay exported event XML files")
    rp.add_argument("files", nargs="+", help="XML file(s) or directory")
    rp.set_defaults(func=cmd_replay)
    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        sys.exit(1)
    try:
        sys.exit(args.func(args) or 0)
    except KeyboardInterrupt:
        print("\nStopped")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
