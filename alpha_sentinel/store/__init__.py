"""Store package - state directory, alert history and dashboard users.

Everything the monitor persists lives in one state directory so it is easy to
back up and to lock down:

  alerts.jsonl          append-only alert history (one JSON object per line)
  collector-state.json  file offsets / cursors so a restart does not re-read logs
  users.json            dashboard accounts (PBKDF2 hashes, never plain passwords)
"""

import dataclasses
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

_lock = threading.Lock()
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
PBKDF2_ITERATIONS = 310_000
MIN_PASSWORD_LEN = 12


def state_dir() -> Path:
    """State directory: $ALPHA_SENTINEL_STATE_DIR, else /var/lib/alpha-sentinel if
    writable, else ~/.local/state/alpha-sentinel. Created with mode 0700."""
    env = os.environ.get("ALPHA_SENTINEL_STATE_DIR")
    candidates = [Path(env)] if env else [Path("/var/lib/alpha-sentinel"),
                                          Path.home() / ".local" / "state" / "alpha-sentinel"]
    for path in candidates:
        try:
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            if os.access(path, os.W_OK):
                return path
        except OSError:
            continue
    raise RuntimeError("no writable state directory; set ALPHA_SENTINEL_STATE_DIR")


def _write_private(path: Path, text: str) -> None:
    """Atomic write with owner-only permissions (these files hold credentials/state)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


# ---- alert history --------------------------------------------------------
def append_alert(alert) -> None:
    """Append an alert to alerts.jsonl. Failures are reported, never raised."""
    try:
        line = json.dumps(dataclasses.asdict(alert), ensure_ascii=False, default=str)
        fd = os.open(state_dir() / "alerts.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with _lock, os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception as exc:  # noqa: BLE001
        print(f"warning: could not persist alert: {exc}")


# ---- generic json state ---------------------------------------------------
def load_json(name: str, default: Any) -> Any:
    path = state_dir() / name
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as exc:
        print(f"warning: ignoring unreadable {path}: {exc}")
        return default


def save_json(name: str, data: Any) -> None:
    with _lock:
        _write_private(state_dir() / name, json.dumps(data, indent=2))


# ---- dashboard users ------------------------------------------------------
def _hash(password: str, salt: bytes, iterations: int) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations).hex()


def create_user(username: str, password: str, role: str = "admin") -> None:
    if not USERNAME_RE.match(username):
        raise ValueError("username must be 3-32 characters of A-Z a-z 0-9 . _ -")
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    if password.lower() == username.lower():
        raise ValueError("password must not equal the username")
    users = load_json("users.json", {})
    if username.lower() in {u.lower() for u in users}:
        raise ValueError(f"user '{username}' already exists")
    salt = secrets.token_bytes(16)
    users[username] = {"salt": salt.hex(), "iterations": PBKDF2_ITERATIONS,
                       "hash": _hash(password, salt, PBKDF2_ITERATIONS), "role": role,
                       "created": datetime.now(timezone.utc).isoformat()}
    save_json("users.json", users)


def has_users() -> bool:
    return bool(load_json("users.json", {}))


# a real hash of a throwaway value, so unknown usernames cost the same time as bad passwords
_DUMMY_SALT = secrets.token_bytes(16)
_DUMMY_HASH = _hash("dummy-password", _DUMMY_SALT, PBKDF2_ITERATIONS)


def verify_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Return {'username', 'role'} on success, else None (constant-ish time)."""
    users = load_json("users.json", {})
    rec = users.get(username) if isinstance(username, str) else None
    if rec is None:
        hmac.compare_digest(_hash(password, _DUMMY_SALT, PBKDF2_ITERATIONS), _DUMMY_HASH)
        return None
    expected = rec["hash"]
    actual = _hash(password, bytes.fromhex(rec["salt"]), int(rec["iterations"]))
    if hmac.compare_digest(actual, expected):
        return {"username": username, "role": rec.get("role", "admin")}
    return None


def change_password(username: str, current: str, new: str) -> None:
    if verify_user(username, current) is None:
        raise ValueError("current password is incorrect")
    if len(new) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    if new.lower() == username.lower():
        raise ValueError("password must not equal the username")
    users = load_json("users.json", {})
    salt = secrets.token_bytes(16)
    users[username].update(salt=salt.hex(), iterations=PBKDF2_ITERATIONS, hash=_hash(new, salt, PBKDF2_ITERATIONS),
                           updated=datetime.now(timezone.utc).isoformat())
    save_json("users.json", users)


def list_users(current: str = "") -> list:
    """Rows for the Users tab. Never includes hashes or salts."""
    users = load_json("users.json", {})
    return [{"name": n, "current": n == current, "created": u.get("created", ""),
             "updated": u.get("updated", ""), "role": u.get("role", "admin")}
            for n, u in sorted(users.items(), key=lambda kv: kv[0].lower())]


def reset_password(username: str, new: str) -> None:
    """Admin reset of another account's password (caller has already re-authenticated)."""
    users = load_json("users.json", {})
    if username not in users:
        raise ValueError("no such account")
    if len(new) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    if new.lower() == username.lower():
        raise ValueError("password must not equal the username")
    salt = secrets.token_bytes(16)
    users[username].update(salt=salt.hex(), iterations=PBKDF2_ITERATIONS, hash=_hash(new, salt, PBKDF2_ITERATIONS),
                           updated=datetime.now(timezone.utc).isoformat())
    save_json("users.json", users)


def remove_user(username: str) -> None:
    users = load_json("users.json", {})
    if username not in users:
        raise ValueError("no such account")
    if len(users) <= 1:
        raise ValueError("the last account cannot be removed")
    del users[username]
    save_json("users.json", users)


def rename_user(old: str, new: str) -> None:
    users = load_json("users.json", {})
    if old not in users:
        raise ValueError("no such account")
    if not USERNAME_RE.match(new):
        raise ValueError("username must be 3-32 characters of A-Z a-z 0-9 . _ -")
    if new.lower() != old.lower() and new.lower() in {u.lower() for u in users}:
        raise ValueError(f"user '{new}' already exists")
    rec = users.pop(old)
    rec["updated"] = datetime.now(timezone.utc).isoformat()
    users[new] = rec
    save_json("users.json", users)


# ---- secrets (Gemini key): stored server-side only, 0600 --------------------
def get_gemini_key() -> str:
    return os.environ.get("GEMINI_API_KEY", "") or load_json("secrets.json", {}).get("gemini_key", "")


def set_gemini_key(key: str) -> None:
    data = load_json("secrets.json", {})
    if key:
        data["gemini_key"] = key
    else:
        data.pop("gemini_key", None)
    save_json("secrets.json", data)


DEFAULT_GEMINI_MODEL = "gemini-3.1-flash-lite"


def get_gemini_model() -> str:
    return (os.environ.get("ALPHA_SENTINEL_GEMINI_MODEL", "")
            or load_json("secrets.json", {}).get("gemini_model", "") or DEFAULT_GEMINI_MODEL)


def set_gemini_model(model: str) -> None:
    data = load_json("secrets.json", {})
    data["gemini_model"] = model
    save_json("secrets.json", data)


def get_ai_provider() -> dict:
    d = load_json("secrets.json", {})
    return {"provider": d.get("ai_provider", "gemini"), "baseUrl": d.get("ai_base_url", "")}


def set_ai_provider(provider: str, base_url: str) -> None:
    d = load_json("secrets.json", {})
    d["ai_provider"], d["ai_base_url"] = provider, base_url
    save_json("secrets.json", d)
