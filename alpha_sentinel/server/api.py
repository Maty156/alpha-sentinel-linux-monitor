"""HTTP API + dashboard server for Alpha Sentinel (FastAPI).

Security model (mirrors the PowerShell build):
  * every /api/* route needs a valid session cookie, except /api/login and
    /api/health; collector forwarding uses a shared key instead;
  * session id is random, HttpOnly, SameSite=Strict, with absolute + idle timeouts;
  * sign-in is rate limited per client address;
  * state-changing requests must be same-origin (CSRF guard);
  * binds to 127.0.0.1 unless told otherwise.
"""

import asyncio
import hmac
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional
from urllib.parse import urlparse

from alpha_sentinel import __version__, store
from alpha_sentinel.catalog import ALL_LINUX_RULE_KEYS, ALL_WINDOWS_RULE_KEYS, LINUX_RULE_META
from alpha_sentinel.engine import SEVERITY_ORDER, Engine
from alpha_sentinel.rule_meta import WINDOWS_RULE_META

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import FileResponse, JSONResponse, Response
    from fastapi.staticfiles import StaticFiles
    FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover
    FASTAPI_AVAILABLE = False

STATIC_DIR = Path(__file__).parent / "static"
SESSION_COOKIE = "sentinel_session"
SESSION_HOURS = 8
IDLE_MINUTES = 30
MAX_LOGIN_FAILURES = 5
LOGIN_WINDOW_SECONDS = 600
LOGIN_BLOCK_SECONDS = 900
MAX_BODY_BYTES = 64 * 1024
ALERT_STATUSES = ("New", "Investigating", "Resolved", "False Positive")
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
       "script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
NOT_AVAILABLE = {"error": "Not available in the Linux build yet."}


class AppState:
    """Everything the server shares: the engine, sessions and login throttling."""

    def __init__(self, engine: Optional[Engine] = None, host: str = "127.0.0.1", port: int = 8443,
                 collector_key: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.collecting = False
        self.engine = engine or Engine()
        self.host, self.port = host, port
        self.collector_key = collector_key or os.environ.get("ALPHA_SENTINEL_COLLECTOR_KEY", "")
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.failures: Dict[str, Deque[float]] = defaultdict(deque)
        self.blocked_until: Dict[str, float] = {}
        self.lock = threading.Lock()
        self.started = time.time()

    # ---- sessions ---------------------------------------------------------
    def new_session(self, user: Dict[str, Any]) -> str:
        sid = secrets.token_urlsafe(32)
        now = time.time()
        with self.lock:
            self.sessions[sid] = {"user": user["username"], "role": user["role"], "created": now, "last": now}
        return sid

    def get_session(self, sid: Optional[str]) -> Optional[Dict[str, Any]]:
        if not sid:
            return None
        now = time.time()
        with self.lock:
            s = self.sessions.get(sid)
            if not s:
                return None
            if now - s["created"] > SESSION_HOURS * 3600 or now - s["last"] > IDLE_MINUTES * 60:
                del self.sessions[sid]
                return None
            s["last"] = now
            return dict(s)

    def end_session(self, sid: Optional[str]) -> None:
        with self.lock:
            self.sessions.pop(sid or "", None)

    # ---- login throttling -------------------------------------------------
    def retry_after(self, ip: str) -> int:
        with self.lock:
            until = self.blocked_until.get(ip, 0)
        return max(0, int(until - time.time()))

    def record_failure(self, ip: str) -> None:
        now = time.time()
        with self.lock:
            q = self.failures[ip]
            q.append(now)
            while q and now - q[0] > LOGIN_WINDOW_SECONDS:
                q.popleft()
            if len(q) >= MAX_LOGIN_FAILURES:
                self.blocked_until[ip] = now + LOGIN_BLOCK_SECONDS
                q.clear()

    def end_sessions_for(self, user: str) -> None:
        with self.lock:
            for sid in [k for k, v in self.sessions.items() if v["user"] == user]:
                del self.sessions[sid]

    def clear_failures(self, ip: str) -> None:
        with self.lock:
            self.failures.pop(ip, None)
            self.blocked_until.pop(ip, None)


# ---- payload builders -------------------------------------------------------
LINUX_SOURCES = {
    "ssh_bruteforce": ["sshd"], "ssh_key_auth": ["sshd"], "ssh_success_after_failures": ["sshd"],
    "root_ssh_login": ["sshd"], "user_account_changed": ["useradd/usermod"],
    "ssh_authorized_keys_modified": ["auth log"], "sshd_config_modified": ["auth log"],
    "cron_or_systemd_persistence": ["cron/systemd"], "sudo_privilege_escalation": ["sudo"],
    "suspicious_command_execution": ["sudo/auth log"],
}


def rule_scope() -> str:
    """Which rule set the UI shows: linux (default on Linux), windows or all."""
    v = os.environ.get("ALPHA_SENTINEL_RULES", "").strip().lower()
    return v if v in ("linux", "windows", "all") else "linux"


def _all_rule_meta() -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    scope = rule_scope()
    if scope in ("windows", "all"):
        for k in ALL_WINDOWS_RULE_KEYS:
            out[k] = WINDOWS_RULE_META.get(k, {})
    if scope in ("linux", "all"):
        for k in ALL_LINUX_RULE_KEYS:
            m = dict(LINUX_RULE_META.get(k, {}))
            m["event_ids"] = LINUX_SOURCES.get(k, [])
            out[k] = m
    return out


def alert_row(a) -> Dict[str, Any]:
    return {
        "Id": a.Id, "Time": a.Time, "RuleKey": a.RuleKey, "Rule": a.Rule, "Severity": a.Severity,
        "Title": a.Title, "Mitre": a.Mitre, "MitreId": a.MitreId, "MitreName": a.MitreName,
        "Tactic": a.Tactic, "Entity": a.Entity or a.Account or a.Host, "Remediation": a.Remediation,
        "Description": a.Description, "Host": a.Host, "Account": a.Account, "SourceIp": a.SourceIp,
        "EventId": a.EventId, "Acknowledged": a.Acknowledged, "Status": a.Status, "Notes": a.Notes,
        "SelfTest": a.SelfTest, "FirstSeen": a.FirstSeen or a.Time, "LastSeen": a.LastSeen or a.Time,
        "Count": a.Count, "Events": a.Events,
    }


def _is_open(a) -> bool:
    return not a.SelfTest and a.Status in ("New", "Investigating", "")


def overview_payload(engine: Engine) -> Dict[str, Any]:
    alerts = [a for a in engine.alerts if not a.SelfTest]
    open_ = [a for a in alerts if _is_open(a)]
    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    tactics: Dict[str, int] = defaultdict(int)
    for a in alerts:
        if a.Severity in sev:
            sev[a.Severity] += 1
        tactics[a.Tactic or "Unknown"] += 1
    meta = _all_rule_meta()
    total = len(meta)
    hour_key = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")
    hourly = [engine.hourly[k] for k in sorted(engine.hourly)]
    return {
        "tiles": {
            "openAlerts": len(open_),
            "critical": sum(1 for a in open_ if a.Severity == "Critical"),
            "high": sum(1 for a in open_ if a.Severity == "High"),
            "eventsLastHour": engine.hourly.get(hour_key, {}).get("events", 0),
            "hostsSeen": len(engine.hosts),
        },
        "deltas": {"openAlerts": 0, "critical": 0, "high": 0, "eventsLastHour": 0, "hostsSeen": 0},
        "coverage": {"percent": 100, "rulesTotal": total, "rulesWorking": total, "rulesBlind": 0,
                     "rulesUnknown": 0, "blindRules": [], "unknownRules": []},
        "severityCounts": sev,
        "tacticCounts": dict(tactics),
        "hourly": hourly,
        "lastPoll": {"lagSeconds": 0, "catchingUp": False, "capped": False},
        "health": {"state": "ok", "reasons": []},
        "version": __version__,
        "demoData": False,
    }


def rules_payload(engine: Engine) -> Dict[str, Any]:
    rules = []
    for key, m in _all_rule_meta().items():
        mitre = f"{m.get('mitre_id', '')} - {m.get('mitre_name', '')}" if m.get("mitre_name") else m.get("mitre_id", "")
        rules.append({
            "key": key, "title": m.get("title", key), "severity": m.get("severity", "Medium"),
            "mitre": mitre, "category": m.get("category", ""), "eventIds": m.get("event_ids", []),
            "dedupeMinutes": m.get("dedupe_minutes", 15), "description": m.get("description", ""),
            "remediation": m.get("remediation", ""), "fired": engine.rules_fired.get(key, 0),
            "lastFired": engine.rules_last.get(key), "auditState": "ok", "auditDetail": "",
        })
    rules.sort(key=lambda r: (-SEVERITY_ORDER.get(r["severity"], 0), r["title"]))
    ids = sorted({e for r in rules for e in r["eventIds"]})
    return {"rules": rules, "total": len(rules), "firedTotal": sum(1 for r in rules if r["fired"]),
            "monitoredEventIds": ids, "auditBlind": 0, "auditUnknown": 0, "auditCheckedAt": None}


def events_payload(engine: Engine, q) -> Dict[str, Any]:
    try:
        limit = max(1, min(int(q.get("limit", 100)), 500))
    except ValueError:
        limit = 100
    rows = list(engine.recent_events)
    eid = q.get("eventId", "")
    if eid:
        if not eid.isdigit() or len(eid) > 10:
            return {"error": "eventId must be digits."}
        rows = [r for r in rows if r["eventId"] == eid]
    for field, col in (("host", "host"), ("user", "user")):
        v = q.get(field, "")[:120].lower()
        if v:
            rows = [r for r in rows if r[col].lower() == v]
    needle = q.get("q", "")[:120].lower()
    if needle:
        rows = [r for r in rows if needle in r["summary"].lower() or needle in r["host"].lower()
                or needle in r["user"].lower() or needle in r["eventId"]]
    total = len(rows)
    newest = sorted(rows, key=lambda r: r["time"], reverse=True)[:limit]
    return {"events": newest, "count": len(newest), "total": total, "limit": limit}


def settings_payload(state: AppState) -> Dict[str, Any]:
    users = [{"user": n, "created": u.get("created", "")} for n, u in store.load_json("users.json", {}).items()]
    return {
        "version": __version__, "pollSeconds": 0, "bind": state.host, "port": state.port,
        "sessionHours": SESSION_HOURS, "idleMinutes": IDLE_MINUTES,
        "rateLimit": {"maxLoginFailures": MAX_LOGIN_FAILURES, "windowMinutes": LOGIN_WINDOW_SECONDS // 60,
                      "blockMinutes": LOGIN_BLOCK_SECONDS // 60, "maxBodyStalls": 0, "bodyReadMs": 0,
                      "maxLoginBodyBytes": MAX_BODY_BYTES, "maxJsonBodyBytes": MAX_BODY_BYTES},
        "forwarding": {"enabled": False, "host": "", "keyConfigured": bool(state.collector_key)},
        "audit": {"checkedAt": None, "readable": True, "rulesTotal": len(_all_rule_meta()),
                  "okCount": len(_all_rule_meta()), "blindCount": 0, "unknownCount": 0, "fix": [],
                  "lastChange": None, "elevated": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
                  "backups": []},
        "users": users, "usersFileState": "ok", "demoData": False,
    }


# ---- app ---------------------------------------------------------------------
def create_app(state: Optional[AppState] = None) -> "FastAPI":
    if not FASTAPI_AVAILABLE:
        raise RuntimeError("FastAPI is not installed. Run: pip install fastapi 'uvicorn[standard]'")
    state = state or AppState()
    app = FastAPI(title="Alpha Sentinel", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.sentinel = state

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def err(message: str, status: int, **headers) -> "JSONResponse":
        return JSONResponse({"error": message}, status_code=status, headers=headers or None)

    def same_origin(request: Request) -> bool:
        origin = request.headers.get("origin") or request.headers.get("referer")
        if not origin:
            return True  # non-browser client; the session cookie is still required
        return urlparse(origin).netloc == request.headers.get("host", "")

    async def read_json(request: Request) -> Dict[str, Any]:
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            raise ValueError("body too large")
        if not body:
            return {}
        import json
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("JSON object expected")
        return data

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        public = path in ("/api/login", "/api/health") or path.startswith("/api/ingest/")
        if path.startswith("/api/"):
            if request.method not in ("GET", "HEAD") and not same_origin(request):
                return err("Cross-origin request refused.", 403)
            if not public:
                sess = state.get_session(request.cookies.get(SESSION_COOKIE))
                if not sess:
                    return err("Not signed in.", 401)
                request.state.session = sess
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if path.startswith("/api/") or path.startswith(("/js/", "/css/")):
            response.headers["Cache-Control"] = "no-store"
        if response.headers.get("content-type", "").startswith("text/html"):
            response.headers["Content-Security-Policy"] = CSP
            response.headers["Cache-Control"] = "no-store"
        return response

    # ---- pages ---------------------------------------------------------------
    @app.get("/")
    async def index(request: Request):
        signed_in = state.get_session(request.cookies.get(SESSION_COOKIE)) is not None
        return FileResponse(STATIC_DIR / ("dashboard.html" if signed_in else "login.html"))

    @app.get("/login.js")
    async def login_js():
        return FileResponse(STATIC_DIR / "login.js")

    app.mount("/css", StaticFiles(directory=STATIC_DIR / "css"), name="css")
    app.mount("/js", StaticFiles(directory=STATIC_DIR / "js"), name="js")

    # ---- auth ----------------------------------------------------------------
    @app.post("/api/login")
    async def login(request: Request):
        ip = client_ip(request)
        wait = state.retry_after(ip)
        if wait:
            return err("Too many attempts. Try again later.", 429, **{"Retry-After": str(wait)})
        try:
            body = await read_json(request)
        except ValueError:
            return err("Invalid request.", 400)
        username, password = body.get("username"), body.get("password")
        if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
            return err("Enter your username and password.", 400)
        user = store.verify_user(username, password)
        if user is None:
            state.record_failure(ip)
            return err("Invalid username or password.", 401)
        state.clear_failures(ip)
        sid = state.new_session(user)
        resp = JSONResponse({"ok": True})
        resp.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="strict", path="/",
                        secure=request.url.scheme == "https", max_age=SESSION_HOURS * 3600)
        return resp

    @app.post("/api/logout")
    async def logout(request: Request):
        state.end_session(request.cookies.get(SESSION_COOKIE))
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.get("/api/session")
    async def session(request: Request):
        s = request.state.session
        return {"ok": True, "user": s["user"], "sessionHours": SESSION_HOURS, "idleMinutes": IDLE_MINUTES,
                "avatarColor": "", "avatarInitials": s["user"][:2].upper()}

    @app.get("/api/health")
    async def health():
        return {"ok": True}

    @app.post("/api/account/password")
    async def account_password(request: Request):
        try:
            body = await read_json(request)
            store.change_password(request.state.session["user"], str(body.get("current", "")), str(body.get("new", "")))
        except ValueError as exc:
            return err(str(exc), 400)
        return {"ok": True}

    # ---- data ----------------------------------------------------------------
    @app.get("/api/overview")
    async def overview():
        return overview_payload(state.engine)

    @app.get("/api/alerts")
    async def alerts(request: Request):
        q = request.query_params
        rows = list(state.engine.alerts)
        if q.get("selfTest") == "0":
            rows = [a for a in rows if not a.SelfTest]
        elif q.get("selfTest") == "1":
            rows = [a for a in rows if a.SelfTest]
        if q.get("since", "").isdigit() and int(q["since"]) > 0:
            rows = [a for a in rows if a.Id > int(q["since"])]
        if q.get("limit", "").isdigit() and int(q["limit"]) > 0:
            rows = rows[-int(q["limit"]):]
        return [alert_row(a) for a in rows]

    def _alert_or_404(alert_id: int):
        return state.engine.get_alert(alert_id)

    @app.post("/api/alerts/{alert_id}/ack")
    async def ack(alert_id: int):
        a = _alert_or_404(alert_id)
        if not a:
            return err("Alert not found.", 404)
        a.Acknowledged = True
        return {"ok": True, "acknowledged": True}

    @app.post("/api/alerts/{alert_id}/unack")
    async def unack(alert_id: int):
        a = _alert_or_404(alert_id)
        if not a:
            return err("Alert not found.", 404)
        a.Acknowledged = False
        return {"ok": True, "acknowledged": False}

    @app.post("/api/alerts/{alert_id}/status")
    async def set_status(alert_id: int, request: Request):
        a = _alert_or_404(alert_id)
        if not a:
            return err("Alert not found.", 404)
        try:
            body = await read_json(request)
        except ValueError:
            return err("Invalid request.", 400)
        if body.get("status") in ALERT_STATUSES:
            a.Status = body["status"]
        if body.get("notes") is not None:
            a.Notes = str(body["notes"])[:4000]
        return {"ok": True, "id": alert_id, "status": a.Status, "notes": a.Notes}

    @app.get("/api/events")
    async def events(request: Request):
        payload = events_payload(state.engine, request.query_params)
        if "error" in payload:
            return err(payload["error"], 400)
        return payload

    @app.get("/api/hosts")
    async def hosts():
        rows = [{"host": h["host"], "eventCount": h["events"], "alertCount": h["alerts"],
                 "lastSeen": h.get("lastSeen", "")} for h in state.engine.hosts.values()]
        return sorted(rows, key=lambda r: (r["alertCount"] * 1_000_000 + r["eventCount"]), reverse=True)

    @app.get("/api/rules")
    async def rules():
        return rules_payload(state.engine)

    @app.get("/api/settings")
    async def settings():
        return settings_payload(state)

    @app.get("/api/settings/gemini-key/status")
    async def gemini_status():
        return {"keySet": bool(store.get_gemini_key())}

    @app.post("/api/settings/gemini-key")
    async def gemini_save(request: Request):
        try:
            body = await read_json(request)
        except ValueError:
            return err("Invalid request.", 400)
        key = str(body.get("apiKey", "")).strip()
        if not re.fullmatch(r"[\x21-\x7e]{20,300}", key):
            return err("That does not look like an API key (no spaces, 20-300 characters).", 400)
        store.set_gemini_key(key)
        return {"ok": True}

    @app.get("/api/settings/gemini-model")
    async def gemini_model_get():
        from alpha_sentinel.assistant import STATIC_MODELS, list_gemini_models, list_openai_models
        key = store.get_gemini_key()
        cfg = store.get_ai_provider()
        if key and cfg["provider"] == "openai" and cfg["baseUrl"]:
            choices = await asyncio.to_thread(list_openai_models, key, cfg["baseUrl"])
        elif key:
            choices = await asyncio.to_thread(list_gemini_models, key)
        else:
            choices = STATIC_MODELS
        cur = store.get_gemini_model()
        choices = list(choices or STATIC_MODELS)
        if cur not in choices:
            choices = [cur] + choices
        return {"model": cur, "choices": choices, "provider": cfg["provider"], "baseUrl": cfg["baseUrl"]}

    @app.post("/api/settings/gemini-model")
    async def gemini_model_set(request: Request):
        try:
            body = await read_json(request)
        except ValueError:
            return err("Invalid request.", 400)
        model = str(body.get("model", "")).strip()
        if not re.fullmatch(r"[A-Za-z0-9._:/\-]{3,100}", model):
            return err("Model name may contain only letters, digits and . _ : / -", 400)
        provider = str(body.get("provider", "gemini"))
        base = str(body.get("baseUrl", "")).strip()
        if provider not in ("gemini", "openai"):
            return err("Unknown provider.", 400)
        if provider == "openai":
            u = urlparse(base)
            if u.scheme not in ("http", "https") or not u.netloc:
                return err("Base URL must start with http:// or https:// (for example https://host/v1).", 400)
        store.set_ai_provider(provider, base if provider == "openai" else "")
        store.set_gemini_model(model)
        return {"ok": True, "model": model}

    @app.post("/api/settings/gemini-key/clear")
    async def gemini_clear():
        store.set_gemini_key("")
        return {"ok": True}

    @app.post("/api/account/username")
    async def account_username(request: Request):
        try:
            body = await read_json(request)
        except ValueError:
            return err("Invalid request.", 400)
        bad = reauth(request, body)
        if bad:
            return bad
        me = request.state.session["user"]
        try:
            store.rename_user(me, str(body.get("newName", "")).strip())
        except ValueError as exc:
            return err(str(exc), 400)
        new = str(body.get("newName", "")).strip()
        with state.lock:
            for sess in state.sessions.values():
                if sess["user"] == me:
                    sess["user"] = new
        return {"ok": True}

    @app.get("/api/chains")
    async def chains():
        return []

    @app.get("/api/assets")
    async def assets(request: Request):
        return {"assets": [], "count": 0, "total": 0, "limit": 100, "kind": request.query_params.get("kind", "host")}

    @app.get("/api/preflight")
    async def preflight():
        return {"checkedAt": None, "readable": False, "rulesTotal": len(_all_rule_meta()),
                "okCount": len(_all_rule_meta()), "blindCount": 0, "unknownCount": 0, "fix": [], "rules": []}

    # ---- Wolf assistant --------------------------------------------------------
    @app.post("/api/bot/ask")
    async def bot_ask(request: Request):
        from alpha_sentinel.assistant import answer
        try:
            body = await read_json(request)
        except ValueError:
            return err("Invalid request.", 400)
        question = str(body.get("question", ""))[:500]
        rules = _all_rule_meta()
        from alpha_sentinel.collectors import DEFAULT_SOURCES
        from alpha_sentinel.health import check_log_sources
        from alpha_sentinel.selftest import run_selftest
        turns = []
        raw_hist = body.get("history")
        if isinstance(raw_hist, list):
            for t in raw_hist[-6:]:
                if isinstance(t, dict) and t.get("role") in ("user", "assistant") and isinstance(t.get("text"), str):
                    turns.append({"role": t["role"], "text": t["text"][:500]})
        extra = {"history": turns, "collecting": state.collecting, "selftest": run_selftest(),
                 "health": await asyncio.to_thread(check_log_sources, state.config.get("log_sources", DEFAULT_SOURCES))}
        key = store.get_gemini_key()
        if key and question.strip():
            from alpha_sentinel import assistant as asst
            cfg = store.get_ai_provider()
            try:
                if cfg["provider"] == "openai" and cfg["baseUrl"]:
                    text = await asyncio.to_thread(asst.ask_openai, question, state.engine, rules, key,
                                                   store.get_gemini_model(), cfg["baseUrl"], 30, extra)
                else:
                    text = await asyncio.to_thread(asst.ask_gemini, question, state.engine, rules, key,
                                                   store.get_gemini_model(), 20, extra)
                return {"answer": text}
            except Exception as exc:  # noqa: BLE001
                reason = str(exc).replace(key, "***")[:300]
                local = answer(question, state.engine, rules, extra)
                return {"answer": local + f"\n\n(The AI did not answer, so this is the built-in answer. Reason: {reason})"}
        return {"answer": answer(question, state.engine, rules, extra)}

    # ---- dashboard users -------------------------------------------------------
    def reauth(request: Request, body: Dict[str, Any]):
        """Managing accounts needs the signed-in user's password again."""
        ip = client_ip(request)
        wait = state.retry_after(ip)
        if wait:
            return err(f"Too many attempts. Try again in {wait}s.", 429, **{"Retry-After": str(wait)})
        me = request.state.session["user"]
        if not store.verify_user(me, str(body.get("password", ""))):
            state.record_failure(ip)
            return err("Your password is incorrect.", 403)
        state.clear_failures(ip)
        return None

    @app.get("/api/users")
    async def users_list(request: Request):
        return store.list_users(request.state.session["user"])

    @app.post("/api/users")
    async def users_add(request: Request):
        try:
            body = await read_json(request)
        except ValueError:
            return err("Invalid request.", 400)
        bad = reauth(request, body)
        if bad:
            return bad
        try:
            store.create_user(str(body.get("name", "")).strip(), str(body.get("newPassword", "")))
        except ValueError as exc:
            return err(str(exc), 400)
        return {"ok": True}

    @app.post("/api/users/{name}/reset")
    async def users_reset(name: str, request: Request):
        try:
            body = await read_json(request)
        except ValueError:
            return err("Invalid request.", 400)
        bad = reauth(request, body)
        if bad:
            return bad
        try:
            store.reset_password(name, str(body.get("newPassword", "")))
        except ValueError as exc:
            return err(str(exc), 400)
        state.end_sessions_for(name)
        return {"ok": True}

    @app.post("/api/users/{name}/remove")
    async def users_remove(name: str, request: Request):
        try:
            body = await read_json(request)
        except ValueError:
            return err("Invalid request.", 400)
        if name == request.state.session["user"]:
            return err("You cannot remove the account you are signed in with.", 400)
        bad = reauth(request, body)
        if bad:
            return bad
        try:
            store.remove_user(name)
        except ValueError as exc:
            return err(str(exc), 400)
        state.end_sessions_for(name)
        return {"ok": True}

    @app.post("/api/selftest")
    async def selftest():
        from alpha_sentinel.selftest import run_selftest
        return run_selftest()

    # ---- log source readiness (Linux "audit") ----------------------------------
    @app.get("/api/audit")
    async def audit():
        from alpha_sentinel.collectors import DEFAULT_SOURCES
        from alpha_sentinel.health import check_log_sources
        sources = state.config.get("log_sources", DEFAULT_SOURCES)
        return await asyncio.to_thread(check_log_sources, sources)

    # ---- collector forwarding ----------------------------------------------------
    @app.post("/api/ingest/alert")
    async def ingest_alert(request: Request):
        if not state.collector_key:
            return err("Collector forwarding is not configured (set ALPHA_SENTINEL_COLLECTOR_KEY).", 503)
        provided = request.headers.get("x-alpha-collector-key", "")
        if not hmac.compare_digest(provided.encode(), state.collector_key.encode()):
            return err("Invalid or missing collector key.", 401)
        try:
            body = await read_json(request)
        except ValueError:
            return err("Invalid request.", 400)
        alert = state.engine.add_external_alert(body)
        return {"ok": True, "id": alert.Id}

    # ---- everything else the Windows dashboard can call ---------------------------
    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def not_available(rest: str):
        return JSONResponse(NOT_AVAILABLE, status_code=501)

    return app


def run_server(host: str = "127.0.0.1", port: int = 8443, config: Optional[str] = None,
               collect: bool = False) -> None:
    if not FASTAPI_AVAILABLE:
        raise SystemExit("FastAPI/uvicorn not installed. Run: pip install fastapi 'uvicorn[standard]'")
    import asyncio
    import logging
    import uvicorn
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not store.has_users():
        raise SystemExit("No dashboard account exists. Create one first:  alpha-sentinel create-admin")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: binding to {host}. The dashboard is plain HTTP - put TLS in front of it "
              "(reverse proxy) or use an SSH tunnel.")
    from alpha_sentinel.collectors import load_config
    state = AppState(host=host, port=port, config=load_config(config))
    app = create_app(state)
    state.collecting = collect

    if collect:
        from alpha_sentinel.collectors import LogCollector
        collector = LogCollector(load_config(config), engine=state.engine)

        @app.on_event("startup")
        async def _start_collector():
            app.state.collector_task = asyncio.create_task(collector.run())

        @app.on_event("shutdown")
        async def _stop_collector():
            collector.stop()

    print(f"Alpha Sentinel {__version__} on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
