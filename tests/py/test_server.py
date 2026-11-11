import dataclasses

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from alpha_sentinel import store  # noqa: E402
from alpha_sentinel.engine import Engine  # noqa: E402
from alpha_sentinel.models import Event  # noqa: E402
from alpha_sentinel.rules import evaluate_event  # noqa: E402
from alpha_sentinel.server import AppState, create_app  # noqa: E402

PW = "correct horse battery"


@pytest.fixture
def client():
    store.create_user("maty", PW)
    state = AppState()
    return TestClient(create_app(state), base_url="http://testserver"), state


def login(c):
    r = c.post("/api/login", json={"username": "maty", "password": PW})
    assert r.status_code == 200, r.text
    return r


def test_api_requires_login(client):
    c, _ = client
    for path in ("/api/overview", "/api/alerts", "/api/events", "/api/rules", "/api/settings", "/api/session"):
        assert c.get(path).status_code == 401, path
    assert c.get("/api/health").status_code == 200


def test_any_credentials_are_not_accepted(client):
    c, _ = client
    assert c.post("/api/login", json={"username": "maty", "password": "wrong-password"}).status_code == 401
    assert c.post("/api/login", json={"username": "nobody", "password": PW}).status_code == 401
    assert c.post("/api/login", json={}).status_code == 400
    assert c.get("/api/session").status_code == 401


def test_session_cookie_is_httponly_strict_and_no_token_in_body(client):
    c, _ = client
    r = login(c)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert "access_token" not in r.text
    assert c.get("/api/session").json()["user"] == "maty"


def test_sessions_are_per_user_not_global(client):
    c, state = client
    login(c)
    other = TestClient(create_app(state))
    assert other.get("/api/session").status_code == 401
    assert "login" in other.get("/").text.lower()          # anonymous visitor still gets the login page
    assert "dashboard" in c.get("/").text.lower() or "Sentinel" in c.get("/").text


def test_logout_only_ends_own_session(client):
    c, state = client
    login(c)
    other = TestClient(create_app(state))
    other.post("/api/login", json={"username": "maty", "password": PW})
    c.post("/api/logout")
    assert c.get("/api/session").status_code == 401
    assert other.get("/api/session").status_code == 200


def test_login_is_rate_limited(client):
    c, _ = client
    codes = [c.post("/api/login", json={"username": "maty", "password": "bad-password-x"}).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and 429 in codes[5:]
    assert c.post("/api/login", json={"username": "maty", "password": PW}).status_code == 429


def test_cross_origin_post_is_refused(client):
    c, _ = client
    login(c)
    r = c.post("/api/logout", headers={"Origin": "http://evil.example"})
    assert r.status_code == 403
    assert c.get("/api/session").status_code == 200


def test_real_data_flows_to_overview_alerts_events_rules(client, monkeypatch):
    monkeypatch.setenv("ALPHA_SENTINEL_RULES", "all")
    c, state = client
    login(c)
    ev = Event(eventId="4720", hostname="DC01", accountName="attacker1", sourceIp="", channel="Security",
               timestamp="2026-03-04T09:15:00.0000000Z", subjectUserName="administrator")
    assert evaluate_event(state.engine, ev).RuleKey == "account_created"
    ov = c.get("/api/overview").json()
    assert ov["tiles"]["openAlerts"] == 1 and ov["tiles"]["hostsSeen"] == 1
    alerts = c.get("/api/alerts").json()
    assert alerts[0]["RuleKey"] == "account_created" and alerts[0]["Mitre"]
    assert c.get("/api/events").json()["total"] == 1
    assert c.get("/api/events?eventId=abc").status_code == 400
    rules = c.get("/api/rules").json()
    assert rules["total"] == 46 and rules["firedTotal"] == 1
    assert c.get("/api/hosts").json()[0]["alertCount"] == 1


def test_alert_ack_and_status(client):
    c, state = client
    login(c)
    ev = Event(eventId="4720", hostname="DC01", accountName="a", sourceIp="", channel="Security",
               timestamp="2026-03-04T09:15:00.0000000Z")
    evaluate_event(state.engine, ev)
    assert c.post("/api/alerts/1/ack").json()["acknowledged"] is True
    assert c.post("/api/alerts/1/status", json={"status": "Resolved", "notes": "ok"}).json()["status"] == "Resolved"
    assert c.post("/api/alerts/99/ack").status_code == 404
    assert c.get("/api/overview").json()["tiles"]["openAlerts"] == 0


def test_ingest_needs_the_collector_key(client):
    c, state = client
    alert = {"RuleKey": "ssh_bruteforce", "Severity": "High", "Description": "x", "Host": "h", "Time": "2026-01-01T00:00:00+00:00"}
    assert c.post("/api/ingest/alert", json=alert).status_code == 503          # not configured
    state.collector_key = "s3cret-key"
    assert c.post("/api/ingest/alert", json=alert).status_code == 401
    r = c.post("/api/ingest/alert", json=alert, headers={"X-Alpha-Collector-Key": "s3cret-key"})
    assert r.status_code == 200 and len(state.engine.alerts) == 1
    login(c)
    assert c.get("/api/alerts").json()[0]["RuleKey"] == "ssh_bruteforce"


def test_unsupported_endpoints_return_clean_json_not_html(client):
    c, _ = client
    login(c)
    r = c.get("/api/report")
    assert r.status_code == 501 and r.json()["error"]


def test_security_headers(client):
    c, _ = client
    r = c.get("/")
    assert r.headers["x-frame-options"] == "DENY" and "default-src 'self'" in r.headers["content-security-policy"]


def test_password_change(client):
    c, _ = client
    login(c)
    assert c.post("/api/account/password", json={"current": "nope", "new": "another long password"}).status_code == 400
    assert c.post("/api/account/password", json={"current": PW, "new": "another long password"}).status_code == 200
    assert store.verify_user("maty", "another long password")
    assert store.verify_user("maty", PW) is None


def test_store_password_rules():
    for bad in ("short", "maty-maty-maty"[:0] + "maty"):
        with pytest.raises(ValueError):
            store.create_user("maty", bad)
    store.create_user("maty", PW)
    with pytest.raises(ValueError):
        store.create_user("MATY", PW)           # case-insensitive duplicate
    assert oct(store.state_dir().joinpath("users.json").stat().st_mode & 0o777) == "0o600"
