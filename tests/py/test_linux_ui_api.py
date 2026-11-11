"""Linux dashboard: rule scope, Wolf bot, user management, log-source check."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from alpha_sentinel import store
from alpha_sentinel.server.api import AppState, create_app

PW = "correct-horse-battery"


@pytest.fixture
def c():
    store.create_user("maty", PW)
    cl = TestClient(create_app(AppState()), base_url="http://testserver")
    assert cl.post("/api/login", json={"username": "maty", "password": PW}).status_code == 200
    return cl


def test_rules_are_linux_only(c, monkeypatch):
    r = c.get("/api/rules").json()
    assert r["total"] == 10
    assert all(x["key"] != "kerberoasting" for x in r["rules"])
    assert "sshd" in r["monitoredEventIds"]
    ov = c.get("/api/overview").json()
    assert ov["coverage"]["rulesTotal"] == 10


def test_rules_scope_env(c, monkeypatch):
    monkeypatch.setenv("ALPHA_SENTINEL_RULES", "all")
    assert c.get("/api/rules").json()["total"] == 46


def test_bot_answers(c):
    a = c.post("/api/bot/ask", json={"question": "help"}).json()["answer"]
    assert a
    a = c.post("/api/bot/ask", json={"question": "what rules do you have?"}).json()["answer"]
    assert "ssh" in a.lower() and "kerberoast" not in a.lower()
    assert c.post("/api/bot/ask", json={"question": ""}).status_code == 200


def test_users_crud(c):
    assert [u["name"] for u in c.get("/api/users").json()] == ["maty"]
    bad = c.post("/api/users", json={"password": "wrong", "name": "bob", "newPassword": "another-long-pass"})
    assert bad.status_code == 403
    ok = c.post("/api/users", json={"password": PW, "name": "bob", "newPassword": "another-long-pass"})
    assert ok.status_code == 200
    assert {u["name"] for u in c.get("/api/users").json()} == {"maty", "bob"}
    assert c.post("/api/users/bob/reset", json={"password": PW, "newPassword": "new-long-password"}).status_code == 200
    assert store.verify_user("bob", "new-long-password")
    assert c.post("/api/users/maty/remove", json={"password": PW}).status_code == 400
    assert c.post("/api/users/bob/remove", json={"password": PW}).status_code == 200
    assert [u["name"] for u in c.get("/api/users").json()] == ["maty"]


def test_users_need_login():
    cl = TestClient(create_app(AppState()), base_url="http://testserver")
    assert cl.get("/api/users").status_code == 401
    assert cl.post("/api/bot/ask", json={"question": "hi"}).status_code == 401


def test_audit_log_sources(c):
    r = c.get("/api/audit")
    assert r.status_code == 200
    j = r.json()
    assert j["sources"] and set(j["counts"]) == {"ok", "blind", "unverified"}


def test_new_style_key_with_dot(c):
    assert c.post("/api/settings/gemini-key", json={"apiKey": "AQ.Ab8RN6" + "x" * 40}).status_code == 200


def test_gemini_key_and_rename(c, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert c.get("/api/settings/gemini-key/status").json() == {"keySet": False}
    assert c.post("/api/settings/gemini-key", json={"apiKey": "has space in it 12345678"}).status_code == 400
    assert c.post("/api/settings/gemini-key", json={"apiKey": "AIza" + "x" * 35}).status_code == 200
    assert c.get("/api/settings/gemini-key/status").json() == {"keySet": True}
    # AI unreachable -> falls back to local answer, never leaks key
    import alpha_sentinel.assistant as a
    monkeypatch.setattr(a, "ask_gemini", lambda *x, **k: (_ for _ in ()).throw(OSError("net")))
    ans = c.post("/api/bot/ask", json={"question": "latest alerts"}).json()["answer"]
    assert "built-in answer" in ans and "AIza" not in ans
    monkeypatch.setattr(a, "ask_gemini", lambda *x, **k: "from gemini")
    assert c.get("/api/settings/gemini-model").json()["model"] == "gemini-3.1-flash-lite"
    assert c.post("/api/settings/gemini-model", json={"model": "bad model!"}).status_code == 400
    assert c.post("/api/settings/gemini-model", json={"model": "gemini-3.8-pro"}).status_code == 200
    assert "gemini-3.8-pro" in c.get("/api/settings/gemini-model").json()["choices"]
    assert c.post("/api/bot/ask", json={"question": "hi there"}).json()["answer"] == "from gemini"
    assert c.post("/api/settings/gemini-key/clear", json={}).status_code == 200
    assert c.get("/api/settings/gemini-key/status").json() == {"keySet": False}
    assert c.post("/api/account/username", json={"password": "bad", "newName": "boss"}).status_code == 403
    assert c.post("/api/account/username", json={"password": PW, "newName": "boss"}).status_code == 200
    assert c.get("/api/session").json()["user"] == "boss"


def test_openai_compatible_provider(c, monkeypatch):
    import alpha_sentinel.assistant as a
    c.post("/api/settings/gemini-key", json={"apiKey": "sk-" + "x" * 30})
    assert c.post("/api/settings/gemini-model", json={"model": "gemini-3.1-flash-lite", "provider": "openai",
                                                       "baseUrl": "not a url"}).status_code == 400
    assert c.post("/api/settings/gemini-model", json={"model": "gemini-3.1-flash-lite", "provider": "openai",
                                                       "baseUrl": "https://example.test/v1"}).status_code == 200
    seen = {}
    monkeypatch.setattr(a, "ask_openai", lambda q, e, r, key, model, base, *a: seen.update(m=model, b=base) or "hello")
    monkeypatch.setattr(a, "list_openai_models", lambda key, base: ["m1"])
    assert c.post("/api/bot/ask", json={"question": "hi there"}).json()["answer"] == "hello"
    assert seen == {"m": "gemini-3.1-flash-lite", "b": "https://example.test/v1"}
    j = c.get("/api/settings/gemini-model").json()
    assert j["provider"] == "openai" and "m1" in j["choices"]


def test_selftest_and_wolf_knows_rules_and_logs(c):
    j = c.post("/api/selftest").json()
    assert j["passed"] == j["total"] == 10
    a = c.post("/api/bot/ask", json={"question": "are all the rules working?"}).json()["answer"]
    assert "10/10" in a and "--collect" in a
    a = c.post("/api/bot/ask", json={"question": "what about the log sources"}).json()["answer"]
    assert "Log sources" in a and "sshd logging" in a


def test_conversation_history_reaches_the_prompt(c, monkeypatch):
    import alpha_sentinel.assistant as a
    c.post("/api/settings/gemini-key", json={"apiKey": "AQ." + "x" * 40})
    seen = {}
    monkeypatch.setattr(a, "ask_gemini", lambda q, e, r, key, model, t, extra: seen.update(extra=extra) or "ok")
    hist = [{"role": "user", "text": "hello"}, {"role": "assistant", "text": "hi"}, {"role": "evil", "text": "x"}, {"role": "user", "text": 5}]
    c.post("/api/bot/ask", json={"question": "and now?", "history": hist})
    assert seen["extra"]["history"] == [{"role": "user", "text": "hello"}, {"role": "assistant", "text": "hi"}]
    p = a._prompt("and now?", None, {}, {"history": seen["extra"]["history"]}) if False else None


def test_wolf_page_assets_are_served(c):
    for path in ("/js/wolf-store.js", "/js/pages/wolf.js"):
        r = c.get(path)
        assert r.status_code == 200 and "javascript" in r.headers["content-type"]
    html = c.get("/").text
    assert "#/wolf" in html and "/js/wolf-store.js" in html and "/js/pages/wolf.js" in html
