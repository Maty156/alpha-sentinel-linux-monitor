"""Wolf - the dashboard's built-in assistant.

Answers questions from the live engine state with simple intent matching. It runs
entirely locally: no external AI service, no network, nothing leaves the machine.
"""

import re
from collections import Counter
from typing import Any, Callable, Dict, List

from alpha_sentinel.engine import SEVERITY_ORDER, Engine

Rules = Dict[str, Dict[str, Any]]

HELP = ("I can answer from this monitor's live data. Try:\n"
        "- \"how many alerts?\" / \"any critical alerts?\"\n"
        "- \"latest alerts\"\n"
        "- \"which host has the most alerts?\"\n"
        "- \"what rules do you have?\" / \"explain ssh_bruteforce\"\n"
        "- \"what should I do about alert 3?\"\n"
        "- \"is everything covered?\"")


def _open(engine: Engine):
    return [a for a in engine.alerts if not a.SelfTest and a.Status in ("New", "Investigating", "")]


def _fmt(a) -> str:
    who = a.Account or a.SourceIp or a.Host
    return f"#{a.Id} [{a.Severity}] {a.Title} - {who} on {a.Host}"


def _find_rule(q: str, rules: Rules):
    q = q.lower()
    for key, m in rules.items():
        if key in q or key.replace("_", " ") in q or (m.get("title") and m["title"].lower() in q):
            return key, m
    return None, None


def answer(question: str, engine: Engine, rules: Rules, extra: Dict[str, Any] = None) -> str:
    q = (question or "").strip()
    ql = q.lower()
    if not ql:
        return HELP
    if re.search(r"\b(hi|hello|hey|help|what can you do)\b", ql) and len(ql) < 40:
        return HELP

    extra = extra or {}
    health, st = extra.get("health"), extra.get("selftest")
    if re.search(r"log source|log file|auth\.log|journal|audit", ql) and health:
        rows = health.get("sources", [])
        out = [f"- {r['name']}: {r['state'].upper()} - {r.get('detail', '')}" for r in rows]
        return "Log sources:\n" + "\n".join(out) + ("\n\nFix a blind source in Settings > Log sources." if health["counts"]["blind"] else "")
    if re.search(r"verify|self.?test|working|work\b|health|test", ql) and re.search(r"rule|detect|everything|all", ql) and st:
        bad = [r for r in st["results"] if not r["ok"]]
        msg = f"Self-test: {st['passed']}/{st['total']} rules fire correctly on synthetic log lines."
        if bad:
            msg += "\nFailing: " + ", ".join(f"{r['key']} ({r['detail']})" for r in bad)
        if extra.get("collecting") is False:
            msg += "\nNote: this server is not reading logs (started without --collect), so no real events will arrive."
        if health and health["counts"]["blind"]:
            msg += f"\n{health['counts']['blind']} log source(s) are blind - see Settings > Log sources."
        return msg

    # explicit alert number: remediation / details
    m = re.search(r"(?:alert|#)\s*(\d+)", ql)
    if m:
        a = engine.get_alert(int(m.group(1)))
        if not a:
            return f"I can't find alert #{m.group(1)} (alerts reset when the server restarts; history is in alerts.jsonl)."
        return (f"{_fmt(a)}\n\n{a.Description}\n\nMITRE: {a.Mitre or 'n/a'}\nWhat to do: {a.Remediation}\n"
                f"Seen {a.Count} time(s), last at {a.LastSeen or a.Time}.")

    key, meta = _find_rule(ql, rules)
    if key and re.search(r"explain|what is|what does|about|how|detect|mean", ql):
        return (f"{meta.get('title', key)} ({key}) - severity {meta.get('severity', '?')}.\n"
                f"{meta.get('description') or 'Detects ' + meta.get('title', key).lower() + '.'}\n"
                f"MITRE: {meta.get('mitre_id', '')} {meta.get('mitre_name', '')}\n"
                f"Fix: {meta.get('remediation', 'n/a')}\nFired {engine.rules_fired.get(key, 0)} time(s) so far.")

    if re.search(r"how many|count|number of|any (critical|high|alerts)|open alerts|are there", ql):
        op = _open(engine)
        if not engine.alerts:
            return "No alerts have fired yet - nothing suspicious has been detected."
        by = Counter(a.Severity for a in op)
        wanted = next((s for s in ("critical", "high", "medium", "low") if s in ql), None)
        if wanted:
            n = by.get(wanted.capitalize(), 0)
            return f"{n} open {wanted} alert(s)." + ("" if not n else " Ask for \"latest alerts\" to see them.")
        parts = ", ".join(f"{by[s]} {s.lower()}" for s in ("Critical", "High", "Medium", "Low") if by.get(s))
        return f"{len(op)} open alert(s) of {len(engine.alerts)} total" + (f": {parts}." if parts else ".")

    if re.search(r"latest|recent|last|newest|show.*alerts|list.*alerts", ql):
        rows = sorted(engine.alerts, key=lambda a: (-SEVERITY_ORDER.get(a.Severity, 0), -a.Id))[:5]
        return "No alerts yet." if not rows else "Top alerts (most severe first):\n" + "\n".join(f"- {_fmt(a)}" for a in rows)

    if re.search(r"host|machine|server|which.*most|noisiest|worst", ql):
        if not engine.hosts:
            return "No hosts have reported events yet."
        top = sorted(engine.hosts.values(), key=lambda h: (-h["alerts"], -h["events"]))[:5]
        return "Hosts by alerts:\n" + "\n".join(f"- {h['host']}: {h['alerts']} alert(s), {h['events']} event(s)" for h in top)

    if re.search(r"coverage|covered|blind|working|healthy|health", ql):
        return (f"{len(rules)} detection rules are loaded for this platform. See Settings -> Log sources for whether "
                "the logs they read are present and readable.")

    if re.search(r"rules|detections|what do you detect|what can you detect", ql):
        names = sorted(rules, key=lambda k: -SEVERITY_ORDER.get(rules[k].get("severity", ""), 0))
        return f"{len(rules)} rules:\n" + "\n".join(f"- {k}: {rules[k].get('title', k)} ({rules[k].get('severity', '?')})" for k in names)

    if re.search(r"attack (path|chain)|bloodhound|graph", ql):
        return "Attack paths and chains are not available in this build yet; the Attack Paths page shows an example only."

    return "I'm not sure about that one.\n\n" + HELP


import os
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def _context(engine: Engine, rules: Rules, extra: Dict[str, Any] = None) -> str:
    extra = extra or {}
    more = []
    if "collecting" in extra:
        more.append("Log collector: " + ("running (reading logs)" if extra["collecting"] else
                                         "NOT running - the server was started without --collect, so no events arrive"))
    if extra.get("health"):
        h = extra["health"]
        more.append("Log sources: " + "; ".join(f"{r['name']}={r['state']} ({r.get('detail', '')})" for r in h["sources"]))
    if extra.get("selftest"):
        st = extra["selftest"]
        more.append(f"Rule self-test (synthetic logs): {st['passed']}/{st['total']} rules fire correctly"
                    + ("" if st["passed"] == st["total"] else "; failing: " + ", ".join(r["key"] for r in st["results"] if not r["ok"])))
    fired = {k: engine.rules_fired.get(k, 0) for k in rules}
    more.append("Alerts fired per rule: " + ", ".join(f"{k}={v}" for k, v in fired.items()))
    rows = sorted((a for a in engine.alerts if not a.SelfTest),
                  key=lambda a: (-SEVERITY_ORDER.get(a.Severity, 0), -a.Id))[:15]
    lines = [f"Open alerts: {len(_open(engine))} of {len(engine.alerts)} total. Hosts seen: {len(engine.hosts)}.",
             "Rules: " + ", ".join(f"{k} ({m.get('severity', '?')})" for k, m in rules.items()),
             *more, "Top alerts:"] + [f"- {_fmt(a)} | {a.Description}"[:300] for a in rows]
    return "\n".join(lines)


def ask_gemini(question: str, engine: Engine, rules: Rules, key: str, model: str = "gemini-3.1-flash-lite",
               timeout: int = 20, extra: Dict[str, Any] = None) -> str:
    """Ask Gemini with a compact summary of current alerts. Raises on any failure."""
    import json
    import urllib.request
    prompt = _prompt(question, engine, rules, extra)
    body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode()
    req = urllib.request.Request(GEMINI_URL.format(model=model), data=body, method="POST",
                                 headers={"Content-Type": "application/json", "x-goog-api-key": key})
    import urllib.error
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            msg = json.loads(exc.read().decode()).get("error", {}).get("message", "")
        except Exception:  # noqa: BLE001
            msg = ""
        raise RuntimeError(f"Google returned HTTP {exc.code}: {msg}") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"cannot reach Google ({exc.reason})") from None
    try:
        return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except (KeyError, IndexError):
        raise RuntimeError("Gemini returned no text (blocked or empty response)") from None


STATIC_MODELS = ["gemini-3.1-flash-lite", "gemini-3.1-flash-lite-preview", "gemini-2.5-flash", "gemini-3.8-flash",
                 "gemini-flash-latest"]


def list_gemini_models(key: str, timeout: int = 10) -> List[str]:
    """Models this key can use for text generation (falls back to a static list)."""
    import json
    import urllib.request
    req = urllib.request.Request("https://generativelanguage.googleapis.com/v1beta/models?pageSize=200",
                                 headers={"x-goog-api-key": key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
        names = [m["name"].split("/", 1)[-1] for m in data.get("models", [])
                 if "generateContent" in m.get("supportedGenerationMethods", [])
                 and m["name"].split("/", 1)[-1].startswith("gemini")]
    except Exception:  # noqa: BLE001
        return STATIC_MODELS
    return sorted(set(names), reverse=True) or STATIC_MODELS


SYSTEM = (
    "You are Wolf, the built-in assistant of Alpha Sentinel, a Linux host attack detector. You are not Gemini "
    "or any other product; if asked, you are Wolf. Use ONLY the DATA section for facts about this machine.\n"
    "- Zero alerts does not mean a rule is broken: say so, and use the self-test line to say whether rules work "
    "and the log-collector and log-source lines to say whether real events can arrive.\n"
    "- To judge 'are the rules working', combine: self-test result, collector running or not, log sources state, "
    "and alerts fired per rule.\n"
    "- For log sources, report each source's state and the fix hint from DATA; blind means the log is missing or "
    "unreadable. A missing auth.log is fine if the systemd journal is working.\n"
    "- For how to attack-test or fix something, give short concrete steps. Never invent alerts, hosts or numbers.\n"
    "- Be concise: a short paragraph or a short list. Plain text, no markdown headings.")


def _prompt(question: str, engine: Engine, rules: Rules, extra: Dict[str, Any] = None) -> str:
    hist = ""
    turns = (extra or {}).get("history") or []
    if turns:
        hist = "\n\nCONVERSATION SO FAR (oldest first; for context only):\n" + "\n".join(
            f"{'Admin' if t['role'] == 'user' else 'Wolf'}: {t['text']}" for t in turns)
    return f"{SYSTEM}\n\nDATA:\n{_context(engine, rules, extra)}{hist}\n\nQUESTION: {question}"


def _http_json(req, timeout: int):
    import json
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - admin-configured URL
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode())
            err = body.get("error", {})
            msg = err.get("message", "") if isinstance(err, dict) else str(err)
        except Exception:  # noqa: BLE001
            msg = ""
        raise RuntimeError(f"HTTP {exc.code}: {msg}") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"cannot reach the server ({exc.reason})") from None


def ask_openai(question: str, engine: Engine, rules: Rules, key: str, model: str, base_url: str,
               timeout: int = 30, extra: Dict[str, Any] = None) -> str:
    """Any OpenAI-compatible endpoint (FreeLLMAPI, OpenRouter, local Ollama, ...)."""
    import json
    import urllib.request
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": _prompt(question, engine, rules, extra)}]}).encode()
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    data = _http_json(req, timeout)
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError, AttributeError):
        raise RuntimeError("the server returned no answer text") from None


def list_openai_models(key: str, base_url: str, timeout: int = 10) -> List[str]:
    import urllib.request
    req = urllib.request.Request(base_url.rstrip("/") + "/models", headers={"Authorization": f"Bearer {key}"})
    try:
        data = _http_json(req, timeout)
        return sorted({m["id"] for m in data.get("data", []) if "id" in m})
    except Exception:  # noqa: BLE001
        return []
