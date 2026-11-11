"""Outputs - forwarding alerts to a running Alpha Sentinel dashboard."""

import dataclasses
import json
import logging
import urllib.error
import urllib.request
from typing import Callable

log = logging.getLogger("alpha_sentinel.outputs")


def make_forwarder(server_url: str, key: str, timeout: float = 3.0) -> Callable:
    """Return an on_alert callback that POSTs each alert to <server>/api/ingest/alert.

    Short timeout and swallowed (but logged) errors: a dead dashboard must never
    stall detection. The alert is already in local history either way.
    """
    url = server_url.rstrip("/") + "/api/ingest/alert"

    def forward(alert) -> None:
        body = json.dumps(dataclasses.asdict(alert), default=str).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST", headers={
            "Content-Type": "application/json", "X-Alpha-Collector-Key": key})
        try:
            with urllib.request.urlopen(req, timeout=timeout):
                pass
        except (urllib.error.URLError, OSError) as exc:
            log.warning("could not forward alert %s to %s: %s", alert.Id, url, exc)

    return forward
