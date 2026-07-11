"""Append-only JSON Lines audit trail for every attempted scan."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def log_attempt(path: str, target: str, authorization_reference: str | None, outcome: str) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "authorization_reference": authorization_reference or "NOT_PROVIDED",
        "outcome": outcome,
    }
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
