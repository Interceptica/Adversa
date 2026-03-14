from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    def __init__(self, log_path: str) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_scope_block(
        self, url: str, reason: str, tool: str, agent: str = ""
    ) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "scope_blocked",
            "url": url,
            "reason": reason,
            "tool": tool,
            "agent": agent,
        }
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
