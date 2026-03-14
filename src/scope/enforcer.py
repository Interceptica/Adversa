from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlparse

from src.config.models import AdversaConfig, ScopeConfig


@dataclass
class ScopeResult:
    allowed: bool
    reason: str | None = None


class ScopeEnforcer:
    def __init__(
        self,
        config: ScopeConfig,
        included_hosts: list[str],
        excluded_hosts: list[str],
    ) -> None:
        self.config = config
        self.included_hosts = set(included_hosts)
        self.excluded_hosts = set(excluded_hosts)
        self.excluded_paths = {
            r.url_path for r in config.rules.avoid if r.type == "path"
        }
        self.excluded_patterns = [
            r.url_path for r in config.rules.avoid if r.type == "path_pattern"
        ]

    def check(self, url: str) -> ScopeResult:
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path

        if self.included_hosts and host not in self.included_hosts:
            return ScopeResult(False, f"Host '{host}' not in included_hosts")
        if host in self.excluded_hosts:
            return ScopeResult(False, f"Host '{host}' is explicitly excluded")
        if path in self.excluded_paths:
            return ScopeResult(False, f"Path '{path}' is excluded")
        for pattern in self.excluded_patterns:
            if fnmatch(path, pattern):
                return ScopeResult(
                    False, f"Path '{path}' matches excluded pattern '{pattern}'"
                )
        return ScopeResult(True)

    def to_json(self) -> dict:
        """Serialise for SCOPE_MANIFEST artifact and system prompt injection."""
        return {
            "included_hosts": list(self.included_hosts),
            "excluded_hosts": list(self.excluded_hosts),
            "excluded_paths": list(self.excluded_paths),
            "excluded_patterns": self.excluded_patterns,
            "avoid_rules": [
                {"description": r.description, "type": r.type, "url_path": r.url_path}
                for r in self.config.rules.avoid
            ],
            "focus_rules": [
                {"description": r.description, "type": r.type, "url_path": r.url_path}
                for r in self.config.rules.focus
            ],
        }

    @classmethod
    def from_config(cls, config: AdversaConfig) -> ScopeEnforcer:
        return cls(config.scope, config.target.included_hosts, config.target.excluded_hosts)


def _extract_url(input_data: dict) -> str | None:
    """Extract URL from tool input dict. Checks common key names."""
    for key in ("url", "target", "endpoint", "base_url", "file_path"):
        if key in input_data and isinstance(input_data[key], str):
            val = input_data[key]
            if val.startswith("http://") or val.startswith("https://"):
                return val
    return None
