from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from src.config.models import AdversaConfig


class ConfigError(Exception):
    pass


def _interpolate_env_vars(raw: str) -> str:
    def replace(match: re.Match) -> str:
        key = match.group(1)
        val = os.environ.get(key)
        if val is None:
            raise ConfigError(f"Missing required environment variable: ${{{key}}}")
        return val

    return re.sub(r"\$\{(\w+)\}", replace, raw)


def load_config(path: str) -> AdversaConfig:
    from dotenv import load_dotenv
    load_dotenv()
    with open(path) as f:
        raw = f.read()
    resolved = _interpolate_env_vars(raw)
    data = yaml.safe_load(resolved)
    try:
        return AdversaConfig.model_validate(data)
    except ValidationError as e:
        raise ConfigError(f"Invalid config:\n{e}") from e


def load_config_from_bytes(content: bytes) -> AdversaConfig:
    """Used by the FastAPI upload endpoint."""
    resolved = _interpolate_env_vars(content.decode())
    data = yaml.safe_load(resolved)
    try:
        return AdversaConfig.model_validate(data)
    except ValidationError as e:
        raise ConfigError(f"Invalid config:\n{e}") from e


def finalise_engagement_id(config: AdversaConfig, repo_path: str) -> str:
    """
    Called in Phase 0 once repo path is known.
    Produces: adv-{repo-name}-{YYYYMMDD-HHmm}
    If user provided a real custom ID, return it unchanged.
    """
    # Auto-generated IDs start with "adv-YYYYMMDD" (8 digit date)
    if not re.match(r"adv-\d{8}-", config.meta.engagement_id):
        return config.meta.engagement_id  # user-provided — keep it
    repo_name = re.sub(r"[^a-z0-9]", "-", Path(repo_path).name.lower()).strip("-")
    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return f"adv-{repo_name}-{ts}"
