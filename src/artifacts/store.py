"""
Artifact store — typed JSON persistence for inter-phase communication.

All artifacts are written to ./runs/{engagement_id}/artifacts/{artifact_type}.json
and read by subsequent phases. Docker volume ./runs:/app/runs is already mounted.
"""
from __future__ import annotations

import json
from pathlib import Path


class ArtifactStore:
    """Read/write JSON artifacts scoped to an engagement run."""

    def __init__(self, engagement_id: str, base_dir: str = "./runs") -> None:
        self._dir = Path(base_dir) / engagement_id / "artifacts"

    def write(self, artifact_type: str, data: dict) -> Path:
        """Write a JSON artifact. Creates directories as needed."""
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._dir / f"{artifact_type}.json"
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return path

    def read(self, artifact_type: str) -> dict:
        """Read a JSON artifact. Raises FileNotFoundError if missing."""
        path = self._dir / f"{artifact_type}.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def exists(self, artifact_type: str) -> bool:
        """Check if an artifact exists."""
        return (self._dir / f"{artifact_type}.json").is_file()
