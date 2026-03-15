"""
Joern CPG query helper — executes Joern queries against a built CPG.

Used by Phase 3 agents via the query_joern MCP tool.
NOT called during Phase 1 — built now for Phase 3 readiness.
"""
from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 120


async def run_joern_query(cpg_path: str, query: str) -> str:
    """
    Execute a Joern query against the given CPG.

    Args:
        cpg_path: Path to the CPG binary (e.g. ./runs/{id}/cpg.bin).
        query: Joern/CPGQL query string.

    Returns:
        Query result as a string.

    Raises:
        RuntimeError: If Joern exits with a non-zero code.
        asyncio.TimeoutError: If query exceeds timeout.
    """
    # Build the Joern script that loads the CPG and runs the query
    script = f'importCpg("{cpg_path}")\n{query}'

    cmd = ["joern", "--script", "/dev/stdin"]

    logger.info("Running Joern query on %s", cpg_path)

    proc = await asyncio.wait_for(
        asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        ),
        timeout=_TIMEOUT_SECONDS,
    )
    stdout, stderr = await proc.communicate(input=script.encode())

    if proc.returncode != 0:
        error_msg = stderr.decode(errors="replace").strip()
        raise RuntimeError(f"Joern query failed (exit {proc.returncode}): {error_msg}")

    return stdout.decode(errors="replace").strip()
