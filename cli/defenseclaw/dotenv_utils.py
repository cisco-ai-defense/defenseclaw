"""Shared dotenv file helpers for CLI commands."""

from __future__ import annotations

import os
from pathlib import Path


def persist_env_var(env_path: Path, key: str, value: str) -> None:
    """Append or update a KEY=VALUE line in a dotenv file."""
    env_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    found = False
    if env_path.exists():
        lines = env_path.read_text().splitlines()
        new_lines: list[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(f"{key}=") or stripped.startswith(f"export {key}="):
                new_lines.append(f"{key}={value}")
                found = True
            else:
                new_lines.append(line)
        lines = new_lines

    if not found:
        lines.append(f"{key}={value}")

    content = "\n".join(lines) + "\n"

    # Atomic write with correct permissions from creation (avoids TOCTOU race)
    fd = os.open(str(env_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(content)

    actual = os.stat(str(env_path)).st_mode & 0o777
    if actual != 0o600:
        import logging
        logging.getLogger(__name__).warning(
            "Env file %s has mode %o, expected 0600", env_path, actual
        )
