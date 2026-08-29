"""Runtime configuration and store path resolution."""

from __future__ import annotations

import os
from pathlib import Path


def data_home() -> Path:
    """Return the OpenSystem data directory.

    Resolution order:
      1. $OPENSYSTEM_HOME if set
      2. ./.os if it already exists (project-local mode)
      3. ~/.local/share/opensystem (XDG data home)
    """
    env = os.environ.get("OPENSYSTEM_HOME")
    if env:
        path = Path(env).expanduser()
        path.mkdir(parents=True, exist_ok=True)
        return path

    project_local = Path.cwd() / ".os"
    if project_local.exists():
        return project_local

    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    path = base / "opensystem"
    path.mkdir(parents=True, exist_ok=True)
    return path


def store_path() -> str:
    """Return the default knowledge-store path."""
    return str(data_home() / "opensystem.db")
