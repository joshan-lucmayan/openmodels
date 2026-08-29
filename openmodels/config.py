"""Runtime configuration and store path resolution."""

from __future__ import annotations

import os
from pathlib import Path


def data_home() -> Path:
    """Return the OpenModels data directory.

    Resolution order:
      1. $OPENMODELS_HOME if set
      2. ./.om if it already exists (project-local mode)
      3. ~/.local/share/openmodels (XDG data home)
    """
    env = os.environ.get("OPENMODELS_HOME")
    if env:
        path = Path(env).expanduser()
        path.mkdir(parents=True, exist_ok=True)
        return path

    project_local = Path.cwd() / ".om"
    if project_local.exists():
        return project_local

    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    path = base / "openmodels"
    path.mkdir(parents=True, exist_ok=True)
    return path


def store_path() -> str:
    """Return the default knowledge-store path."""
    return str(data_home() / "openmodels.db")
