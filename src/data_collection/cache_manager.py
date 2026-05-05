"""Unified caching layer for all data collectors.

Stores and retrieves pickled Python objects (DataFrames, dicts, etc.)
under a configurable cache directory.  Thread-safe writes via
temporary file + atomic rename.
"""
from __future__ import annotations

import logging
import os
import pickle
import tempfile
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class CacheManager:
    """Disk-backed pickle cache keyed by human-readable strings."""

    def __init__(
        self,
        cache_dir: str = "data/raw/",
        enabled: bool = True,
        refresh: bool = False,
        reuse_recent_days: int = 7,
    ):
        self.cache_dir = Path(cache_dir)
        self.enabled = enabled
        self.refresh = refresh
        self.reuse_recent_days = reuse_recent_days
        if self.enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def exists(self, key: str) -> bool:
        """Return True when cached data can be reused for *key*."""
        if not self.enabled:
            return False

        path = self._path(key)
        if not path.exists():
            return False

        if self._is_recent(path):
            return True

        return not self.refresh

    def load(self, key: str) -> Any:
        """Load a previously cached object.  Raises FileNotFoundError if
        the cache file is missing."""
        path = self._path(key)
        logger.info("  cache hit: %s", path)
        with open(path, "rb") as fh:
            return pickle.load(fh)

    def save(self, key: str, data: Any) -> None:
        """Persist *data* under *key*.  Writes to a temporary file first,
        then renames for atomicity."""
        if not self.enabled:
            return
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Write to temp file in the same directory, then atomic rename
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as fh:
                pickle.dump(data, fh, protocol=pickle.HIGHEST_PROTOCOL)
            # On Windows, target must not exist for os.rename
            if path.exists():
                path.unlink()
            os.rename(tmp, str(path))
        except Exception:
            # Clean up the temp file on failure
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _path(self, key: str) -> Path:
        """Convert a human-readable key to a safe filesystem path."""
        safe = key.replace("/", "_").replace("\\", "_").replace(" ", "_")
        safe = safe.replace(":", "_").replace("*", "_").replace("?", "_")
        return self.cache_dir / f"{safe}.pkl"

    def _is_recent(self, path: Path) -> bool:
        if self.reuse_recent_days <= 0:
            return False
        max_age_sec = self.reuse_recent_days * 24 * 60 * 60
        return (time.time() - path.stat().st_mtime) <= max_age_sec
