"""Server-side sessions for the browser UI, in memory (lost on restart, like the todos). The cookie holds only a random id; the
tokens never reach the browser's storage."""
from __future__ import annotations

import secrets
from threading import Lock
from typing import Any, Optional


class SessionStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._data: dict[str, dict[str, Any]] = {}

    def create(self, data: Optional[dict[str, Any]] = None) -> str:
        sid = secrets.token_urlsafe(32)
        with self._lock:
            self._data[sid] = dict(data or {})
        return sid

    def get(self, sid: Optional[str]) -> Optional[dict[str, Any]]:
        with self._lock:
            return self._data.get(sid) if sid else None

    def delete(self, sid: Optional[str]) -> None:
        with self._lock:
            self._data.pop(sid or "", None)
