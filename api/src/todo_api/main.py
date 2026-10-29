"""The app: wires the token verifier, the IdP client, the sessions and the todo store, and mounts the browser pages (`ui.py`).
Run it with `uvicorn todo_api.main:create_app --factory --port 5174`."""
from __future__ import annotations

from typing import Optional

from fastapi import FastAPI

from todo_api import ui
from todo_api.auth import TokenVerifier
from todo_api.config import Settings
from todo_api.idp_client import IdpClient
from todo_api.sessions import SessionStore
from todo_api.todos import TodoStore


def create_app(
    settings: Optional[Settings] = None, *, verifier: Optional[TokenVerifier] = None, idp: Optional[IdpClient] = None
) -> FastAPI:
    settings = settings or Settings.from_env()
    api = FastAPI(title="todo-api", docs_url=None, redoc_url=None, openapi_url=None)
    api.state.settings = settings
    api.state.verifier = verifier or TokenVerifier(settings)
    api.state.todos = TodoStore()
    api.state.idp = idp or IdpClient(settings)
    api.state.sessions = SessionStore()
    ui.install(api)

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return api
