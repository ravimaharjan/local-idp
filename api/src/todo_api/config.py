"""Settings, read from the environment (a `.env` file is loaded too). See `.env.example` for what each one does."""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    issuer: str = "http://localhost:9001"
    audience: str = "todo-api"
    jwks_url: str = "http://localhost:9001/jwks.json"
    jwks_cache_seconds: int = 300
    clock_skew_seconds: int = 10
    read_scope: str = "todos:read"
    write_scope: str = "todos:write"
    # the browser UI, which signs people in with the IdP (authorization code + PKCE) as a public app
    ui_client_id: str = "todo-ui"
    ui_redirect_uri: str = "http://localhost:5174/auth/callback"
    ui_scopes: str = "openid profile email todos:read todos:write"
    ui_cookie_secure: bool = False  # set true when served over https

    @property
    def authorize_url(self) -> str:
        return f"{self.issuer}/authorize"

    @property
    def token_url(self) -> str:
        return f"{self.issuer}/token"

    @property
    def revoke_url(self) -> str:
        return f"{self.issuer}/revoke"

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        env = os.environ.get
        issuer = env("IDP_ISSUER", cls.issuer).rstrip("/")
        return cls(
            issuer=issuer,
            audience=env("IDP_AUDIENCE", cls.audience),
            jwks_url=env("IDP_JWKS_URL") or f"{issuer}/jwks.json",
            jwks_cache_seconds=int(env("IDP_JWKS_CACHE_SECONDS", "300")),
            clock_skew_seconds=int(env("IDP_CLOCK_SKEW_SECONDS", "10")),
            read_scope=env("API_READ_SCOPE", cls.read_scope),
            write_scope=env("API_WRITE_SCOPE", cls.write_scope),
            ui_client_id=env("UI_CLIENT_ID", cls.ui_client_id),
            ui_redirect_uri=env("UI_REDIRECT_URI", cls.ui_redirect_uri),
            ui_scopes=env("UI_SCOPES", cls.ui_scopes),
            ui_cookie_secure=env("UI_COOKIE_SECURE", "false").lower() in ("1", "true", "yes"),
        )
