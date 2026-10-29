"""Settings, read from the environment (a `.env` file is loaded too). See `.env.example` for what each one does."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    issuer: str = "http://localhost:9001"
    api_audience: str = "todo-api"  # only the default audience, for clients that do not ask for one
    keys_dir: Path = Path("keys")
    access_token_minutes: int = 10
    refresh_token_hours: int = 12
    code_seconds: int = 60
    max_failed_logins: int = 5
    lock_minutes: int = 30
    cors_origins: tuple[str, ...] = ("http://localhost:5174",)
    db_dsn: str = "host=localhost port=5435 dbname=idp_db user=idp-user password=idp-pass-123"

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        env = os.environ.get
        dsn = (
            f"host={env('IDP_DB_HOST', 'localhost')} port={env('IDP_DB_PORT', '5435')} dbname={env('IDP_DB_NAME', 'idp_db')} "
            f"user={env('IDP_DB_USER', 'idp-user')} password={env('IDP_DB_PASSWORD', 'idp-pass-123')}"
        )
        origins = tuple(o.strip() for o in env("IDP_CORS_ORIGINS", "http://localhost:5174").split(",") if o.strip())
        return cls(
            issuer=env("IDP_ISSUER", cls.issuer).rstrip("/"),
            api_audience=env("IDP_API_AUDIENCE", cls.api_audience),
            keys_dir=Path(env("IDP_KEYS_DIR", "keys")),
            access_token_minutes=int(env("IDP_ACCESS_TOKEN_MINUTES", "10")),
            refresh_token_hours=int(env("IDP_REFRESH_TOKEN_HOURS", "12")),
            code_seconds=int(env("IDP_CODE_SECONDS", "60")),
            max_failed_logins=int(env("IDP_MAX_FAILED_LOGINS", "5")),
            lock_minutes=int(env("IDP_LOCK_MINUTES", "30")),
            cors_origins=origins,
            db_dsn=dsn,
        )
