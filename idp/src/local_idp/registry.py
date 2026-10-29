"""Registered applications: who may ask for tokens, where they may be sent back to, and with which grants and scopes.

The identifier is public (`client_id` on the wire). A confidential app (a backend) also proves itself with a secret, which is
stored only as a bcrypt hash; a public app (a browser app) has none and relies on PKCE."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

import bcrypt

from local_idp.db import PgConnection

GRANT_TYPES = ("authorization_code", "refresh_token", "client_credentials")
# A scope name is printable ASCII without spaces, quotes or backslashes (RFC 6749 section 3.3): `openid`, `claims:write`, ...
_SCOPE_NAME = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")


@dataclass(frozen=True)
class App:
    app_id: str
    name: str
    app_type: str
    secret_hash: Optional[str]
    redirect_uris: tuple[str, ...]
    grant_types: tuple[str, ...]
    allowed_scopes: tuple[str, ...]
    allowed_audiences: tuple[str, ...] = ()

    @property
    def is_confidential(self) -> bool:
        return self.app_type == "confidential"

    def allows_grant(self, grant_type: str) -> bool:
        return grant_type in self.grant_types

    def allows_audience(self, audience: str) -> bool:
        return audience in self.allowed_audiences

    def has_redirect_uri(self, redirect_uri: str) -> bool:
        """Exact string match -- no prefixes, patterns or normalisation."""
        return redirect_uri in self.redirect_uris

    def secret_matches(self, secret: str) -> bool:
        if not self.secret_hash:
            return False
        try:
            return bcrypt.checkpw(secret.encode(), self.secret_hash.encode())
        except ValueError:
            return False


def find_app(conn: PgConnection, app_id: str) -> Optional[App]:
    row = conn.execute(
        "SELECT app_id, name, app_type, secret_hash, redirect_uris, grant_types, allowed_scopes, allowed_audiences "
        "FROM idp.app WHERE app_id = %s AND enabled",
        (app_id,),
    ).fetchone()
    if row is None:
        return None
    return App(
        app_id=row["app_id"],
        name=row["name"],
        app_type=row["app_type"],
        secret_hash=row["secret_hash"],
        redirect_uris=tuple(row["redirect_uris"]),
        grant_types=tuple(row["grant_types"]),
        allowed_scopes=tuple(row["allowed_scopes"]),
        allowed_audiences=tuple(row["allowed_audiences"]),
    )


def api_exists(conn: PgConnection, audience: str) -> bool:
    return conn.execute("SELECT 1 FROM idp.api WHERE audience = %s AND enabled", (audience,)).fetchone() is not None


def register_api(conn: PgConnection, *, audience: str, name: str) -> None:
    """Creates the API, or renames it if the audience is already registered."""
    if not audience or any(c.isspace() for c in audience):
        raise ValueError("the audience must be non-empty and contain no spaces")
    conn.execute(
        "INSERT INTO idp.api (audience, name) VALUES (%s, %s) "
        "ON CONFLICT (audience) DO UPDATE SET name = EXCLUDED.name, updated_at = now()",
        (audience, name),
    )


def register_app(
    conn: PgConnection,
    *,
    app_id: str,
    name: str,
    app_type: str,
    secret: Optional[str] = None,
    redirect_uris: list[str],
    grant_types: list[str],
    allowed_scopes: list[str],
    allowed_audiences: Optional[list[str]] = None,
) -> None:
    """Creates the app, or updates it if the identifier is already registered (re-running a setup script is harmless)."""
    if app_type not in ("public", "confidential"):
        raise ValueError("app_type must be 'public' or 'confidential'")
    if app_type == "confidential" and not secret:
        raise ValueError("a confidential app needs a secret")
    unknown = [g for g in grant_types if g not in GRANT_TYPES]
    if unknown:
        raise ValueError(f"unknown grant type: {', '.join(unknown)}")
    malformed = [s for s in allowed_scopes if not _SCOPE_NAME.match(s)]
    if malformed:
        raise ValueError(f"malformed scope name: {', '.join(malformed)}")
    allowed_audiences = allowed_audiences or []
    unregistered = [a for a in allowed_audiences if not api_exists(conn, a)]
    if unregistered:
        raise ValueError(f"API not registered (run register-api first): {', '.join(unregistered)}")
    secret_hash = bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode() if secret else None
    conn.execute(
        "INSERT INTO idp.app (app_id, name, app_type, secret_hash, redirect_uris, grant_types, allowed_scopes, allowed_audiences) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
        "ON CONFLICT (app_id) DO UPDATE SET name = EXCLUDED.name, app_type = EXCLUDED.app_type, "
        "secret_hash = EXCLUDED.secret_hash, redirect_uris = EXCLUDED.redirect_uris, grant_types = EXCLUDED.grant_types, "
        "allowed_scopes = EXCLUDED.allowed_scopes, allowed_audiences = EXCLUDED.allowed_audiences, updated_at = now()",
        (app_id, name, app_type, secret_hash, redirect_uris, grant_types, allowed_scopes, allowed_audiences),
    )
