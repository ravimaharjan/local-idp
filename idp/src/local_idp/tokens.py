"""Authorization codes, access / ID / refresh tokens, and the three grants that produce them.

State rule: these functions raise `OAuthError` only at points where the database already holds what must be kept (a code
marked used, a leaked refresh token's family revoked) or nothing was changed, and the route commits before answering with the
error. That is how a reused code or refresh token still gets its family revoked although the request itself fails.

Timestamps are computed here from `now` and passed to SQL, never taken from the database clock, so expiry is testable."""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

from local_idp import accounts, registry
from local_idp.accounts import Account
from local_idp.config import Settings
from local_idp.db import PgConnection
from local_idp.keys import KeyRing
from local_idp.registry import App

# RFC 7636: a verifier is 43 to 128 characters from this set; a S256 challenge is the base64url of a SHA-256, 43 characters.
_VERIFIER = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
_CHALLENGE = re.compile(r"^[A-Za-z0-9\-_]{43}$")


class OAuthError(Exception):
    """An error the protocol defines a code for (`invalid_grant`, `invalid_scope`, ...); `status` is the HTTP status."""

    def __init__(self, error: str, description: str, status: int = 400) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def is_valid_challenge(code_challenge: str) -> bool:
    return bool(_CHALLENGE.match(code_challenge))


def challenge_for(code_verifier: str) -> str:
    """The `code_challenge` (method S256) that goes with a `code_verifier`."""
    return _b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())


def pkce_matches(code_verifier: str, code_challenge: str) -> bool:
    if not _VERIFIER.match(code_verifier):
        return False
    return hmac.compare_digest(challenge_for(code_verifier), code_challenge)


def resolve_scopes(app: App, requested: Optional[str]) -> list[str]:
    """The scopes to grant: those asked for (all must be allowed to the app), or all the app's when none are asked for."""
    if requested is None or not requested.strip():
        return list(app.allowed_scopes)
    scopes = list(dict.fromkeys(requested.split()))
    not_allowed = [scope for scope in scopes if scope not in app.allowed_scopes]
    if not_allowed:
        raise OAuthError("invalid_scope", f"scope not allowed for this app: {' '.join(not_allowed)}")
    return scopes


def resolve_audience(conn: PgConnection, settings: Settings, app: App, requested: Optional[str]) -> str:
    """The API the access token is for: the one asked for (`audience` parameter), else the configured default. It must be a
    registered API that this app is allowed to get tokens for."""
    audience = (requested or "").strip() or settings.api_audience
    if not app.allows_audience(audience) or not registry.api_exists(conn, audience):
        raise OAuthError("invalid_target", f"this app may not get tokens for the API: {audience}")
    return audience


# --- authorization code ---


def issue_authorization_code(
    conn: PgConnection,
    settings: Settings,
    *,
    app: App,
    account: Account,
    redirect_uri: str,
    scopes: list[str],
    audience: str,
    code_challenge: str,
    nonce: Optional[str],
    now: Optional[datetime] = None,
) -> str:
    now = now or _now()
    code = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO idp.authorization_code "
        "(code_hash, app_id, account_id, redirect_uri, scope, audience, code_challenge, nonce, auth_time, family_id, expires_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            _digest(code), app.app_id, account.id, redirect_uri, " ".join(scopes), audience, code_challenge, nonce, now, uuid4(),
            now + timedelta(seconds=settings.code_seconds),
        ),
    )
    return code


def exchange_authorization_code(
    conn: PgConnection,
    settings: Settings,
    keyring: KeyRing,
    *,
    app: App,
    code: Optional[str],
    redirect_uri: Optional[str],
    code_verifier: Optional[str],
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    now = now or _now()
    if not app.allows_grant("authorization_code"):
        raise OAuthError("unauthorized_client", "this app may not use the authorization_code grant")
    if not code or not redirect_uri or not code_verifier:
        raise OAuthError("invalid_request", "code, redirect_uri and code_verifier are required")

    code_hash = _digest(code)
    # One statement both checks and spends the code: two requests with the same code cannot both succeed.
    row = conn.execute(
        "UPDATE idp.authorization_code SET used_at = %s WHERE code_hash = %s AND used_at IS NULL AND expires_at > %s "
        "RETURNING app_id, account_id, redirect_uri, scope, audience, code_challenge, nonce, auth_time, family_id",
        (now, code_hash, now),
    ).fetchone()
    if row is None:
        # A code that was already spent means it leaked (or the app retried): take back what it produced.
        conn.execute(
            "UPDATE idp.refresh_token SET revoked_at = %s WHERE revoked_at IS NULL AND family_id = "
            "(SELECT family_id FROM idp.authorization_code WHERE code_hash = %s AND used_at IS NOT NULL)",
            (now, code_hash),
        )
        raise OAuthError("invalid_grant", "the authorization code is invalid, expired or already used")

    if row["app_id"] != app.app_id or row["redirect_uri"] != redirect_uri:
        raise OAuthError("invalid_grant", "the code was not issued to this app and redirect_uri")
    if not pkce_matches(code_verifier, row["code_challenge"]):
        raise OAuthError("invalid_grant", "PKCE verification failed")

    account = accounts.find_account(conn, row["account_id"])
    if account is None:
        raise OAuthError("invalid_grant", "the account is no longer active")
    return _issue_tokens(
        conn, settings, keyring, app=app, account=account, scopes=row["scope"].split(), audience=row["audience"],
        auth_time=row["auth_time"], nonce=row["nonce"], family_id=row["family_id"], now=now,
    )


# --- refresh token ---


def refresh(
    conn: PgConnection,
    settings: Settings,
    keyring: KeyRing,
    *,
    app: App,
    refresh_token: Optional[str],
    scope: Optional[str],
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    now = now or _now()
    if not app.allows_grant("refresh_token"):
        raise OAuthError("unauthorized_client", "this app may not use the refresh_token grant")
    if not refresh_token:
        raise OAuthError("invalid_request", "refresh_token is required")

    token_hash = _digest(refresh_token)
    row = conn.execute(
        "SELECT family_id, app_id, account_id, scope, audience, auth_time, expires_at, used_at, revoked_at "
        "FROM idp.refresh_token WHERE token_hash = %s FOR UPDATE",
        (token_hash,),
    ).fetchone()
    if row is None:
        raise OAuthError("invalid_grant", "the refresh token is invalid")
    if row["used_at"] is not None or row["revoked_at"] is not None:
        _revoke_family(conn, row["family_id"], now)  # presented again after rotation or revocation: assume it leaked
        raise OAuthError("invalid_grant", "the refresh token was already used or revoked")
    if row["expires_at"] <= now:
        raise OAuthError("invalid_grant", "the refresh token has expired")
    if row["app_id"] != app.app_id:
        _revoke_family(conn, row["family_id"], now)
        raise OAuthError("invalid_grant", "the refresh token was not issued to this app")

    original = row["scope"].split()
    scopes = original if scope is None or not scope.strip() else list(dict.fromkeys(scope.split()))
    if not set(scopes) <= set(original):
        raise OAuthError("invalid_scope", "a refreshed token cannot gain scopes the first one did not have")

    account = accounts.find_account(conn, row["account_id"])
    if account is None:
        _revoke_family(conn, row["family_id"], now)
        raise OAuthError("invalid_grant", "the account is no longer active")

    conn.execute("UPDATE idp.refresh_token SET used_at = %s WHERE token_hash = %s", (now, token_hash))
    return _issue_tokens(
        conn, settings, keyring, app=app, account=account, scopes=scopes, audience=row["audience"],
        auth_time=row["auth_time"], nonce=None, family_id=row["family_id"], now=now,
    )


def revoke_token(conn: PgConnection, app: App, token: str, *, now: Optional[datetime] = None) -> None:
    """Revokes the refresh-token family `token` belongs to, if it is this app's. Anything else is ignored (RFC 7009): an
    access token cannot be revoked, it just expires in minutes."""
    now = now or _now()
    conn.execute(
        "UPDATE idp.refresh_token SET revoked_at = %s WHERE revoked_at IS NULL AND family_id = "
        "(SELECT family_id FROM idp.refresh_token WHERE token_hash = %s AND app_id = %s)",
        (now, _digest(token), app.app_id),
    )


def _revoke_family(conn: PgConnection, family_id: UUID, now: datetime) -> None:
    conn.execute("UPDATE idp.refresh_token SET revoked_at = %s WHERE family_id = %s AND revoked_at IS NULL", (now, family_id))


# --- client credentials ---


def client_credentials(
    conn: PgConnection, settings: Settings, keyring: KeyRing, *, app: App, scope: Optional[str],
    audience: Optional[str] = None, now: Optional[datetime] = None,
) -> dict[str, Any]:
    """A token for a service acting as itself: no person, so no ID token, no refresh token and no email."""
    now = now or _now()
    if not app.is_confidential or not app.allows_grant("client_credentials"):
        raise OAuthError("unauthorized_client", "this app may not use the client_credentials grant")
    scopes = resolve_scopes(app, scope)
    api = resolve_audience(conn, settings, app, audience)
    claims = _access_claims(settings, subject=app.app_id, app=app, scopes=scopes, audience=api, now=now)
    return {
        "token_type": "Bearer",
        "access_token": keyring.sign(claims, token_type="at+jwt"),
        "expires_in": settings.access_token_minutes * 60,
        "scope": " ".join(scopes),
    }


# --- token building ---


def _access_claims(
    settings: Settings, *, subject: str, app: App, scopes: list[str], audience: str, now: datetime, email: Optional[str] = None
):
    issued = int(now.timestamp())
    claims: dict[str, Any] = {
        "iss": settings.issuer,
        "sub": subject,
        "aud": audience,
        "client_id": app.app_id,
        "scope": " ".join(scopes),
        "iat": issued,
        "exp": issued + settings.access_token_minutes * 60,
        "jti": str(uuid4()),
    }
    if email:
        # Always in a person's access token, whatever the scopes: it is how the API tells who is calling.
        claims["email"] = email
    return claims


def _issue_tokens(
    conn: PgConnection,
    settings: Settings,
    keyring: KeyRing,
    *,
    app: App,
    account: Account,
    scopes: list[str],
    audience: str,
    auth_time: datetime,
    nonce: Optional[str],
    family_id: UUID,
    now: datetime,
) -> dict[str, Any]:
    access_claims = _access_claims(settings, subject=str(account.id), app=app, scopes=scopes, audience=audience, now=now, email=account.email)
    response: dict[str, Any] = {
        "token_type": "Bearer",
        "access_token": keyring.sign(access_claims, token_type="at+jwt"),
        "expires_in": settings.access_token_minutes * 60,
        "scope": " ".join(scopes),
    }

    if "openid" in scopes:
        id_claims: dict[str, Any] = {
            "iss": settings.issuer,
            "sub": str(account.id),
            "aud": app.app_id,
            "iat": access_claims["iat"],
            "exp": access_claims["exp"],
            "auth_time": int(auth_time.timestamp()),
        }
        if nonce:
            id_claims["nonce"] = nonce
        id_claims.update(profile_claims(account, scopes))
        response["id_token"] = keyring.sign(id_claims)

    if app.allows_grant("refresh_token"):
        refresh_token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO idp.refresh_token (token_hash, family_id, app_id, account_id, scope, audience, auth_time, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                _digest(refresh_token), family_id, app.app_id, account.id, " ".join(scopes), audience, auth_time,
                now + timedelta(hours=settings.refresh_token_hours),
            ),
        )
        response["refresh_token"] = refresh_token
    return response


def profile_claims(account: Account, scopes: list[str]) -> dict[str, Any]:
    """The identity claims the granted scopes allow: `email` gives the email, `profile` gives the names."""
    claims: dict[str, Any] = {}
    if "email" in scopes:
        claims["email"] = account.email
    if "profile" in scopes:
        for claim, value in (("given_name", account.given_name), ("family_name", account.family_name), ("name", account.name)):
            if value:
                claims[claim] = value
    return claims


# --- retention ---


def purge_expired(conn: PgConnection, *, now: Optional[datetime] = None, keep: timedelta = timedelta(days=1)) -> dict[str, int]:
    """Deletes codes and refresh tokens that expired more than `keep` ago (kept a while so a late replay is still recognised)."""
    now = now or _now()
    cutoff = now - keep
    codes = conn.execute("DELETE FROM idp.authorization_code WHERE expires_at < %s", (cutoff,)).rowcount
    tokens = conn.execute("DELETE FROM idp.refresh_token WHERE expires_at < %s", (cutoff,)).rowcount
    return {"authorization_codes": codes, "refresh_tokens": tokens}
