"""People who can sign in: creating an account, and checking an email and password with lockout.

A failed attempt is counted in one UPDATE; reaching the limit locks the account for `lock_minutes`, and a lock that has run out
clears itself on the next attempt. The caller must commit after `SignInFailed`, or the failed attempts are not remembered."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import bcrypt

from local_idp.config import Settings
from local_idp.db import PgConnection

# Checked when the email is unknown, so an unknown email and a wrong password take the same time.
_DUMMY_HASH = bcrypt.hashpw(b"unused", bcrypt.gensalt()).decode()

MIN_PASSWORD_LENGTH = 8


class AccountExists(ValueError):
    pass


class WeakPassword(ValueError):
    pass


class SignInFailed(Exception):
    """The email and password do not sign anyone in. `str(error)` is safe to show the person."""


@dataclass(frozen=True)
class Account:
    id: UUID
    email: str
    given_name: Optional[str]
    family_name: Optional[str]

    @property
    def name(self) -> Optional[str]:
        full = " ".join(part for part in (self.given_name, self.family_name) if part)
        return full or None


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _password_matches(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


def create_account(
    conn: PgConnection, *, email: str, password: str, given_name: Optional[str] = None, family_name: Optional[str] = None
) -> UUID:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPassword(f"the password needs at least {MIN_PASSWORD_LENGTH} characters")
    row = conn.execute(
        "INSERT INTO idp.account (email, password_hash, given_name, family_name) VALUES (%s, %s, %s, %s) "
        "ON CONFLICT (email) DO NOTHING RETURNING id",
        (email.strip().lower(), hash_password(password), given_name, family_name),
    ).fetchone()
    if row is None:
        raise AccountExists(f"an account for {email.strip().lower()} already exists")
    return row["id"]


def find_account(conn: PgConnection, account_id: UUID) -> Optional[Account]:
    row = conn.execute(
        "SELECT id, email, given_name, family_name FROM idp.account WHERE id = %s AND enabled", (account_id,)
    ).fetchone()
    return Account(**row) if row else None


def sign_in(conn: PgConnection, settings: Settings, email: str, password: str, *, now: Optional[datetime] = None) -> Account:
    now = now or datetime.now(timezone.utc)
    row = conn.execute(
        "SELECT id, email, given_name, family_name, password_hash, enabled, failed_login_attempts, locked_until "
        "FROM idp.account WHERE email = %s",
        (email.strip().lower(),),
    ).fetchone()
    if row is None:
        _password_matches(password, _DUMMY_HASH)
        raise SignInFailed("Invalid email or password")

    if row["locked_until"] is not None:
        if row["locked_until"] > now:
            raise SignInFailed(f"Account is locked. Try again in {settings.lock_minutes} minutes.")
        conn.execute(  # the lock ran out: start counting again
            "UPDATE idp.account SET failed_login_attempts = 0, locked_until = NULL, updated_at = now() WHERE id = %s",
            (row["id"],),
        )
        row["failed_login_attempts"] = 0

    if not _password_matches(password, row["password_hash"]):
        locked = conn.execute(
            "UPDATE idp.account SET failed_login_attempts = failed_login_attempts + 1, "
            "locked_until = CASE WHEN failed_login_attempts + 1 >= %s THEN %s ELSE locked_until END, updated_at = now() "
            "WHERE id = %s RETURNING locked_until",
            (settings.max_failed_logins, now + timedelta(minutes=settings.lock_minutes), row["id"]),
        ).fetchone()["locked_until"]
        if locked is not None:
            raise SignInFailed(f"Account locked after {settings.max_failed_logins} failed attempts.")
        raise SignInFailed("Invalid email or password")

    if not row["enabled"]:
        raise SignInFailed("This account is disabled")

    if row["failed_login_attempts"]:
        conn.execute("UPDATE idp.account SET failed_login_attempts = 0, updated_at = now() WHERE id = %s", (row["id"],))
    return Account(id=row["id"], email=row["email"], given_name=row["given_name"], family_name=row["family_name"])
