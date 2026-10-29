"""Shared fixtures. The DB-backed tests make a throwaway database on the identity provider's own Postgres container
(`docker compose up -d` in the project root), load db/schema/ into it, and drop it afterwards. They never touch idp_db itself."""
from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path

import bcrypt
import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql

from local_idp import accounts, registry
from local_idp.config import Settings
from local_idp.db import open_pool
from local_idp.keys import KeyRing, new_signing_key
from local_idp.main import create_app

SCHEMA_LOAD = Path(__file__).resolve().parents[1] / "db" / "schema" / "load.sql"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  # the example value from RFC 7636, appendix B
CALLBACK = "http://localhost:5173/auth/callback"
PASSWORD = "correct horse battery"


@pytest.fixture(autouse=True)
def _cheap_password_hashing(monkeypatch):
    """bcrypt at its normal cost makes every test that creates an account take a quarter of a second."""
    real = bcrypt.gensalt
    monkeypatch.setattr(bcrypt, "gensalt", lambda rounds=4, prefix=b"2b": real(rounds=4, prefix=prefix))


@pytest.fixture(scope="session")
def _server_dsn() -> dict:
    base = Settings.from_env().db_dsn
    return dict(part.split("=", 1) for part in base.split())


@pytest.fixture(scope="session")
def test_dsn(_server_dsn):
    name = f"idp_test_{uuid.uuid4().hex[:8]}"
    admin = psycopg.connect(**{**_server_dsn, "dbname": _server_dsn["dbname"]}, autocommit=True)
    admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    env = {**os.environ, "PGPASSWORD": _server_dsn["password"]}
    subprocess.run(
        ["psql", "-v", "ON_ERROR_STOP=1", "-q", "-h", _server_dsn["host"], "-p", _server_dsn["port"], "-U", _server_dsn["user"],
         "-d", name, "-f", SCHEMA_LOAD.name],
        cwd=SCHEMA_LOAD.parent, env=env, check=True, capture_output=True,
    )
    yield " ".join(f"{k}={v}" for k, v in {**_server_dsn, "dbname": name}.items())
    admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))
    admin.close()


@pytest.fixture(scope="session")
def pool(test_dsn):
    pool = open_pool(test_dsn, min_size=1, max_size=6)
    yield pool
    pool.close()


@pytest.fixture(scope="session")
def keyring() -> KeyRing:
    return KeyRing([new_signing_key()])


@pytest.fixture
def settings(test_dsn, tmp_path) -> Settings:
    return Settings(issuer="http://idp.test", api_audience="todo-api", keys_dir=tmp_path, db_dsn=test_dsn)


@pytest.fixture
def conn(pool):
    """A connection on an empty database; committed when the test ends."""
    with pool.connection() as connection:
        connection.execute("TRUNCATE idp.refresh_token, idp.authorization_code, idp.app, idp.api, idp.account CASCADE")
        connection.commit()
        yield connection


@pytest.fixture
def world(conn):
    """One person and two apps, committed so the HTTP app (which uses its own connections) sees them."""
    account_id = accounts.create_account(conn, email="amy@fund.org", password=PASSWORD, given_name="Amy", family_name="Lee")
    registry.register_api(conn, audience="todo-api", name="Todo API")
    registry.register_app(
        conn, app_id="web-ui", name="Example App", app_type="public", redirect_uris=[CALLBACK],
        grant_types=["authorization_code", "refresh_token"], allowed_scopes=["openid", "profile", "email"],
        allowed_audiences=["todo-api"],
    )
    registry.register_app(
        conn, app_id="claim-processor", name="Claim processor", app_type="confidential", secret="s3cret", redirect_uris=[],
        grant_types=["client_credentials"], allowed_scopes=["claims:write", "claims:read"],
        allowed_audiences=["todo-api"],
    )
    conn.commit()
    return type("World", (), {"account_id": account_id, "email": "amy@fund.org", "password": PASSWORD})


@pytest.fixture
def web(settings, pool, keyring, world):
    """The identity provider's HTTP app over the test database."""
    return TestClient(create_app(settings, pool=pool, keyring=keyring), follow_redirects=False)
