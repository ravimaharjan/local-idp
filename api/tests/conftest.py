"""Tests sign tokens with a throwaway RSA key and hand the API a key client that serves its public half, so no IdP is needed."""
import time
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWKClientConnectionError

from todo_api.config import Settings

SETTINGS = Settings(issuer="http://idp.test", audience="todo-api", jwks_url="http://idp.test/jwks.json")


class FakeKeys:
    def __init__(self, key, down=False):
        self.key, self.down = key, down

    def get_signing_key_from_jwt(self, raw):
        if self.down:
            raise PyJWKClientConnectionError("idp down")
        return SimpleNamespace(key=self.key.public_key())


@pytest.fixture(scope="session")
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def keys(private_key):
    return FakeKeys(private_key)


@pytest.fixture
def make_token(private_key):
    def make(*, scope="todos:read todos:write", sub=None, typ="at+jwt", key=None, **overrides):
        now = int(time.time())
        claims = {
            "iss": SETTINGS.issuer, "sub": sub or str(uuid4()), "aud": SETTINGS.audience, "client_id": "web-ui",
            "scope": scope, "iat": now, "exp": now + 600, "email": "priya@fundx.org",
        }
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, key or private_key, algorithm="RS256", headers={"kid": "k1", "typ": typ})

    return make
