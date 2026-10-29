"""Access-token verification against the identity provider (used by the browser UI to check the session's token).

The IdP signs access tokens with RS256 and publishes the public keys at its JWKS endpoint, so the API needs no shared secret
and no call per request: it fetches the keys (cached), then checks the signature, `iss`, `aud`, `exp` and the `at+jwt` type
locally. A token signed by a key the API has not seen yet (key rotation) makes the key client refetch the set once.

Failures are told apart: a bad token raises `TokenInvalid`, and an IdP that cannot be reached raises `IdpUnavailable` -- the
person did nothing wrong, so the UI shows that as a 503 page, not as a sign-out."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import jwt
from jwt import PyJWKClient, PyJWKClientConnectionError

from todo_api.config import Settings

_ALGORITHMS = ["RS256"]  # never read from the token header: that is how "alg: none" / HMAC-with-public-key attacks work


class TokenInvalid(Exception):
    pass


class IdpUnavailable(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    """Who is calling: a person (`email` set) or a service acting as itself (`sub` is its app id)."""

    subject: str
    client_id: str
    scopes: frozenset[str]
    email: Optional[str] = None

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


class TokenVerifier:
    def __init__(self, settings: Settings, jwks_client: Optional[PyJWKClient] = None) -> None:
        self._settings = settings
        self._jwks = jwks_client or PyJWKClient(
            settings.jwks_url, cache_jwk_set=True, lifespan=settings.jwks_cache_seconds, timeout=5
        )

    def verify(self, raw: str) -> Principal:
        try:
            if jwt.get_unverified_header(raw).get("typ") != "at+jwt":
                raise TokenInvalid("not an access token")  # e.g. an ID token, which is for the app and not for this API
            key = self._jwks.get_signing_key_from_jwt(raw).key
            claims = jwt.decode(
                raw, key, algorithms=_ALGORITHMS, audience=self._settings.audience, issuer=self._settings.issuer,
                leeway=self._settings.clock_skew_seconds, options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except PyJWKClientConnectionError as error:
            raise IdpUnavailable(str(error)) from error
        except jwt.PyJWTError as error:
            raise TokenInvalid(str(error)) from error
        return Principal(
            subject=str(claims["sub"]),
            client_id=str(claims.get("client_id", "")),
            scopes=frozenset(str(claims.get("scope", "")).split()),
            email=claims.get("email"),
        )
