"""Verifying an access token against the IdP's keys (what the UI does with the token in a session)."""
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.conftest import SETTINGS
from todo_api.auth import IdpUnavailable, TokenInvalid, TokenVerifier


@pytest.fixture
def verifier(keys):
    return TokenVerifier(SETTINGS, jwks_client=keys)


def test_a_valid_token_gives_the_caller(verifier, make_token):
    principal = verifier.verify(make_token(sub="u1"))
    assert (principal.subject, principal.client_id, principal.email) == ("u1", "web-ui", "priya@fundx.org")
    assert principal.scopes == {"todos:read", "todos:write"}
    assert principal.has_scope("todos:read") and not principal.has_scope("todos:admin")


def test_a_service_token_has_no_email(verifier, make_token):
    principal = verifier.verify(make_token(sub="claim-processor", email=None, client_id="claim-processor"))
    assert principal.email is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200},
        {"aud": "another-api"},
        {"iss": "http://evil.test"},
        {"typ": "JWT"},  # an ID token, not an access token
    ],
)
def test_bad_tokens_are_refused(verifier, make_token, overrides):
    with pytest.raises(TokenInvalid):
        verifier.verify(make_token(**overrides))


def test_a_token_signed_by_another_key_is_refused(verifier, make_token):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(TokenInvalid):
        verifier.verify(make_token(key=other))


def test_garbage_is_refused(verifier):
    with pytest.raises(TokenInvalid):
        verifier.verify("not.a.jwt")


def test_an_unreachable_idp_is_not_blamed_on_the_token(verifier, keys, make_token):
    keys.down = True
    with pytest.raises(IdpUnavailable):
        verifier.verify(make_token())
