from datetime import datetime, timedelta, timezone

import jwt
import pytest

from local_idp import registry, tokens
from local_idp.tokens import OAuthError
from tests.conftest import CALLBACK, VERIFIER


def app_of(conn, app_id="web-ui"):
    return registry.find_app(conn, app_id)


def issue_code(conn, settings, *, scopes=("openid", "profile", "email"), audience="todo-api", nonce="n-1", now=None) -> str:
    from local_idp import accounts

    account = accounts.find_account(conn, conn.execute("SELECT id FROM idp.account").fetchone()["id"])
    return tokens.issue_authorization_code(
        conn, settings, app=app_of(conn), account=account, redirect_uri=CALLBACK, scopes=list(scopes),
        audience=audience, code_challenge=tokens.challenge_for(VERIFIER), nonce=nonce, now=now,
    )


def exchange(conn, settings, keyring, code, **over):
    values = dict(app=app_of(conn), code=code, redirect_uri=CALLBACK, code_verifier=VERIFIER)
    values.update(over)
    return tokens.exchange_authorization_code(conn, settings, keyring, **values)


def refresh(conn, settings, keyring, refresh_token, **over):
    return tokens.refresh(conn, settings, keyring, app=over.pop("app", app_of(conn)), refresh_token=refresh_token, scope=over.pop("scope", None), **over)


def refusal(call) -> OAuthError:
    with pytest.raises(OAuthError) as caught:
        call()
    return caught.value


def decode(keyring, token, audience):
    kid = jwt.get_unverified_header(token)["kid"]
    return jwt.decode(token, keyring.public_key_for(kid), algorithms=["RS256"], audience=audience, issuer="http://idp.test")


class TestAuthorizationCode:
    def test_a_good_exchange_gives_access_id_and_refresh_tokens(self, conn, world, settings, keyring):
        result = exchange(conn, settings, keyring, issue_code(conn, settings))

        assert result["token_type"] == "Bearer" and result["expires_in"] == 600
        assert result["scope"] == "openid profile email" and result["refresh_token"]
        assert set(result) == {"token_type", "access_token", "expires_in", "scope", "id_token", "refresh_token"}

    def test_the_access_token_is_for_the_api_and_names_the_person(self, conn, world, settings, keyring):
        result = exchange(conn, settings, keyring, issue_code(conn, settings))

        claims = decode(keyring, result["access_token"], "todo-api")
        assert claims["sub"] == str(world.account_id) and claims["email"] == "amy@fund.org"
        assert claims["client_id"] == "web-ui" and claims["scope"] == "openid profile email"
        assert claims["exp"] - claims["iat"] == 600 and claims["jti"]
        assert jwt.get_unverified_header(result["access_token"])["typ"] == "at+jwt"

    def test_the_id_token_is_for_the_app_and_carries_the_nonce(self, conn, world, settings, keyring):
        result = exchange(conn, settings, keyring, issue_code(conn, settings, nonce="my-nonce"))

        claims = decode(keyring, result["id_token"], "web-ui")
        assert claims["sub"] == str(world.account_id) and claims["nonce"] == "my-nonce"
        assert claims["email"] == "amy@fund.org" and claims["given_name"] == "Amy" and claims["name"] == "Amy Lee"
        assert isinstance(claims["auth_time"], int)
        assert jwt.get_unverified_header(result["id_token"])["typ"] == "JWT"

    def test_the_id_token_has_no_nonce_if_none_was_sent(self, conn, world, settings, keyring):
        result = exchange(conn, settings, keyring, issue_code(conn, settings, nonce=None))

        assert "nonce" not in decode(keyring, result["id_token"], "web-ui")

    def test_identity_claims_follow_the_granted_scopes_but_the_access_token_always_names_the_person(self, conn, world, settings, keyring):
        result = exchange(conn, settings, keyring, issue_code(conn, settings, scopes=("openid",)))

        id_claims = decode(keyring, result["id_token"], "web-ui")
        assert not {"email", "given_name", "name"} & id_claims.keys()
        assert decode(keyring, result["access_token"], "todo-api")["email"] == "amy@fund.org"

    def test_without_the_openid_scope_there_is_no_id_token(self, conn, world, settings, keyring):
        result = exchange(conn, settings, keyring, issue_code(conn, settings, scopes=("email",)))

        assert "id_token" not in result and result["access_token"]

    def test_a_code_works_once(self, conn, world, settings, keyring):
        code = issue_code(conn, settings)
        exchange(conn, settings, keyring, code)

        assert refusal(lambda: exchange(conn, settings, keyring, code)).error == "invalid_grant"

    def test_reusing_a_code_takes_back_the_refresh_token_it_produced(self, conn, world, settings, keyring):
        code = issue_code(conn, settings)
        first = exchange(conn, settings, keyring, code)
        refusal(lambda: exchange(conn, settings, keyring, code))

        assert conn.execute("SELECT revoked_at FROM idp.refresh_token").fetchone()["revoked_at"] is not None
        assert refusal(lambda: refresh(conn, settings, keyring, first["refresh_token"])).error == "invalid_grant"

    def test_an_expired_code_is_refused(self, conn, world, settings, keyring):
        code = issue_code(conn, settings)
        later = datetime.now(timezone.utc) + timedelta(seconds=settings.code_seconds + 5)

        assert refusal(lambda: exchange(conn, settings, keyring, code, now=later)).error == "invalid_grant"

    def test_a_wrong_verifier_is_refused_and_burns_the_code(self, conn, world, settings, keyring):
        code = issue_code(conn, settings)

        error = refusal(lambda: exchange(conn, settings, keyring, code, code_verifier="y" * 43))

        assert error.error == "invalid_grant" and "PKCE" in error.description
        assert refusal(lambda: exchange(conn, settings, keyring, code)).error == "invalid_grant"

    def test_another_return_address_is_refused(self, conn, world, settings, keyring):
        code = issue_code(conn, settings)

        assert refusal(lambda: exchange(conn, settings, keyring, code, redirect_uri=CALLBACK + "/x")).error == "invalid_grant"

    def test_a_code_cannot_be_redeemed_by_another_app(self, conn, world, settings, keyring):
        registry.register_app(
            conn, app_id="other", name="Other", app_type="public", redirect_uris=[CALLBACK],
            grant_types=["authorization_code"], allowed_scopes=["openid"],
        )
        code = issue_code(conn, settings)

        assert refusal(lambda: exchange(conn, settings, keyring, code, app=app_of(conn, "other"))).error == "invalid_grant"

    @pytest.mark.parametrize("missing", ["code", "redirect_uri", "code_verifier"])
    def test_a_missing_parameter_is_an_invalid_request(self, conn, world, settings, keyring, missing):
        code = issue_code(conn, settings)
        given = {name: None if name == missing else value for name, value in
                 dict(code=code, redirect_uri=CALLBACK, code_verifier=VERIFIER).items()}

        error = refusal(lambda: tokens.exchange_authorization_code(conn, settings, keyring, app=app_of(conn), **given))

        assert error.error == "invalid_request"

    def test_an_app_without_the_grant_is_refused(self, conn, world, settings, keyring):
        error = refusal(lambda: exchange(conn, settings, keyring, "x", app=app_of(conn, "claim-processor")))

        assert error.error == "unauthorized_client"

    def test_a_disabled_account_gets_nothing(self, conn, world, settings, keyring):
        code = issue_code(conn, settings)
        conn.execute("UPDATE idp.account SET enabled = false")

        assert refusal(lambda: exchange(conn, settings, keyring, code)).error == "invalid_grant"

    def test_only_hashes_of_codes_and_refresh_tokens_are_stored(self, conn, world, settings, keyring):
        code = issue_code(conn, settings)
        result = exchange(conn, settings, keyring, code)

        stored = [conn.execute("SELECT code_hash AS h FROM idp.authorization_code").fetchone()["h"],
                  conn.execute("SELECT token_hash AS h FROM idp.refresh_token").fetchone()["h"]]
        assert code not in stored and result["refresh_token"] not in stored and all(len(h) == 64 for h in stored)


class TestRefreshToken:
    @pytest.fixture
    def first(self, conn, world, settings, keyring):
        return exchange(conn, settings, keyring, issue_code(conn, settings))

    def test_it_gives_new_tokens_and_a_new_refresh_token(self, conn, first, settings, keyring):
        second = refresh(conn, settings, keyring, first["refresh_token"])

        assert second["refresh_token"] != first["refresh_token"] and second["access_token"] != first["access_token"]
        assert second["scope"] == "openid profile email" and "id_token" in second

    def test_the_new_id_token_has_no_nonce(self, conn, first, settings, keyring):
        second = refresh(conn, settings, keyring, first["refresh_token"])

        claims = decode(keyring, second["id_token"], "web-ui")
        assert "nonce" not in claims and "auth_time" in claims

    def test_a_used_token_is_refused_and_takes_the_whole_family_with_it(self, conn, first, settings, keyring):
        second = refresh(conn, settings, keyring, first["refresh_token"])

        assert refusal(lambda: refresh(conn, settings, keyring, first["refresh_token"])).error == "invalid_grant"
        assert refusal(lambda: refresh(conn, settings, keyring, second["refresh_token"])).error == "invalid_grant"

    def test_the_scope_can_be_narrowed(self, conn, first, settings, keyring):
        second = refresh(conn, settings, keyring, first["refresh_token"], scope="openid")

        assert second["scope"] == "openid"

    def test_the_scope_cannot_grow_and_the_token_is_not_burnt_by_asking(self, conn, first, settings, keyring):
        registry.register_app(
            conn, app_id="web-ui", name="Example App", app_type="public", redirect_uris=[CALLBACK],
            grant_types=["authorization_code", "refresh_token"], allowed_scopes=["openid", "profile", "email", "extra"],
            allowed_audiences=["todo-api"],
        )
        narrow = refresh(conn, settings, keyring, first["refresh_token"], scope="openid")

        assert refusal(lambda: refresh(conn, settings, keyring, narrow["refresh_token"], scope="openid email")).error == "invalid_scope"
        assert refresh(conn, settings, keyring, narrow["refresh_token"])["scope"] == "openid"

    def test_an_expired_token_is_refused(self, conn, first, settings, keyring):
        later = datetime.now(timezone.utc) + timedelta(hours=settings.refresh_token_hours, minutes=1)

        assert refusal(lambda: refresh(conn, settings, keyring, first["refresh_token"], now=later)).error == "invalid_grant"

    def test_a_made_up_token_is_refused(self, conn, world, settings, keyring):
        assert refusal(lambda: refresh(conn, settings, keyring, "nonsense")).error == "invalid_grant"

    def test_another_app_presenting_it_revokes_the_family(self, conn, first, settings, keyring):
        registry.register_app(
            conn, app_id="other", name="Other", app_type="public", redirect_uris=[CALLBACK],
            grant_types=["refresh_token"], allowed_scopes=["openid"],
        )

        error = refusal(lambda: refresh(conn, settings, keyring, first["refresh_token"], app=app_of(conn, "other")))

        assert error.error == "invalid_grant"
        assert refusal(lambda: refresh(conn, settings, keyring, first["refresh_token"])).error == "invalid_grant"

    def test_a_disabled_account_cannot_refresh(self, conn, first, settings, keyring):
        conn.execute("UPDATE idp.account SET enabled = false")

        assert refusal(lambda: refresh(conn, settings, keyring, first["refresh_token"])).error == "invalid_grant"

    def test_a_missing_token_is_an_invalid_request(self, conn, world, settings, keyring):
        assert refusal(lambda: refresh(conn, settings, keyring, None)).error == "invalid_request"

    def test_an_app_without_the_grant_is_refused(self, conn, world, settings, keyring):
        assert refusal(lambda: refresh(conn, settings, keyring, "x", app=app_of(conn, "claim-processor"))).error == "unauthorized_client"


class TestRevoke:
    def test_revoking_ends_the_family(self, conn, world, settings, keyring):
        result = exchange(conn, settings, keyring, issue_code(conn, settings))

        tokens.revoke_token(conn, app_of(conn), result["refresh_token"])

        assert refusal(lambda: refresh(conn, settings, keyring, result["refresh_token"])).error == "invalid_grant"

    def test_another_apps_token_is_left_alone(self, conn, world, settings, keyring):
        result = exchange(conn, settings, keyring, issue_code(conn, settings))

        tokens.revoke_token(conn, app_of(conn, "claim-processor"), result["refresh_token"])

        assert refresh(conn, settings, keyring, result["refresh_token"])["access_token"]

    def test_an_unknown_token_is_ignored(self, conn, world):
        tokens.revoke_token(conn, app_of(conn), "never-issued")


class TestClientCredentials:
    def grant(self, conn, settings, keyring, scope=None, app_id="claim-processor"):
        return tokens.client_credentials(conn, settings, keyring, app=app_of(conn, app_id), scope=scope)

    def test_a_service_gets_an_access_token_in_its_own_name(self, conn, world, settings, keyring):
        result = self.grant(conn, settings, keyring, scope="claims:write")

        claims = decode(keyring, result["access_token"], "todo-api")
        assert claims["sub"] == claims["client_id"] == "claim-processor" and claims["scope"] == "claims:write"
        assert "email" not in claims
        assert set(result) == {"token_type", "access_token", "expires_in", "scope"}

    def test_without_a_scope_it_gets_all_its_scopes(self, conn, world, settings, keyring):
        assert self.grant(conn, settings, keyring)["scope"] == "claims:write claims:read"

    def test_a_scope_it_may_not_have_is_refused(self, conn, world, settings, keyring):
        assert refusal(lambda: self.grant(conn, settings, keyring, scope="admin")).error == "invalid_scope"

    def test_a_browser_app_may_not_use_it(self, conn, world, settings, keyring):
        assert refusal(lambda: self.grant(conn, settings, keyring, app_id="web-ui")).error == "unauthorized_client"


def test_old_codes_and_tokens_are_purged_recent_ones_kept(conn, world, settings, keyring):
    result = exchange(conn, settings, keyring, issue_code(conn, settings))
    later = datetime.now(timezone.utc) + timedelta(hours=settings.refresh_token_hours, days=2)

    assert tokens.purge_expired(conn) == {"authorization_codes": 0, "refresh_tokens": 0}
    assert tokens.purge_expired(conn, now=later) == {"authorization_codes": 1, "refresh_tokens": 1}
    assert result["refresh_token"]
