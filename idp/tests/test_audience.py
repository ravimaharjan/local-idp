"""Each access token is for one API: its `aud` is the API the client asked for, if the app may get tokens for it."""
import jwt
import pytest

from local_idp import registry
from tests.conftest import CALLBACK
from tests.test_http import basic, get_tokens, query_of, sign_in


def aud_of(token: str):
    return jwt.decode(token, options={"verify_signature": False})["aud"]


@pytest.fixture
def two_apis(conn, world):
    """todo-api (the default) and rider-api are both registered; web-ui may use both, claim-processor only todo-api."""
    registry.register_api(conn, audience="rider-api", name="Rider API")
    registry.register_app(
        conn, app_id="web-ui", name="Example App", app_type="public", redirect_uris=[CALLBACK],
        grant_types=["authorization_code", "refresh_token"], allowed_scopes=["openid", "profile", "email"],
        allowed_audiences=["todo-api", "rider-api"],
    )
    conn.commit()


class TestRegistration:
    def test_an_app_cannot_be_given_an_api_that_is_not_registered(self, conn):
        with pytest.raises(ValueError, match="not registered"):
            registry.register_app(
                conn, app_id="x", name="X", app_type="public", redirect_uris=[], grant_types=[], allowed_scopes=[],
                allowed_audiences=["ghost-api"],
            )

    def test_an_audience_with_spaces_is_refused(self, conn):
        with pytest.raises(ValueError):
            registry.register_api(conn, audience="two words", name="X")


class TestClientCredentials:
    def test_no_audience_gets_the_default(self, web, world):
        body = web.post("/token", data=dict(grant_type="client_credentials", scope="claims:write"),
                        headers=basic("claim-processor", "s3cret")).json()
        assert aud_of(body["access_token"]) == "todo-api"

    def test_the_audience_asked_for_is_used(self, web, two_apis, conn):
        registry.register_app(
            conn, app_id="claim-processor", name="Claim processor", app_type="confidential", secret="s3cret", redirect_uris=[],
            grant_types=["client_credentials"], allowed_scopes=["claims:write"], allowed_audiences=["todo-api", "rider-api"],
        )
        conn.commit()
        body = web.post("/token", data=dict(grant_type="client_credentials", audience="rider-api"),
                        headers=basic("claim-processor", "s3cret")).json()
        assert aud_of(body["access_token"]) == "rider-api"

    def test_an_api_the_app_may_not_use_is_refused(self, web, two_apis):
        response = web.post("/token", data=dict(grant_type="client_credentials", audience="rider-api"),
                            headers=basic("claim-processor", "s3cret"))
        assert response.status_code == 400 and response.json()["error"] == "invalid_target"

    def test_an_unknown_api_is_refused(self, web, two_apis):
        response = web.post("/token", data=dict(grant_type="client_credentials", audience="ghost-api"),
                            headers=basic("claim-processor", "s3cret"))
        assert response.json()["error"] == "invalid_target"


class TestSignedInPerson:
    def test_the_audience_asked_at_authorize_ends_up_in_the_token_and_survives_refresh(self, web, two_apis):
        first = get_tokens(web, audience="rider-api")
        assert aud_of(first["access_token"]) == "rider-api"
        again = web.post("/token", data=dict(grant_type="refresh_token", refresh_token=first["refresh_token"], client_id="web-ui")).json()
        assert aud_of(again["access_token"]) == "rider-api"

    def test_without_it_the_default_api_is_used(self, web, two_apis):
        assert aud_of(get_tokens(web)["access_token"]) == "todo-api"

    def test_an_api_the_app_may_not_use_is_sent_back_as_an_error(self, web, two_apis):
        location = query_of(sign_in(web, audience="ghost-api"))
        assert location["error"] == "invalid_target" and "code" not in location

    def test_userinfo_accepts_a_token_for_any_registered_api(self, web, two_apis):
        access = get_tokens(web, audience="rider-api")["access_token"]
        response = web.get("/userinfo", headers={"Authorization": f"Bearer {access}"})
        assert response.status_code == 200 and response.json()["email"] == "amy@fund.org"
