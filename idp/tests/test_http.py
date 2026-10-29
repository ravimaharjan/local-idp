"""The whole flow over HTTP, the way the web app and the API use it."""
import base64
import re
from urllib.parse import parse_qs, urlsplit

import jwt

from local_idp import tokens
from tests.conftest import CALLBACK, PASSWORD, VERIFIER

CHALLENGE = tokens.challenge_for(VERIFIER)


def authorize_params(**over):
    params = dict(
        client_id="web-ui", redirect_uri=CALLBACK, response_type="code", scope="openid profile email", state="st-1",
        nonce="nonce-1", code_challenge=CHALLENGE, code_challenge_method="S256",
    )
    params.update(over)
    return {k: v for k, v in params.items() if v is not None}


def query_of(response):
    return {k: v[0] for k, v in parse_qs(urlsplit(response.headers["location"]).query).items()}


def sign_in(web, email="amy@fund.org", password=PASSWORD, **over):
    return web.post("/authorize", data={**authorize_params(**over), "email": email, "password": password})


def get_tokens(web, **over):
    code = query_of(sign_in(web, **over))["code"]
    return web.post("/token", data=dict(
        grant_type="authorization_code", code=code, redirect_uri=CALLBACK, client_id="web-ui", code_verifier=VERIFIER
    )).json()


def basic(client_id, secret):
    return {"Authorization": "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()}


class TestDiscovery:
    def test_the_document_points_at_the_endpoints(self, web):
        doc = web.get("/.well-known/openid-configuration").json()

        assert doc["issuer"] == "http://idp.test" and doc["token_endpoint"] == "http://idp.test/token"
        assert doc["jwks_uri"] == "http://idp.test/jwks.json" and doc["code_challenge_methods_supported"] == ["S256"]
        assert doc["response_types_supported"] == ["code"]

    def test_the_keys_verify_what_the_server_signs(self, web, keyring):
        published = web.get("/jwks.json").json()["keys"]

        assert [k["kid"] for k in published] == [keyring.active.kid]
        assert "d" not in published[0]

    def test_health(self, web):
        assert web.get("/health").json() == {"status": "ok"}


class TestSignInPage:
    def test_a_valid_request_shows_the_form_with_the_request_carried_along(self, web):
        page = web.get("/authorize", params=authorize_params())

        assert page.status_code == 200 and "Example App" in page.text
        for name in ("client_id", "redirect_uri", "code_challenge", "state", "nonce"):
            assert f'name="{name}"' in page.text
        assert page.headers["cache-control"] == "no-store"

    def test_the_page_cannot_be_framed(self, web):
        headers = web.get("/authorize", params=authorize_params()).headers

        assert headers["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in headers["content-security-policy"]

    def test_values_in_the_request_cannot_inject_html(self, web):
        page = web.get("/authorize", params=authorize_params(state='"><script>alert(1)</script>'))

        assert "<script>alert(1)</script>" not in page.text

    def test_an_unknown_app_is_an_error_page_not_a_redirect(self, web):
        response = web.get("/authorize", params=authorize_params(client_id="ghost"))

        assert response.status_code == 400 and "location" not in response.headers

    def test_an_unregistered_return_address_is_an_error_page_not_a_redirect(self, web):
        for uri in ("http://evil.test/cb", CALLBACK + "/", CALLBACK + "?x=1", None):
            response = web.get("/authorize", params=authorize_params(redirect_uri=uri))

            assert response.status_code == 400 and "location" not in response.headers

    def test_other_problems_go_back_to_the_app_with_an_error(self, web):
        cases = {
            "response_type": ("token", "unsupported_response_type"),
            "code_challenge": (None, "invalid_request"),
            "code_challenge_method": ("plain", "invalid_request"),
            "scope": ("openid admin", "invalid_scope"),
        }
        for field, (value, error) in cases.items():
            response = web.get("/authorize", params=authorize_params(**{field: value}))

            assert response.status_code == 303
            assert response.headers["location"].startswith(CALLBACK + "?")
            assert query_of(response)["error"] == error and query_of(response)["state"] == "st-1"
            assert query_of(response)["iss"] == "http://idp.test"


class TestSigningIn:
    def test_a_good_sign_in_redirects_back_with_a_code_state_and_issuer(self, web):
        response = sign_in(web)

        assert response.status_code == 303 and response.headers["location"].startswith(CALLBACK + "?")
        assert set(query_of(response)) == {"code", "state", "iss"}
        assert query_of(response)["state"] == "st-1" and query_of(response)["iss"] == "http://idp.test"

    def test_a_wrong_password_shows_the_form_again(self, web):
        response = sign_in(web, password="wrong")

        assert response.status_code == 401 and "Invalid email or password" in response.text and "location" not in response.headers

    def test_failed_attempts_lock_the_account_even_across_requests(self, web, settings):
        for _ in range(settings.max_failed_logins):
            sign_in(web, password="wrong")

        locked = sign_in(web, password=PASSWORD)

        assert locked.status_code == 401 and "locked" in locked.text

    def test_the_posted_request_is_checked_again_not_trusted(self, web):
        evil = sign_in(web, redirect_uri="http://evil.test/cb")
        no_pkce = sign_in(web, code_challenge=None)

        assert evil.status_code == 400 and "location" not in evil.headers
        assert no_pkce.status_code == 303 and query_of(no_pkce)["error"] == "invalid_request"


class TestAuthorizationCodeFlow:
    def test_the_whole_flow(self, web, keyring, world):
        result = get_tokens(web)

        access = jwt.decode(result["access_token"], keyring.active.private_key.public_key(), algorithms=["RS256"],
                            audience="todo-api", issuer="http://idp.test")
        ident = jwt.decode(result["id_token"], keyring.active.private_key.public_key(), algorithms=["RS256"],
                           audience="web-ui", issuer="http://idp.test")
        assert access["email"] == "amy@fund.org" and access["sub"] == str(world.account_id)
        assert ident["nonce"] == "nonce-1" and ident["email"] == "amy@fund.org"

    def test_tokens_are_never_cached(self, web):
        code = query_of(sign_in(web))["code"]

        response = web.post("/token", data=dict(grant_type="authorization_code", code=code, redirect_uri=CALLBACK,
                                                client_id="web-ui", code_verifier=VERIFIER))

        assert response.headers["cache-control"] == "no-store" and response.headers["pragma"] == "no-cache"

    def test_a_wrong_verifier_is_refused(self, web):
        code = query_of(sign_in(web))["code"]

        response = web.post("/token", data=dict(grant_type="authorization_code", code=code, redirect_uri=CALLBACK,
                                                client_id="web-ui", code_verifier="z" * 43))

        assert response.status_code == 400 and response.json()["error"] == "invalid_grant"

    def test_a_reused_code_revokes_what_it_produced_even_though_the_request_fails(self, web):
        code = query_of(sign_in(web))["code"]
        form = dict(grant_type="authorization_code", code=code, redirect_uri=CALLBACK, client_id="web-ui", code_verifier=VERIFIER)
        first = web.post("/token", data=form).json()

        assert web.post("/token", data=form).status_code == 400
        revived = web.post("/token", data=dict(grant_type="refresh_token", refresh_token=first["refresh_token"], client_id="web-ui"))

        assert revived.status_code == 400 and revived.json()["error"] == "invalid_grant"

    def test_an_unknown_app_is_invalid_client(self, web):
        response = web.post("/token", data=dict(grant_type="authorization_code", client_id="ghost"))

        assert response.status_code == 401 and response.json()["error"] == "invalid_client"

    def test_an_unsupported_grant(self, web):
        response = web.post("/token", data=dict(grant_type="password", client_id="web-ui", username="a", password="b"))

        assert response.status_code == 400 and response.json()["error"] == "unsupported_grant_type"


class TestRefreshOverHttp:
    def test_rotation_and_reuse_detection(self, web):
        first = get_tokens(web)
        step = lambda token: web.post("/token", data=dict(grant_type="refresh_token", refresh_token=token, client_id="web-ui"))

        second = step(first["refresh_token"])
        assert second.status_code == 200 and second.json()["refresh_token"] != first["refresh_token"]

        assert step(first["refresh_token"]).status_code == 400  # the old one again: a leak
        assert step(second.json()["refresh_token"]).status_code == 400  # so the whole family is gone

    def test_revoke_ends_the_session(self, web):
        first = get_tokens(web)

        revoked = web.post("/revoke", data=dict(token=first["refresh_token"], client_id="web-ui"))
        again = web.post("/token", data=dict(grant_type="refresh_token", refresh_token=first["refresh_token"], client_id="web-ui"))

        assert revoked.status_code == 200 and again.status_code == 400

    def test_revoke_answers_200_for_a_token_it_does_not_know(self, web):
        assert web.post("/revoke", data=dict(token="never-issued", client_id="web-ui")).status_code == 200

    def test_revoke_still_needs_a_known_app(self, web):
        assert web.post("/revoke", data=dict(token="x", client_id="ghost")).status_code == 401


class TestClientCredentialsOverHttp:
    def test_a_service_signs_in_with_http_basic(self, web, keyring):
        response = web.post("/token", data=dict(grant_type="client_credentials", scope="claims:write"),
                            headers=basic("claim-processor", "s3cret"))

        claims = jwt.decode(response.json()["access_token"], keyring.active.private_key.public_key(), algorithms=["RS256"],
                            audience="todo-api", issuer="http://idp.test")
        assert response.status_code == 200 and claims["sub"] == "claim-processor" and claims["scope"] == "claims:write"

    def test_or_with_the_secret_in_the_form(self, web):
        response = web.post("/token", data=dict(grant_type="client_credentials", client_id="claim-processor", client_secret="s3cret"))

        assert response.status_code == 200

    def test_a_wrong_secret_is_refused_and_asks_for_basic_credentials(self, web):
        response = web.post("/token", data=dict(grant_type="client_credentials"), headers=basic("claim-processor", "wrong"))

        assert response.status_code == 401 and response.json()["error"] == "invalid_client"
        assert response.headers["www-authenticate"].startswith("Basic")

    def test_malformed_basic_credentials_are_refused(self, web):
        response = web.post("/token", data=dict(grant_type="client_credentials"), headers={"Authorization": "Basic !!!"})

        assert response.status_code == 401


class TestUserinfo:
    def test_it_returns_the_claims_the_scopes_allow(self, web, world):
        access = get_tokens(web)["access_token"]

        info = web.get("/userinfo", headers={"Authorization": f"Bearer {access}"}).json()

        assert info == {"sub": str(world.account_id), "email": "amy@fund.org", "given_name": "Amy", "family_name": "Lee", "name": "Amy Lee"}

    def test_only_email_when_only_email_was_granted(self, web, world):
        access = get_tokens(web, scope="openid email")["access_token"]

        assert web.get("/userinfo", headers={"Authorization": f"Bearer {access}"}).json() == {"sub": str(world.account_id), "email": "amy@fund.org"}

    def test_a_token_without_openid_is_forbidden(self, web):
        access = get_tokens(web, scope="email")["access_token"]

        assert web.get("/userinfo", headers={"Authorization": f"Bearer {access}"}).status_code == 403

    def test_no_token_or_a_bad_one_is_a_401(self, web):
        assert web.get("/userinfo").status_code == 401
        assert web.get("/userinfo", headers={"Authorization": "Bearer nonsense"}).status_code == 401

    def test_the_id_token_is_not_accepted_as_an_access_token(self, web):
        ident = get_tokens(web)["id_token"]

        assert web.get("/userinfo", headers={"Authorization": f"Bearer {ident}"}).status_code == 401

    def test_a_service_token_has_no_person_to_describe(self, web):
        access = web.post("/token", data=dict(grant_type="client_credentials", scope="claims:read"),
                          headers=basic("claim-processor", "s3cret")).json()["access_token"]

        assert web.get("/userinfo", headers={"Authorization": f"Bearer {access}"}).status_code == 403


class TestBrowserAccess:
    def test_the_web_apps_origin_may_call_the_token_endpoint(self, web):
        preflight = web.options("/token", headers={
            "Origin": "http://localhost:5174", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"})

        assert preflight.status_code == 200 and preflight.headers["access-control-allow-origin"] == "http://localhost:5174"

    def test_another_origin_may_not(self, web):
        preflight = web.options("/token", headers={"Origin": "http://evil.test", "Access-Control-Request-Method": "POST"})

        assert "access-control-allow-origin" not in preflight.headers
