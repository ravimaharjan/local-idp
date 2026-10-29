"""The browser flow: sign in through the IdP (faked), then use the todo pages."""
import re
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from todo_api.auth import TokenVerifier
from todo_api.idp_client import IdpClient, IdpError, challenge_for
from todo_api.main import create_app
from tests.conftest import SETTINGS


class FakeIdp(IdpClient):
    """The real URL building, with the token endpoint replaced."""

    def __init__(self, make_token):
        super().__init__(SETTINGS)
        self.make_token = make_token
        self.scope = "openid todos:read todos:write"
        self.sub = "amy"
        self.revoked = []
        self.refreshed = 0

    def exchange_code(self, code, verifier):
        if code != "good-code":
            raise IdpError("the authorization code is invalid, expired or already used")
        self.verifier = verifier
        return {"access_token": self.make_token(scope=self.scope, sub=self.sub), "refresh_token": "r1"}

    def refresh(self, refresh_token):
        self.refreshed += 1
        if refresh_token != "r1":
            raise IdpError("the refresh token is invalid")
        return {"access_token": self.make_token(scope=self.scope, sub=self.sub), "refresh_token": "r2"}

    def revoke(self, refresh_token):
        self.revoked.append(refresh_token)


@pytest.fixture
def idp(make_token):
    return FakeIdp(make_token)


@pytest.fixture
def browser(keys, idp):
    app = create_app(SETTINGS, verifier=TokenVerifier(SETTINGS, jwks_client=keys), idp=idp)
    return TestClient(app, follow_redirects=False)


def sign_in(browser):
    """Does what the browser does: /login, the IdP, then back to the callback with a code."""
    login = browser.get("/login")
    state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
    return browser.get("/auth/callback", params={"code": "good-code", "state": state, "iss": SETTINGS.issuer})


def csrf_of(page: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


def test_signed_out_home_offers_sign_in(browser):
    page = browser.get("/")
    assert page.status_code == 200 and 'href="/login"' in page.text


def test_login_redirects_to_the_idp_with_pkce_and_the_api_audience(browser):
    response = browser.get("/login")
    assert response.status_code == 303
    target = urlsplit(response.headers["location"])
    query = {k: v[0] for k, v in parse_qs(target.query).items()}
    assert f"{target.scheme}://{target.netloc}{target.path}" == "http://idp.test/authorize"
    assert query["client_id"] == "todo-ui" and query["response_type"] == "code"
    assert query["redirect_uri"] == "http://localhost:5174/auth/callback"
    assert query["audience"] == SETTINGS.audience
    assert query["code_challenge_method"] == "S256" and len(query["code_challenge"]) == 43
    assert "todos:write" in query["scope"].split()
    assert "httponly" in response.headers["set-cookie"].lower()


def test_callback_signs_in_and_redirects_home(browser):
    callback = sign_in(browser)
    assert callback.status_code == 303 and callback.headers["location"] == "/"
    assert "Signed in as priya@fundx.org" in browser.get("/").text


def test_the_verifier_sent_matches_the_challenge(browser, idp):
    login = browser.get("/login")
    query = parse_qs(urlsplit(login.headers["location"]).query)
    browser.get("/auth/callback", params={"code": "good-code", "state": query["state"][0]})
    assert challenge_for(idp.verifier) == query["code_challenge"][0]


def test_a_wrong_state_is_refused(browser):
    browser.get("/login")
    response = browser.get("/auth/callback", params={"code": "good-code", "state": "forged"})
    assert response.status_code == 400 and "state mismatch" in response.text
    assert "Signed in as" not in browser.get("/").text


def test_a_callback_without_a_sign_in_in_progress_is_refused(browser):
    assert browser.get("/auth/callback", params={"code": "good-code", "state": "x"}).status_code == 400


def test_an_idp_error_is_shown(browser):
    browser.get("/login")
    response = browser.get("/auth/callback", params={"error": "access_denied", "error_description": "nope"})
    assert response.status_code == 400 and "nope" in response.text


def test_a_rejected_code_is_shown(browser):
    state = parse_qs(urlsplit(browser.get("/login").headers["location"]).query)["state"][0]
    response = browser.get("/auth/callback", params={"code": "bad", "state": state})
    assert response.status_code == 502 and "invalid, expired or already used" in response.text


def test_a_callback_cannot_be_replayed(browser):
    state = parse_qs(urlsplit(browser.get("/login").headers["location"]).query)["state"][0]
    params = {"code": "good-code", "state": state}
    assert browser.get("/auth/callback", params=params).status_code == 303
    assert browser.get("/auth/callback", params=params).status_code == 400


def test_todo_lifecycle_in_the_browser(browser):
    sign_in(browser)
    csrf = csrf_of(browser.get("/").text)
    assert browser.post("/ui/todos", data={"title": "buy milk", "csrf": csrf}).status_code == 303
    page = browser.get("/").text
    assert "buy milk" in page
    todo_id = re.search(r"/ui/todos/([0-9a-f-]{36})/toggle", page).group(1)

    browser.post(f"/ui/todos/{todo_id}/toggle", data={"csrf": csrf})
    assert 'class="done"' in browser.get("/").text
    browser.post(f"/ui/todos/{todo_id}/delete", data={"csrf": csrf})
    assert "buy milk" not in browser.get("/").text


def test_each_person_sees_only_their_own_todos(browser, idp):
    sign_in(browser)
    browser.post("/ui/todos", data={"title": "amy's", "csrf": csrf_of(browser.get("/").text)})
    idp.sub = "bob"
    sign_in(browser)  # a new sign-in replaces the session
    page = browser.get("/").text
    assert "Nothing here yet." in page and "amy's" not in page


def test_there_are_no_json_routes(browser):
    for path in ("/todos", "/me", "/docs", "/openapi.json"):
        assert browser.get(path).status_code == 404


def test_the_page_says_so_when_the_idp_cannot_be_reached(browser, keys):
    sign_in(browser)
    keys.down = True
    response = browser.get("/")
    assert response.status_code == 503 and "cannot be reached" in response.text


def test_posting_without_the_csrf_token_is_refused(browser):
    sign_in(browser)
    assert browser.post("/ui/todos", data={"title": "x", "csrf": "wrong"}).status_code == 403
    assert browser.post("/ui/todos", data={"title": "x"}).status_code == 403


def test_posting_when_signed_out_goes_to_login(browser):
    response = browser.post("/ui/todos", data={"title": "x", "csrf": ""})
    assert response.status_code == 303 and response.headers["location"] == "/login"


def test_read_only_sign_in_cannot_change_todos(browser, idp):
    idp.scope = "openid todos:read"
    sign_in(browser)
    page = browser.get("/").text
    assert "Read-only" in page and 'action="/ui/todos"' not in page
    assert browser.post("/ui/todos", data={"title": "x", "csrf": csrf_of(page)}).status_code == 403


def test_logout_revokes_and_ends_the_session(browser, idp):
    sign_in(browser)
    response = browser.post("/logout", data={"csrf": csrf_of(browser.get("/").text)})
    assert response.status_code == 303 and idp.revoked == ["r1"]
    assert "Signed in as" not in browser.get("/").text


def test_an_expired_access_token_is_renewed_with_the_refresh_token(browser, idp, make_token):
    sign_in(browser)
    sessions = browser.app.state.sessions
    (data,) = sessions._data.values()
    data["access_token"] = make_token(exp=1, iat=0)
    assert "Signed in as" in browser.get("/").text
    assert idp.refreshed == 1 and data["refresh_token"] == "r2"


def test_an_expired_session_that_cannot_refresh_ends(browser, idp, make_token):
    sign_in(browser)
    (data,) = browser.app.state.sessions._data.values()
    data["access_token"] = make_token(exp=1, iat=0)
    data["refresh_token"] = "revoked"
    assert 'href="/login"' in browser.get("/").text
