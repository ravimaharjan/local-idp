"""The browser UI's side of OAuth 2.0 with the IdP: authorization code + PKCE, refresh, revoke. The UI is a public app, so it
has no secret; PKCE (a random verifier whose SHA-256 goes in the sign-in request) proves the code is redeemed by whoever
started the sign-in."""
from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any, Optional
from urllib.parse import urlencode

import httpx

from todo_api.config import Settings


class IdpError(Exception):
    """The IdP refused a request (`description` is its own words) or could not be reached."""


def new_verifier() -> str:
    return secrets.token_urlsafe(64)  # 86 characters; RFC 7636 wants 43 to 128


def challenge_for(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()


class IdpClient:
    def __init__(self, settings: Settings, http: Optional[httpx.Client] = None) -> None:
        self._settings = settings
        self._http = http or httpx.Client(timeout=5)

    def authorize_url(self, *, state: str, verifier: str) -> str:
        s = self._settings
        query = {
            "client_id": s.ui_client_id, "redirect_uri": s.ui_redirect_uri, "response_type": "code", "scope": s.ui_scopes,
            "audience": s.audience,  # the access token is for this API
            "state": state, "code_challenge": challenge_for(verifier), "code_challenge_method": "S256",
        }
        return f"{s.authorize_url}?{urlencode(query)}"

    def exchange_code(self, code: str, verifier: str) -> dict[str, Any]:
        s = self._settings
        return self._token_request(
            grant_type="authorization_code", code=code, redirect_uri=s.ui_redirect_uri, code_verifier=verifier,
            client_id=s.ui_client_id,
        )

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        return self._token_request(grant_type="refresh_token", refresh_token=refresh_token, client_id=self._settings.ui_client_id)

    def revoke(self, refresh_token: str) -> None:
        try:
            self._http.post(self._settings.revoke_url, data={"token": refresh_token, "client_id": self._settings.ui_client_id})
        except httpx.HTTPError:
            pass  # best effort: the token expires anyway

    def _token_request(self, **form: str) -> dict[str, Any]:
        try:
            response = self._http.post(self._settings.token_url, data=form)
        except httpx.HTTPError as error:
            raise IdpError("the identity provider cannot be reached") from error
        body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        if response.status_code != 200:
            raise IdpError(body.get("error_description") or body.get("error") or f"token request failed ({response.status_code})")
        return body
