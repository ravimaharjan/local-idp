"""The HTTP side: discovery, signing keys, the sign-in page (`/authorize`), token issuing (`/token`), `/userinfo` and
`/revoke`. The paths and parameter names are the OAuth 2.0 / OpenID Connect ones -- an external contract clients rely on.

Run it with `uvicorn local_idp.main:create_app --factory --port 9001`.

There is no server-side session: `/authorize` shows the sign-in form, and the form's POST validates the whole request again
before signing the person in, so nothing the browser sends is trusted just because the first page accepted it. The price is
that every sign-in asks for the password (no single sign-on yet)."""
from __future__ import annotations

import base64
import binascii
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit
from uuid import UUID

import jwt
from fastapi import Depends, FastAPI, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from psycopg_pool import ConnectionPool

from local_idp import accounts, registry, tokens
from local_idp.config import Settings
from local_idp.db import open_pool
from local_idp.keys import KeyRing, load_keyring
from local_idp.registry import App
from local_idp.tokens import OAuthError

_templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_MAX_STATE = 512
_MAX_NONCE = 256


class PageError(Exception):
    """A problem with the client_id or redirect_uri: shown to the person, never redirected (that could send them anywhere)."""


class RedirectError(Exception):
    """Any other problem with an authorization request: sent back to the app's registered redirect_uri."""

    def __init__(self, redirect_uri: str, error: str, description: str, state: Optional[str]) -> None:
        super().__init__(description)
        self.redirect_uri, self.error, self.description, self.state = redirect_uri, error, description, state


@dataclass(frozen=True)
class AuthorizationRequest:
    app: App
    redirect_uri: str
    scopes: list[str]
    audience: str
    state: Optional[str]
    nonce: Optional[str]
    code_challenge: str


def validate_authorization_request(conn, settings: Settings, params: Mapping[str, Optional[str]]) -> AuthorizationRequest:
    app = registry.find_app(conn, params.get("client_id") or "")
    if app is None:
        raise PageError("This application is not registered.")
    redirect_uri = params.get("redirect_uri") or ""
    if not app.has_redirect_uri(redirect_uri):
        raise PageError("The return address is not registered for this application.")

    state, nonce = params.get("state"), params.get("nonce")

    def fail(error: str, description: str):
        raise RedirectError(redirect_uri, error, description, state)

    if len(state or "") > _MAX_STATE or len(nonce or "") > _MAX_NONCE:
        fail("invalid_request", "state or nonce is too long")
    if params.get("response_type") != "code":
        fail("unsupported_response_type", "only response_type=code is supported")
    if not app.allows_grant("authorization_code"):
        fail("unauthorized_client", "this app may not use the authorization code flow")
    code_challenge = params.get("code_challenge") or ""
    if not tokens.is_valid_challenge(code_challenge):
        fail("invalid_request", "a PKCE code_challenge is required")
    if params.get("code_challenge_method") != "S256":
        fail("invalid_request", "code_challenge_method must be S256")
    try:
        scopes = tokens.resolve_scopes(app, params.get("scope"))
        audience = tokens.resolve_audience(conn, settings, app, params.get("audience"))
    except OAuthError as error:
        fail(error.error, error.description)
    return AuthorizationRequest(app, redirect_uri, scopes, audience, state, nonce or None, code_challenge)


def _with_query(url: str, params: dict[str, Optional[str]]) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True) + [(k, v) for k, v in params.items() if v is not None]
    return urlunsplit(parts._replace(query=urlencode(query)))


def _used_basic(request: Request) -> bool:
    return request.headers.get("authorization", "").lower().startswith("basic ")


def _client_credentials(request: Request, form_id: Optional[str], form_secret: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """The app's identifier and secret: from HTTP Basic if sent, else from the form."""
    if _used_basic(request):
        try:
            decoded = base64.b64decode(request.headers["authorization"][6:], validate=True).decode()
        except (binascii.Error, UnicodeDecodeError):
            return None, None
        client_id, _, secret = decoded.partition(":")
        return unquote_plus(client_id), unquote_plus(secret)
    return form_id, form_secret


def _oauth_error(error: OAuthError, *, basic: bool = False) -> JSONResponse:
    headers = dict(_NO_STORE)
    if error.status == 401 and basic:
        headers["WWW-Authenticate"] = 'Basic realm="local-idp"'
    return JSONResponse({"error": error.error, "error_description": error.description}, status_code=error.status, headers=headers)


def authenticate_app(conn, request: Request, form_id: Optional[str], form_secret: Optional[str]) -> App:
    client_id, secret = _client_credentials(request, form_id, form_secret)
    app = registry.find_app(conn, client_id or "") if client_id else None
    if app is None or (app.is_confidential and not app.secret_matches(secret or "")):
        raise OAuthError("invalid_client", "unknown app or wrong secret", status=401)
    return app


def create_app(
    settings: Optional[Settings] = None, *, pool: Optional[ConnectionPool] = None, keyring: Optional[KeyRing] = None
) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        owns_pool = not hasattr(app.state, "pool")
        if owns_pool:
            app.state.pool = open_pool(settings.db_dsn)
        if not hasattr(app.state, "keyring"):
            app.state.keyring = load_keyring(settings.keys_dir)
        yield
        if owns_pool:
            app.state.pool.close()

    api = FastAPI(title="local-idp", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    api.state.settings = settings
    if pool is not None:
        api.state.pool = pool
    if keyring is not None:
        api.state.keyring = keyring
    api.add_middleware(
        CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @api.middleware("http")
    async def protective_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"  # the sign-in page must never be framed (clickjacking)
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
        return response

    def get_conn(request: Request):
        with request.app.state.pool.connection() as conn:
            yield conn

    def page(request: Request, name: str, status: int = 200, **context: Any) -> Response:
        return _templates.TemplateResponse(request, name, context, status_code=status, headers=_NO_STORE)

    # --- discovery ---

    @api.get("/.well-known/openid-configuration")
    def discovery() -> dict[str, Any]:
        issuer = settings.issuer
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "userinfo_endpoint": f"{issuer}/userinfo",
            "revocation_endpoint": f"{issuer}/revoke",
            "jwks_uri": f"{issuer}/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": list(registry.GRANT_TYPES),
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True,
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "given_name", "family_name", "name"],
        }

    @api.get("/jwks.json")
    def jwks(request: Request) -> JSONResponse:
        return JSONResponse(request.app.state.keyring.jwks(), headers={"Cache-Control": "public, max-age=60"})

    @api.get("/health")
    def health(conn=Depends(get_conn)) -> dict[str, str]:
        conn.execute("SELECT 1")
        return {"status": "ok"}

    # --- sign-in ---

    def sign_in_form(request: Request, auth: AuthorizationRequest, params: Mapping[str, Optional[str]], error: Optional[str] = None):
        hidden = {
            name: params.get(name) or ""
            for name in ("client_id", "redirect_uri", "response_type", "scope", "audience", "state", "nonce", "code_challenge", "code_challenge_method")
            if params.get(name) is not None
        }
        return page(request, "login.html", 401 if error else 200, app_name=auth.app.name, hidden=hidden, error=error)

    def authorization_failure(request: Request, error: Exception) -> Response:
        if isinstance(error, PageError):
            return page(request, "error.html", 400, message=str(error))
        assert isinstance(error, RedirectError)
        target = _with_query(
            error.redirect_uri,
            {"error": error.error, "error_description": error.description, "state": error.state, "iss": settings.issuer},
        )
        return RedirectResponse(target, status_code=303, headers=_NO_STORE)

    @api.get("/authorize")
    def authorize(request: Request, conn=Depends(get_conn)) -> Response:
        params = dict(request.query_params)
        try:
            auth = validate_authorization_request(conn, settings, params)
        except (PageError, RedirectError) as error:
            return authorization_failure(request, error)
        return sign_in_form(request, auth, params)

    @api.post("/authorize")
    def authorize_submit(
        request: Request,
        conn=Depends(get_conn),
        client_id: str = Form(""),
        redirect_uri: str = Form(""),
        response_type: str = Form(""),
        scope: Optional[str] = Form(None),
        audience: Optional[str] = Form(None),
        state: Optional[str] = Form(None),
        nonce: Optional[str] = Form(None),
        code_challenge: str = Form(""),
        code_challenge_method: str = Form(""),
        email: str = Form(""),
        password: str = Form(""),
    ) -> Response:
        params = {
            "client_id": client_id, "redirect_uri": redirect_uri, "response_type": response_type, "scope": scope,
            "audience": audience, "state": state, "nonce": nonce, "code_challenge": code_challenge, "code_challenge_method": code_challenge_method,
        }
        try:
            auth = validate_authorization_request(conn, settings, params)  # the form's fields are as untrusted as the query string was
        except (PageError, RedirectError) as error:
            return authorization_failure(request, error)
        try:
            account = accounts.sign_in(conn, settings, email, password)
        except accounts.SignInFailed as failure:
            return sign_in_form(request, auth, params, error=str(failure))  # returns normally: failed attempts are committed
        code = tokens.issue_authorization_code(
            conn, settings, app=auth.app, account=account, redirect_uri=auth.redirect_uri, scopes=auth.scopes,
            audience=auth.audience, code_challenge=auth.code_challenge, nonce=auth.nonce,
        )
        target = _with_query(auth.redirect_uri, {"code": code, "state": auth.state, "iss": settings.issuer})
        return RedirectResponse(target, status_code=303, headers=_NO_STORE)

    # --- tokens ---

    @api.post("/token")
    def token(
        request: Request,
        conn=Depends(get_conn),
        grant_type: str = Form(""),
        code: Optional[str] = Form(None),
        redirect_uri: Optional[str] = Form(None),
        code_verifier: Optional[str] = Form(None),
        refresh_token: Optional[str] = Form(None),
        scope: Optional[str] = Form(None),
        audience: Optional[str] = Form(None),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
    ) -> Response:
        keyring: KeyRing = request.app.state.keyring
        try:
            app = authenticate_app(conn, request, client_id, client_secret)
            if grant_type == "authorization_code":
                body = tokens.exchange_authorization_code(
                    conn, settings, keyring, app=app, code=code, redirect_uri=redirect_uri, code_verifier=code_verifier
                )
            elif grant_type == "refresh_token":
                body = tokens.refresh(conn, settings, keyring, app=app, refresh_token=refresh_token, scope=scope)
            elif grant_type == "client_credentials":
                body = tokens.client_credentials(conn, settings, keyring, app=app, scope=scope, audience=audience)
            else:
                raise OAuthError("unsupported_grant_type", f"unsupported grant_type: {grant_type or '(missing)'}")
        except OAuthError as error:
            conn.commit()  # keep what the error handling did (a reused code's family revoked), see tokens.py
            return _oauth_error(error, basic=_used_basic(request))
        return JSONResponse(body, headers=_NO_STORE)

    @api.post("/revoke")
    def revoke(
        request: Request,
        conn=Depends(get_conn),
        token: str = Form(""),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
    ) -> Response:
        try:
            app = authenticate_app(conn, request, client_id, client_secret)
        except OAuthError as error:
            return _oauth_error(error, basic=_used_basic(request))
        if token:
            tokens.revoke_token(conn, app, token)
        return Response(status_code=200, headers=_NO_STORE)

    # --- userinfo ---

    def invalid_token(description: str, status: int = 401) -> JSONResponse:
        error = "invalid_token" if status == 401 else "insufficient_scope"
        return JSONResponse(
            {"error": error, "error_description": description}, status_code=status,
            headers={**_NO_STORE, "WWW-Authenticate": f'Bearer error="{error}"'},
        )

    @api.get("/userinfo")
    def userinfo(request: Request, conn=Depends(get_conn)) -> Response:
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            return JSONResponse({"error": "invalid_request"}, status_code=401, headers={**_NO_STORE, "WWW-Authenticate": "Bearer"})
        keyring: KeyRing = request.app.state.keyring
        raw = header[7:].strip()
        try:
            key = keyring.public_key_for(jwt.get_unverified_header(raw).get("kid", ""))
            if key is None or jwt.get_unverified_header(raw).get("typ") != "at+jwt":
                return invalid_token("not an access token issued here")
            claims = jwt.decode(
                raw, key, algorithms=["RS256"], issuer=settings.issuer,  # any audience: this endpoint is the IdP's own
                options={"require": ["exp", "iss", "aud", "sub"], "verify_aud": False},
            )
        except jwt.PyJWTError:
            return invalid_token("the access token is invalid or expired")
        scopes = str(claims.get("scope", "")).split()
        if "openid" not in scopes:
            return invalid_token("the token has no openid scope", status=403)
        try:
            subject = UUID(claims["sub"])
        except ValueError:
            return invalid_token("the token does not stand for a person")
        account = accounts.find_account(conn, subject)
        if account is None:
            return invalid_token("the account is no longer active")
        return JSONResponse({"sub": str(account.id), **tokens.profile_claims(account, scopes)}, headers=_NO_STORE)

    return api
