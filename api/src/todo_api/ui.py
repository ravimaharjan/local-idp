"""The browser UI: a few server-rendered pages. `/` shows the sign-in button or the person's todos; `/login` sends the browser
to the IdP's sign-in page; the IdP sends it back to `/auth/callback` with a one-time code, which is exchanged for tokens kept in
a server-side session. Todo actions go through the same IdP-issued access token and scope checks as the JSON API."""
from __future__ import annotations

import hmac
import secrets
from pathlib import Path
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, FastAPI, Form, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from todo_api.auth import IdpUnavailable, Principal, TokenInvalid
from todo_api.idp_client import IdpError, new_verifier
from todo_api.todos import TodoCreate, TodoUpdate

COOKIE = "todo_sid"
_templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
_NO_STORE = {"Cache-Control": "no-store"}
router = APIRouter(include_in_schema=False)


class UiResponse(Exception):
    """Raised to end a request early with a ready response (a redirect to sign in, an error page)."""

    def __init__(self, response: Response) -> None:
        self.response = response


def install(api: FastAPI) -> None:
    api.include_router(router)

    @api.exception_handler(UiResponse)
    def _ui_response(request: Request, error: UiResponse) -> Response:
        return error.response

    @api.exception_handler(IdpUnavailable)
    def _idp_unavailable(request: Request, error: IdpUnavailable) -> Response:
        return _page(request, "error.html", 503, message="The identity provider cannot be reached.")


def _page(request: Request, name: str, status: int = 200, **context) -> Response:
    return _templates.TemplateResponse(request, name, context, status_code=status, headers=_NO_STORE)


def _redirect(path: str, request: Request, sid: Optional[str] = None, *, clear: bool = False) -> Response:
    response = RedirectResponse(path, status_code=303, headers=_NO_STORE)
    if clear:
        response.delete_cookie(COOKIE, path="/")
    elif sid:
        response.set_cookie(
            COOKIE, sid, httponly=True, samesite="lax", secure=request.app.state.settings.ui_cookie_secure, path="/"
        )
    return response


def _current(request: Request) -> tuple[Optional[str], Optional[dict], Optional[Principal]]:
    """The session and who it belongs to, or no principal when not signed in. An expired access token is renewed with the
    refresh token if there is one; if that fails too the session is ended."""
    sid = request.cookies.get(COOKIE)
    sessions = request.app.state.sessions
    data = sessions.get(sid)
    if not data or "access_token" not in data:
        return sid, data, None
    verifier = request.app.state.verifier
    try:
        return sid, data, verifier.verify(data["access_token"])
    except TokenInvalid:
        pass
    try:
        data.update(_kept(request.app.state.idp.refresh(data["refresh_token"])))
        return sid, data, verifier.verify(data["access_token"])
    except (KeyError, IdpError, TokenInvalid):
        sessions.delete(sid)
        return sid, None, None


def _kept(tokens: dict) -> dict:
    return {k: tokens[k] for k in ("access_token", "refresh_token") if k in tokens}


def _require(request: Request, csrf: str, scope_of) -> Principal:
    """For form posts: a signed-in person, a matching CSRF token and the scope; otherwise ends the request."""
    _, data, principal = _current(request)
    if principal is None:
        raise UiResponse(_redirect("/login", request))
    if not hmac.compare_digest(csrf, data.get("csrf", "")):
        raise UiResponse(_page(request, "error.html", 403, message="The form expired. Go back and try again."))
    scope = scope_of(request.app.state.settings)
    if not principal.has_scope(scope):
        raise UiResponse(_page(request, "error.html", 403, message=f"Your sign-in does not allow this (needs {scope})."))
    return principal


@router.get("/")
def home(request: Request) -> Response:
    settings = request.app.state.settings
    _, data, principal = _current(request)
    if principal is None:
        return _page(request, "index.html", user=None)
    can_read = principal.has_scope(settings.read_scope)
    return _page(
        request, "index.html", user=principal.email or principal.subject, csrf=data["csrf"], can_read=can_read,
        can_write=principal.has_scope(settings.write_scope),
        todos=request.app.state.todos.list(principal.subject) if can_read else [],
    )


@router.get("/login")
def login(request: Request) -> Response:
    state, verifier = secrets.token_urlsafe(24), new_verifier()
    sid = request.app.state.sessions.create({"state": state, "verifier": verifier})  # remembered for the callback
    return _redirect(request.app.state.idp.authorize_url(state=state, verifier=verifier), request, sid)


@router.get("/auth/callback")
def callback(request: Request) -> Response:
    sessions, settings = request.app.state.sessions, request.app.state.settings
    params = request.query_params
    sid = request.cookies.get(COOKIE)
    pending = sessions.get(sid)
    sessions.delete(sid)  # a sign-in attempt is single use, whatever happens next

    def fail(message: str, status: int = 400) -> Response:
        return _page(request, "error.html", status, message=message, retry=True)

    if params.get("error"):
        return fail(f"The sign-in was refused: {params.get('error_description') or params['error']}")
    if not pending or "state" not in pending:
        return fail("There is no sign-in in progress (the page was reloaded, or the session expired).")
    if not hmac.compare_digest(params.get("state", ""), pending["state"]):
        return fail("The sign-in response does not match the request (state mismatch).")
    if params.get("iss", settings.issuer) != settings.issuer:
        return fail("The sign-in response came from an unexpected identity provider.")
    if not params.get("code"):
        return fail("The identity provider returned no code.")
    try:
        tokens = request.app.state.idp.exchange_code(params["code"], pending["verifier"])
    except IdpError as error:
        return fail(str(error), 502)
    # A fresh session id after sign-in, so one fixed beforehand is worthless.
    new_sid = sessions.create({**_kept(tokens), "csrf": secrets.token_urlsafe(24)})
    return _redirect("/", request, new_sid)


@router.post("/logout")
def logout(request: Request, csrf: str = Form("")) -> Response:
    sid, data, _ = _current(request)
    if data and "access_token" in data and hmac.compare_digest(csrf, data.get("csrf", "")):
        if data.get("refresh_token"):
            request.app.state.idp.revoke(data["refresh_token"])
        request.app.state.sessions.delete(sid)
    return _redirect("/", request, clear=True)


@router.post("/ui/todos")
def add_todo(request: Request, title: str = Form(""), csrf: str = Form("")) -> Response:
    principal = _require(request, csrf, lambda s: s.write_scope)
    title = title.strip()
    if 0 < len(title) <= 200:
        request.app.state.todos.create(principal.subject, TodoCreate(title=title))
    return _redirect("/", request)


@router.post("/ui/todos/{todo_id}/toggle")
def toggle_todo(request: Request, todo_id: UUID, csrf: str = Form("")) -> Response:
    principal = _require(request, csrf, lambda s: s.write_scope)
    todos = request.app.state.todos
    todo = todos.get(principal.subject, todo_id)
    if todo is not None:
        todos.update(principal.subject, todo_id, TodoUpdate(done=not todo.done))
    return _redirect("/", request)


@router.post("/ui/todos/{todo_id}/delete")
def delete_todo(request: Request, todo_id: UUID, csrf: str = Form("")) -> Response:
    principal = _require(request, csrf, lambda s: s.write_scope)
    request.app.state.todos.delete(principal.subject, todo_id)
    return _redirect("/", request)
