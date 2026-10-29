# todo-api

A small todo web app that signs people in with the local identity provider (`../idp`, `local-idp`). It is a server-rendered
FastAPI app (Jinja templates): the server runs the OAuth sign-in, keeps the tokens in a server-side session, and keeps an
in-memory todo list per person (lost on restart).

## How sign-in works

`/` is a page with a Sign in button, then the person's todo list. Templates are in `src/todo_api/templates/`.

1. `GET /login` creates a one-time `state` and a PKCE verifier, and redirects the browser to the IdP's `/authorize` (asking for
   `audience=todo-api` and the todo scopes).
2. The person signs in on the IdP's page. The IdP redirects to `/auth/callback?code=...&state=...`.
3. The server checks `state`, exchanges the code (with the PKCE verifier) at the IdP's `/token`, and keeps the tokens in a
   server-side session. The browser gets only an opaque `HttpOnly` cookie, so you will not see the tokens in its network tab;
   the `/token` call is server to server (it shows in the IdP's log).
4. Every page and form post is checked against that session: the access token is verified against the IdP's public keys
   (`/jwks.json`, cached): RS256 signature, `typ: at+jwt`, `iss`, `aud`, `exp`. The token's `scope` must contain `todos:read`
   to see the list and `todos:write` to change it. Forms also carry a CSRF token. An expired access token is renewed with the
   refresh token; sign out revokes the refresh token and ends the session.

Todos belong to the token's `sub`, so people never see each other's. The code is in `ui.py` (routes and session checks),
`idp_client.py` (the calls to the IdP), `auth.py` (token verification), `sessions.py` and `todos.py`.

## Run it

```bash
cp .env.example .env                 # IDP_ISSUER = the IdP's IDP_ISSUER; IDP_AUDIENCE = this API's audience (register-api)
uv sync
uv run uvicorn todo_api.main:create_app --factory --port 5174 --reload
```

Register the app on the IdP once (the redirect URI must match `UI_REDIRECT_URI` exactly, and the app id `UI_CLIENT_ID`), and
create a person to sign in with:

```bash
cd ../idp
uv run local-idp register-api --audience todo-api --name "Todo API"
uv run local-idp register-app --app-id todo-ui --name "Todo UI" --type public \
    --redirect-uri http://localhost:5174/auth/callback \
    --scope openid --scope profile --scope email --scope todos:read --scope todos:write --audience todo-api
uv run local-idp create-user --email priya@example.org --given-name Priya    # asks for the password
```

Then start both servers (IdP on :9001, this app on :5174) and open http://localhost:5174. `GET /health` answers `ok`.

## Routes

| | |
|---|---|
| `GET /` | sign-in page, or the todo list |
| `GET /login` | starts the sign-in at the IdP |
| `GET /auth/callback` | where the IdP sends the browser back |
| `POST /logout` | ends the session |
| `POST /ui/todos`, `/ui/todos/{id}/toggle`, `/ui/todos/{id}/delete` | change the list (need `todos:write`) |
| `GET /health` | liveness |

## Tests

```bash
uv run pytest      # signs tokens with a throwaway key and fakes the IdP; it need not be running
```
