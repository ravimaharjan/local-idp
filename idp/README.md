# local-idp

A local OAuth 2.0 authorization server with OpenID Connect, for any API that wants OAuth2-based authentication. Register
your applications with it, sign people in, and have your API verify the signed access tokens it issues against the public
keys at `/jwks.json`. Production would use a hosted provider (Keycloak, Auth0, Cognito, Okta); this is for developing and
learning locally. It has its own Postgres container, database and schema.

## Run it

```bash
cp .env.example .env                      # then check the values; see "Settings" below
uv sync
docker compose up -d --wait               # its own Postgres on :5435, schema loaded from db/schema/
uv run local-idp generate-key             # signing key -> ./keys (git-ignored)
uv run local-idp create-user --email testuser@example.org --given-name testuser --family-name test   # asks for the password
uv run local-idp register-api --audience todo-api --name "Todo API"      # an API that accepts tokens
uv run local-idp register-app --app-id web-ui --name "My App" --type public \
    --redirect-uri http://localhost:5174/auth/callback --scope openid --scope profile --scope email \
    --audience todo-api                                                   # the APIs this app may get tokens for
uv run uvicorn local_idp.main:create_app --factory --port 9001
```

Check it: `curl localhost:9001/.well-known/openid-configuration`.

A service that calls an API without a person (`client_credentials`):

```bash
uv run local-idp register-app --app-id my-service --type confidential --scope items:read --audience todo-api   # prints the secret once
curl -u my-service:<secret> -d grant_type=client_credentials -d scope=items:read -d audience=todo-api localhost:9001/token
```

Scopes are free-form: an app may only ask for the scopes it was registered with, and they appear in the token's `scope` claim,
which your API checks.

## Settings

Read from `.env` (see `.env.example`). The two that an API must agree with:

- `IDP_ISSUER` (default `http://localhost:9001`): the `iss` of every token. The API's issuer setting must equal it exactly.
- The API's audience: the identifier you gave to `register-api --audience ...`. Use the same value in the API.
- `IDP_API_AUDIENCE` (default `todo-api`) is only the default for a client that does not ask for an `audience`.

Postgres is published on `IDP_DB_PORT` (default 5435); change it if that port is taken.

## APIs and audiences

Like Auth0 or Okta, each API is registered with its own identifier, its **audience**, and that is the `aud` of the access
tokens issued for it, so an API accepts only tokens meant for it. Many APIs can share one IdP:

```bash
uv run local-idp register-api --audience todo-api  --name "Todo API"
uv run local-idp register-api --audience rider-api --name "Rider API"
uv run local-idp register-app --app-id web-ui ... --audience todo-api --audience rider-api   # may get tokens for both
```

A client names the API it wants with an `audience` parameter, on `/authorize` (signed-in people; kept through refresh) or on
`/token` (`client_credentials`). One token is for one API; a client that needs both asks twice. An API the app is not
registered for, or that does not exist, is refused with `invalid_target`. `/userinfo` accepts a token for any of the APIs.

## Using it from an API

Verify each bearer token locally, with no call to the IdP per request: fetch `/jwks.json` (cache it, refetch on an unknown
`kid`) and check the RS256 signature, `typ: at+jwt`, `iss`, `aud` and `exp`, then the `scope`. A person's access token also
carries `email`; a `client_credentials` token has the app id as `sub` and no `email`. `../api/src/todo_api/auth.py` is a working example of this check.

## Endpoints

|                                         |                                                                                                              |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `GET /.well-known/openid-configuration` | discovery                                                                                                    |
| `GET /jwks.json`                        | public keys, to verify tokens                                                                                |
| `GET`/`POST /authorize`                 | sign-in page (optional `audience`); the POST signs in and redirects back with a one-time code                |
| `POST /token`                           | `authorization_code` (PKCE required), `refresh_token` (rotating), `client_credentials` (optional `audience`) |
| `GET /userinfo`                         | the signed-in person's claims for the granted scopes                                                         |
| `POST /revoke`                          | revokes a refresh token and the rest of its family                                                           |

## Tests

```bash
docker compose up -d      # the DB-backed tests make and drop their own throwaway database on this server
uv run pytest
```

## Upkeep

`uv run local-idp purge` deletes codes and refresh tokens that expired over a day ago. Run it on a schedule (cron).
Schema changes are numbered files in `db/migrations/`, also written into `db/schema/` so a fresh and a migrated database match.

## Deliberately missing

Single sign-on (no IdP session, every sign-in asks for the password), consent screen, MFA, password reset, federation
(Google / SAML), logout endpoint, admin UI, access-token revocation (they expire in minutes), key storage in a KMS/HSM,
OpenID conformance. A hosted provider covers all of these.
