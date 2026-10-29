-- Registered APIs: the resource servers that accept tokens. `audience` is the API's identifier and becomes the `aud` of the
-- access tokens issued for it, so an API accepts only tokens meant for it.
CREATE TABLE idp.api (
    audience    text        PRIMARY KEY,
    name        text        NOT NULL,
    enabled     boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Registered applications: the programs allowed to ask for tokens (the web app, the claim processor, ...).
-- `app_id` is the public identifier sent as `client_id` on the wire. A public app (a browser app) holds no secret and is
-- protected by PKCE; a confidential app (a backend) authenticates with a secret, stored only as a bcrypt hash.
CREATE TABLE idp.app (
    app_id          text        PRIMARY KEY,
    name            text        NOT NULL,
    app_type        text        NOT NULL CHECK (app_type IN ('public', 'confidential')),
    secret_hash     text,
    redirect_uris   text[]      NOT NULL DEFAULT '{}',
    grant_types     text[]      NOT NULL DEFAULT '{}',
    allowed_scopes  text[]      NOT NULL DEFAULT '{}',
    allowed_audiences text[]    NOT NULL DEFAULT '{}',  -- the APIs (idp.api.audience) this app may get tokens for
    enabled         boolean     NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT app_confidential_has_secret CHECK (app_type = 'public' OR secret_hash IS NOT NULL)
);
