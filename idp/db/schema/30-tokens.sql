-- Authorization codes: single-use tickets exchanged for tokens within seconds. Only the SHA-256 of the code is stored.
-- `family_id` ties the code to the refresh tokens it leads to, so reusing a code can revoke what it produced.
CREATE TABLE idp.authorization_code (
    code_hash       text        PRIMARY KEY,
    app_id          text        NOT NULL REFERENCES idp.app (app_id) ON DELETE CASCADE,
    account_id      uuid        NOT NULL REFERENCES idp.account (id) ON DELETE CASCADE,
    redirect_uri    text        NOT NULL,
    scope           text        NOT NULL,
    audience        text        NOT NULL,
    code_challenge  text        NOT NULL,
    nonce           text,
    auth_time       timestamptz NOT NULL,
    family_id       uuid        NOT NULL,
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX authorization_code_app_id_idx ON idp.authorization_code (app_id);
CREATE INDEX authorization_code_account_id_idx ON idp.authorization_code (account_id);
CREATE INDEX authorization_code_expires_at_idx ON idp.authorization_code (expires_at);

-- Refresh tokens, rotated on every use: the old one gets `used_at`, a new one is issued in the same family. Presenting a
-- used or revoked token again means it leaked, so the whole family is revoked. Only the SHA-256 of the token is stored.
CREATE TABLE idp.refresh_token (
    token_hash   text        PRIMARY KEY,
    family_id    uuid        NOT NULL,
    app_id       text        NOT NULL REFERENCES idp.app (app_id) ON DELETE CASCADE,
    account_id   uuid        NOT NULL REFERENCES idp.account (id) ON DELETE CASCADE,
    scope        text        NOT NULL,
    audience     text        NOT NULL,
    auth_time    timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_token_family_id_idx ON idp.refresh_token (family_id);
CREATE INDEX refresh_token_app_id_idx ON idp.refresh_token (app_id);
CREATE INDEX refresh_token_account_id_idx ON idp.refresh_token (account_id);
CREATE INDEX refresh_token_expires_at_idx ON idp.refresh_token (expires_at);
