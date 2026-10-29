-- People who can sign in. The email is the natural key and is what an API can match to its own user.
CREATE TABLE idp.account (
    id                     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email                  text        NOT NULL,
    password_hash          text        NOT NULL,
    given_name             text,
    family_name            text,
    enabled                boolean     NOT NULL DEFAULT true,
    failed_login_attempts  integer     NOT NULL DEFAULT 0,
    locked_until           timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT account_email_lower CHECK (email = lower(email))
);
-- One account per email; this is also the index every sign-in looks the account up by.
CREATE UNIQUE INDEX account_email_key ON idp.account (email);
