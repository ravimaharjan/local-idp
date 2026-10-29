"""Setup and upkeep commands: `local-idp generate-key | create-user | register-api | register-app | purge`.

These run outside any request, so this is where keys are made and people and apps are added."""
from __future__ import annotations

import argparse
import getpass
import secrets
import sys
from typing import Optional

import psycopg
from psycopg.rows import dict_row

from local_idp import accounts, registry, tokens
from local_idp.config import Settings
from local_idp.keys import generate_key


def _connect(settings: Settings):
    return psycopg.connect(settings.db_dsn, row_factory=dict_row)


def _generate_key(args: argparse.Namespace, settings: Settings) -> int:
    path = generate_key(settings.keys_dir)
    print(f"wrote {path} (keep the folder private; the newest key signs, all are published)")
    return 0


def _register_api(args: argparse.Namespace, settings: Settings) -> int:
    with _connect(settings) as conn:
        try:
            registry.register_api(conn, audience=args.audience, name=args.name or args.audience)
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
    print(f"registered API {args.audience}; tokens for it carry aud={args.audience}")
    return 0


def _create_user(args: argparse.Namespace, settings: Settings) -> int:
    password = args.password or getpass.getpass("Password: ")
    with _connect(settings) as conn:
        try:
            accounts.create_account(conn, email=args.email, password=password, given_name=args.given_name, family_name=args.family_name)
        except (accounts.AccountExists, accounts.WeakPassword) as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
    print(f"created {args.email.strip().lower()}")
    return 0


def _register_app(args: argparse.Namespace, settings: Settings) -> int:
    grant_types = args.grant_type or (
        ["authorization_code", "refresh_token"] if args.type == "public" else ["client_credentials"]
    )
    secret: Optional[str] = None
    if args.type == "confidential":
        secret = args.secret or secrets.token_urlsafe(32)
    with _connect(settings) as conn:
        try:
            registry.register_app(
                conn, app_id=args.app_id, name=args.name or args.app_id, app_type=args.type, secret=secret,
                redirect_uris=args.redirect_uri or [], grant_types=grant_types, allowed_scopes=args.scope or [],
                allowed_audiences=args.audience or [],
            )
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
    print(f"registered {args.app_id} ({args.type}); grants: {', '.join(grant_types)}; scopes: {', '.join(args.scope or [])}; "
          f"APIs: {', '.join(args.audience or [])}")
    if secret and not args.secret:
        print(f"secret (shown once, not recoverable): {secret}")
    return 0


def _purge(args: argparse.Namespace, settings: Settings) -> int:
    with _connect(settings) as conn:
        removed = tokens.purge_expired(conn)
    print(f"removed {removed['authorization_codes']} authorization codes and {removed['refresh_tokens']} refresh tokens")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="local-idp")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("generate-key", help="make a new signing key (the newest key signs)").set_defaults(run=_generate_key)

    user = commands.add_parser("create-user", help="add a person who can sign in")
    user.add_argument("--email", required=True, help="the person's identity; it becomes the email claim in their tokens")
    user.add_argument("--given-name")
    user.add_argument("--family-name")
    user.add_argument("--password", help="omit to be asked (keeps it out of shell history)")
    user.set_defaults(run=_create_user)

    api = commands.add_parser("register-api", help="register (or rename) an API that accepts tokens")
    api.add_argument("--audience", required=True, help="the API's identifier: the aud of tokens issued for it")
    api.add_argument("--name", help="a readable name")
    api.set_defaults(run=_register_api)

    app = commands.add_parser("register-app", help="register (or update) an application")
    app.add_argument("--app-id", required=True, help="the public identifier sent as client_id")
    app.add_argument("--name", help="shown on the sign-in page")
    app.add_argument("--type", choices=["public", "confidential"], default="public")
    app.add_argument("--secret", help="confidential apps only; one is generated and printed once if omitted")
    app.add_argument("--redirect-uri", action="append", help="exact address the app may be sent back to; repeatable")
    app.add_argument("--grant-type", action="append", help="repeatable; default depends on --type")
    app.add_argument("--scope", action="append", help="a scope the app may ask for; repeatable")
    app.add_argument("--audience", action="append", help="an API (see register-api) the app may get tokens for; repeatable")
    app.set_defaults(run=_register_app)

    commands.add_parser("purge", help="delete long-expired codes and refresh tokens (run it on a schedule)").set_defaults(run=_purge)

    args = parser.parse_args(argv)
    return args.run(args, Settings.from_env())


if __name__ == "__main__":
    raise SystemExit(main())
