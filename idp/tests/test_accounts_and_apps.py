from datetime import datetime, timedelta, timezone

import pytest

from local_idp import accounts, registry
from local_idp.config import Settings

SETTINGS = Settings(max_failed_logins=3, lock_minutes=30)


class TestCreateAccount:
    def test_the_email_is_stored_lower_cased(self, conn):
        accounts.create_account(conn, email="  Amy@Fund.ORG ", password="longenough")

        assert conn.execute("SELECT email FROM idp.account").fetchone()["email"] == "amy@fund.org"

    def test_the_password_is_not_stored_as_given(self, conn):
        accounts.create_account(conn, email="a@x.org", password="longenough")

        assert conn.execute("SELECT password_hash FROM idp.account").fetchone()["password_hash"] != "longenough"

    def test_a_second_account_for_the_same_email_is_refused(self, conn):
        accounts.create_account(conn, email="a@x.org", password="longenough")

        with pytest.raises(accounts.AccountExists):
            accounts.create_account(conn, email="A@X.org", password="another-long-one")

    def test_a_short_password_is_refused(self, conn):
        with pytest.raises(accounts.WeakPassword):
            accounts.create_account(conn, email="a@x.org", password="short")

    def test_the_database_itself_refuses_an_upper_case_email(self, conn):
        import psycopg

        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute("INSERT INTO idp.account (email, password_hash) VALUES ('A@X.org', 'h')")


class TestSignIn:
    @pytest.fixture
    def amy(self, conn):
        accounts.create_account(conn, email="amy@fund.org", password="right password", given_name="Amy", family_name="Lee")

    def attempts(self, conn):
        return conn.execute("SELECT failed_login_attempts AS n FROM idp.account").fetchone()["n"]

    def test_the_right_password_signs_in(self, conn, amy):
        account = accounts.sign_in(conn, SETTINGS, "Amy@Fund.org", "right password")

        assert account.email == "amy@fund.org" and account.name == "Amy Lee"

    def test_a_wrong_password_and_an_unknown_email_look_the_same(self, conn, amy):
        with pytest.raises(accounts.SignInFailed) as wrong:
            accounts.sign_in(conn, SETTINGS, "amy@fund.org", "nope")
        with pytest.raises(accounts.SignInFailed) as unknown:
            accounts.sign_in(conn, SETTINGS, "nobody@fund.org", "nope")

        assert str(wrong.value) == str(unknown.value) == "Invalid email or password"

    def test_failed_attempts_are_counted_and_a_success_clears_them(self, conn, amy):
        for _ in range(2):
            with pytest.raises(accounts.SignInFailed):
                accounts.sign_in(conn, SETTINGS, "amy@fund.org", "nope")
        assert self.attempts(conn) == 2

        accounts.sign_in(conn, SETTINGS, "amy@fund.org", "right password")

        assert self.attempts(conn) == 0

    def test_the_account_locks_at_the_limit_and_then_refuses_even_the_right_password(self, conn, amy):
        for _ in range(2):
            with pytest.raises(accounts.SignInFailed, match="Invalid"):
                accounts.sign_in(conn, SETTINGS, "amy@fund.org", "nope")
        with pytest.raises(accounts.SignInFailed, match="locked after 3"):
            accounts.sign_in(conn, SETTINGS, "amy@fund.org", "nope")

        with pytest.raises(accounts.SignInFailed, match="locked"):
            accounts.sign_in(conn, SETTINGS, "amy@fund.org", "right password")

    def test_a_lock_that_has_run_out_clears_itself(self, conn, amy):
        for _ in range(3):
            with pytest.raises(accounts.SignInFailed):
                accounts.sign_in(conn, SETTINGS, "amy@fund.org", "nope")
        later = datetime.now(timezone.utc) + timedelta(minutes=31)

        accounts.sign_in(conn, SETTINGS, "amy@fund.org", "right password", now=later)

        assert self.attempts(conn) == 0

    def test_after_a_lock_runs_out_counting_starts_again(self, conn, amy):
        for _ in range(3):
            with pytest.raises(accounts.SignInFailed):
                accounts.sign_in(conn, SETTINGS, "amy@fund.org", "nope")
        later = datetime.now(timezone.utc) + timedelta(minutes=31)

        with pytest.raises(accounts.SignInFailed, match="Invalid"):
            accounts.sign_in(conn, SETTINGS, "amy@fund.org", "nope", now=later)

        assert self.attempts(conn) == 1

    def test_a_disabled_account_cannot_sign_in(self, conn, amy):
        conn.execute("UPDATE idp.account SET enabled = false")

        with pytest.raises(accounts.SignInFailed, match="disabled"):
            accounts.sign_in(conn, SETTINGS, "amy@fund.org", "right password")

    def test_find_account_skips_a_disabled_one(self, conn, amy):
        account_id = conn.execute("SELECT id FROM idp.account").fetchone()["id"]
        assert accounts.find_account(conn, account_id) is not None

        conn.execute("UPDATE idp.account SET enabled = false")

        assert accounts.find_account(conn, account_id) is None


class TestRegisterApp:
    def public(self, conn, **over):
        values = dict(
            app_id="web-ui", name="Web", app_type="public", redirect_uris=["http://localhost:5173/auth/callback"],
            grant_types=["authorization_code"], allowed_scopes=["openid"],
        )
        values.update(over)
        registry.register_app(conn, **values)

    def test_a_registered_app_is_found_with_its_settings(self, conn):
        self.public(conn)

        app = registry.find_app(conn, "web-ui")

        assert app.name == "Web" and not app.is_confidential and app.allows_grant("authorization_code")
        assert app.allowed_scopes == ("openid",) and app.secret_hash is None

    def test_registering_again_updates_it(self, conn):
        self.public(conn)
        self.public(conn, name="Renamed", allowed_scopes=["openid", "email"])

        assert registry.find_app(conn, "web-ui").name == "Renamed"
        assert conn.execute("SELECT count(*) AS n FROM idp.app").fetchone()["n"] == 1

    def test_an_unknown_or_disabled_app_is_not_found(self, conn):
        self.public(conn)
        assert registry.find_app(conn, "nope") is None

        conn.execute("UPDATE idp.app SET enabled = false")

        assert registry.find_app(conn, "web-ui") is None

    def test_the_return_address_must_match_exactly(self, conn):
        self.public(conn)
        app = registry.find_app(conn, "web-ui")

        assert app.has_redirect_uri("http://localhost:5173/auth/callback")
        for other in ("http://localhost:5173/auth/callback/", "http://localhost:5173/auth/callback?x=1", "http://localhost:5173",
                      "http://localhost:5173/auth/callback/../x", "HTTP://localhost:5173/auth/callback", ""):
            assert not app.has_redirect_uri(other)

    def test_a_confidential_app_keeps_only_a_hash_of_its_secret(self, conn):
        self.public(conn, app_id="svc", app_type="confidential", secret="s3cret", redirect_uris=[], grant_types=["client_credentials"])

        app = registry.find_app(conn, "svc")

        assert app.is_confidential and app.secret_hash != "s3cret"
        assert app.secret_matches("s3cret") and not app.secret_matches("wrong") and not app.secret_matches("")

    def test_a_confidential_app_needs_a_secret(self, conn):
        with pytest.raises(ValueError, match="secret"):
            self.public(conn, app_type="confidential")

    def test_a_public_app_never_matches_a_secret(self, conn):
        self.public(conn)

        assert not registry.find_app(conn, "web-ui").secret_matches("anything")

    @pytest.mark.parametrize("over", [dict(app_type="hybrid"), dict(grant_types=["password"]), dict(allowed_scopes=["bad scope"])])
    def test_nonsense_is_refused(self, conn, over):
        with pytest.raises(ValueError):
            self.public(conn, **over)

    def test_custom_scope_names_are_fine(self, conn):
        self.public(conn, allowed_scopes=["claims:write", "reports.read"])

        assert registry.find_app(conn, "web-ui").allowed_scopes == ("claims:write", "reports.read")
