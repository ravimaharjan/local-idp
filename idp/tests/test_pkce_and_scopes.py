import pytest

from local_idp import tokens
from local_idp.registry import App

RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def app(scopes=("openid", "profile")) -> App:
    return App("web-ui", "Web", "public", None, (), ("authorization_code",), tuple(scopes))


class TestPkce:
    def test_the_challenge_matches_the_example_in_the_standard(self):
        assert tokens.challenge_for(RFC_VERIFIER) == RFC_CHALLENGE

    def test_the_matching_verifier_passes(self):
        assert tokens.pkce_matches(RFC_VERIFIER, RFC_CHALLENGE)

    def test_another_verifier_fails(self):
        assert not tokens.pkce_matches("x" * 43, RFC_CHALLENGE)

    def test_the_challenge_itself_is_not_a_verifier(self):
        assert not tokens.pkce_matches(RFC_CHALLENGE, RFC_CHALLENGE)

    @pytest.mark.parametrize("verifier", ["", "short", "a" * 129, "has space " + "a" * 40, "ünïcode" + "a" * 40])
    def test_a_verifier_of_the_wrong_shape_fails(self, verifier):
        assert not tokens.pkce_matches(verifier, tokens.challenge_for("a" * 43))

    def test_a_challenge_must_be_43_url_safe_characters(self):
        assert tokens.is_valid_challenge(RFC_CHALLENGE)
        assert not tokens.is_valid_challenge("short")
        assert not tokens.is_valid_challenge(RFC_CHALLENGE + "=")
        assert not tokens.is_valid_challenge("+" * 43)


class TestScopes:
    def test_the_scopes_asked_for(self):
        assert tokens.resolve_scopes(app(), "openid profile") == ["openid", "profile"]

    def test_none_asked_gives_all_the_app_may_have(self):
        assert tokens.resolve_scopes(app(), None) == ["openid", "profile"]
        assert tokens.resolve_scopes(app(), "  ") == ["openid", "profile"]

    def test_duplicates_are_dropped(self):
        assert tokens.resolve_scopes(app(), "openid openid") == ["openid"]

    def test_a_scope_the_app_may_not_have_is_refused(self):
        with pytest.raises(tokens.OAuthError) as caught:
            tokens.resolve_scopes(app(), "openid email")

        assert caught.value.error == "invalid_scope" and "email" in caught.value.description
