import stat

import jwt
import pytest

from local_idp import keys


def test_a_generated_key_is_a_private_file_and_loads_back(tmp_path):
    path = keys.generate_key(tmp_path / "keys")

    assert path.suffix == ".pem" and stat.S_IMODE(path.stat().st_mode) == 0o600
    ring = keys.load_keyring(tmp_path / "keys")
    assert ring.active.kid == path.stem


def test_without_a_key_it_refuses_to_start(tmp_path):
    with pytest.raises(keys.NoSigningKey, match="generate-key"):
        keys.load_keyring(tmp_path / "missing")


def test_the_published_keys_hold_no_private_part():
    ring = keys.KeyRing([keys.new_signing_key()])

    jwk = ring.jwks()["keys"][0]

    assert jwk["kty"] == "RSA" and jwk["alg"] == "RS256" and jwk["use"] == "sig" and jwk["kid"] == ring.active.kid
    assert not {"d", "p", "q", "dp", "dq", "qi"} & jwk.keys()


def test_a_signed_token_verifies_with_the_published_key_and_names_it():
    ring = keys.KeyRing([keys.new_signing_key()])

    token = ring.sign({"sub": "u"}, token_type="at+jwt")

    header = jwt.get_unverified_header(token)
    assert header["kid"] == ring.active.kid and header["typ"] == "at+jwt" and header["alg"] == "RS256"
    assert jwt.decode(token, ring.public_key_for(header["kid"]), algorithms=["RS256"]) == {"sub": "u"}


def test_after_a_rotation_the_newest_signs_and_the_old_one_is_still_published(tmp_path):
    old = keys.generate_key(tmp_path)
    new = keys.generate_key(tmp_path)
    import os
    os.utime(old, (1, 1))  # make the order unambiguous

    ring = keys.load_keyring(tmp_path)

    assert ring.active.kid == new.stem
    assert {k["kid"] for k in ring.jwks()["keys"]} == {old.stem, new.stem}
    assert ring.public_key_for(old.stem) is not None and ring.public_key_for("unknown") is None
