"""Signing keys. The private half signs tokens; the public half is published at /jwks.json so the API can verify them with
no shared secret. Keys are files in a folder (`<kid>.pem`, private, mode 0600), made by `local-idp generate-key` -- never
inside a request. The newest signs; every key present is published, so an old key can stay a while after a new one starts
signing and tokens it signed still verify (key rotation)."""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_ALGORITHM = "RS256"


class NoSigningKey(RuntimeError):
    pass


def _kid_of(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()[:16]


@dataclass(frozen=True)
class SigningKey:
    kid: str
    private_key: rsa.RSAPrivateKey

    def public_jwk(self) -> dict[str, Any]:
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key(), as_dict=True)
        return {**jwk, "kid": self.kid, "alg": _ALGORITHM, "use": "sig"}


class KeyRing:
    def __init__(self, keys: list[SigningKey]) -> None:
        if not keys:
            raise NoSigningKey("no signing key: run `local-idp generate-key` first")
        self._keys = keys  # newest last

    @property
    def active(self) -> SigningKey:
        return self._keys[-1]

    def jwks(self) -> dict[str, Any]:
        return {"keys": [key.public_jwk() for key in self._keys]}

    def public_key_for(self, kid: str):
        for key in self._keys:
            if key.kid == kid:
                return key.private_key.public_key()
        return None

    def sign(self, claims: dict[str, Any], *, token_type: str = "JWT") -> str:
        return jwt.encode(
            claims, self.active.private_key, algorithm=_ALGORITHM, headers={"kid": self.active.kid, "typ": token_type}
        )


def new_signing_key() -> SigningKey:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return SigningKey(kid=_kid_of(private_key.public_key()), private_key=private_key)


def generate_key(directory: Path) -> Path:
    """Writes a new private key into `directory` and returns its path."""
    key = new_signing_key()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{key.kid}.pem"
    pem = key.private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    path.touch(mode=0o600)
    path.write_bytes(pem)
    return path


def load_keyring(directory: Path) -> KeyRing:
    files = sorted(directory.glob("*.pem"), key=lambda p: p.stat().st_mtime) if directory.is_dir() else []
    keys = []
    for path in files:
        private_key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        keys.append(SigningKey(kid=_kid_of(private_key.public_key()), private_key=private_key))
    return KeyRing(keys)
