from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class KeyPair:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey


class KeyService:
    @classmethod
    def generate_X25519_KeyPair(cls) -> KeyPair:
        # generate keypair
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return KeyPair(private_key=private_key, public_key=public_key)

    @classmethod
    def generate_common_secret(
        cls, private_key: X25519PrivateKey, public_key: X25519PublicKey
    ) -> bytes:
        # 共通鍵（shared secret）を生成
        shared_key = private_key.exchange(public_key)
        return shared_key

    @classmethod
    def extract_rawkey_from_DerFormat(
        cls, key: X25519PrivateKey | X25519PublicKey
    ) -> bytes:
        if isinstance(key, X25519PrivateKey):
            return key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        elif isinstance(key, X25519PublicKey):
            return key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            raise TypeError("key must be X25519PrivateKey or X25519PublicKey")
