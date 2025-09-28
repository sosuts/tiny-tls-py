from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_der_public_key


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
        """keyが公開鍵か秘密鍵か判断して、適切なtype(spki, pkcs8)とformatを指定してexportする。

        Args:
            key (X25519PrivateKey | X25519PublicKey): _description_

        Raises:
            TypeError: _description_

        Returns:
            bytes: _description_
        """
        if isinstance(key, X25519PrivateKey):
            der_bytes = key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        elif isinstance(key, X25519PublicKey):
            der_bytes = key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            raise TypeError("key must be X25519PrivateKey or X25519PublicKey")
        raw_key = der_bytes[-32:]
        return raw_key

    @classmethod
    def encode_X25519_publickey_to_DER(cls, publickey_bytes: bytes) -> X25519PublicKey:
        """X25519の公開鍵をDER形式にエンコードする。

        Args:
            publickey_bytes (bytes): X25519の公開鍵(32バイト)

        Returns:
            bytes: DER形式にエンコードされた公開鍵
        """
        if len(publickey_bytes) != 32:
            raise ValueError("公開鍵は32バイトである必要があります。")
        subject_publickey_info: Final[bytes] = (
            bytes.fromhex("302a")
            + bytes.fromhex("3005")
            + bytes.fromhex("0603")
            + bytes.fromhex("2b656e")
            + bytes.fromhex("032100")
            + publickey_bytes
        )
        public_key = load_der_public_key(subject_publickey_info)
        if not isinstance(public_key, X25519PublicKey):
            raise TypeError("Loaded key is not an X25519PublicKey")
        return public_key
