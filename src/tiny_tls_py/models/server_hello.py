from dataclasses import dataclass
from enum import Enum

from tiny_tls_py.models.extension import (
    Extension,
    ExtensionType,
    KeyShare,
    KeyShareEntry,
    SupportedVersion,
)
from tiny_tls_py.models.key_service import KeyPair, KeyService


class ProtocolVersion(Enum):
    TLS_1_2: bytes = b"\x03\x03"


@dataclass
class ServerHello:
    protocol_version: ProtocolVersion
    random: bytes
    session_id: bytes
    cipher_suite: int
    compression_method: bytes
    extension_length: bytes
    extensions: bytes

    @classmethod
    def from_bytes(cls, client_sessionid: bytes, key_pair: KeyPair) -> "ServerHello":
        import os
        from datetime import datetime
        from math import floor

        protocol_version = ProtocolVersion.TLS_1_2
        gmt_timestamp_seconds = floor(datetime.now().timestamp() / 1000)
        buffer = gmt_timestamp_seconds.to_bytes(4, "big")
        random = buffer + os.urandom(28)
        cipher_suite = 0x1302  # TLS_AES_256_GCM_SHA384
        compression_method = bytes([0x00])  # null
        supported_version = Extension(
            extension_type=ExtensionType.SupportedVersions,
            data=SupportedVersion(version=bytes([0x03, 0x04])),
        )
        raw_key = KeyService.extract_rawkey_from_DerFormat(key_pair.public_key)
        key_share_entry = KeyShareEntry(
            group=b"\x00\x1d",  # x25519
            length=32,
            key_exchange=raw_key,
        )
        key_share = Extension(
            extension_type=ExtensionType.KeyShare,
            data=KeyShare(length=34, entries=[key_share_entry]),
        )
        extensions = supported_version.bytes() + key_share.bytes()
        extension_length = len(extensions).to_bytes(2, "big")
        return ServerHello(
            protocol_version=protocol_version,
            random=random,
            session_id=client_sessionid,
            cipher_suite=cipher_suite,
            compression_method=compression_method,
            extension_length=extension_length,
            extensions=extensions,
        )

    def bytes(self) -> bytes:
        protocol_version_buffer = self.protocol_version.value
        session_id_length_buffer = 0x20
        cipher_suite_buffer = self.cipher_suite.to_bytes(2, "big")
        return (
            protocol_version_buffer
            + self.random
            + bytes.fromhex("20")
            + self.session_id
            + cipher_suite_buffer
            + self.compression_method
            + self.extension_length
            + self.extensions
        )
