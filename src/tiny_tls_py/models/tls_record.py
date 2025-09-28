from enum import IntEnum
from typing import Self

from pydantic import BaseModel

from tiny_tls_py.models.handshake import Handshake


class ContentType(IntEnum):
    invalid = 0
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23


class ProtocolVersion(IntEnum):
    TLS_1_0 = 0x0301
    TLS_1_1 = 0x0302
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304


class TlsRecord(BaseModel):
    content_type: ContentType
    legacy_record_version: ProtocolVersion
    length: int
    fragment: bytes | Handshake

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        content_type = ContentType(int.from_bytes(data[:1], "big"))
        if content_type not in ContentType:
            raise ValueError(f"Invalid content type: {content_type}")
        version = ProtocolVersion(int.from_bytes(data[1:3], "big"))
        if version not in ProtocolVersion:
            raise ValueError(f"Invalid protocol version: {version}")
        length = int.from_bytes(data[3:5], "big")
        fragment = Handshake.from_bytes(data[5:])
        return cls(
            content_type=content_type,
            legacy_record_version=version,
            length=length,
            fragment=fragment,
        )

    def bytes(self) -> bytes:
        header_buffer = (
            self.content_type.to_bytes(1, "big")
            + self.legacy_record_version.to_bytes(2, "big")
            + self.length.to_bytes(2, "big")
        )
        if isinstance(self.fragment, bytes):
            return header_buffer + self.fragment
        return header_buffer + self.fragment.bytes()
