from enum import IntEnum
from typing import Self

from pydantic import BaseModel

from tiny_tls_py.models.client_hello import ClientHello


class HandshakeType(IntEnum):
    ClientHello = 1
    ServerHello = 2
    NewSessionTicket = 4
    EndOfEarlyData = 5
    EncryptedExtensions = 8
    Certificate = 11
    CertificateRequest = 13
    CertificateVerify = 15
    Finished = 20
    KeyUpdate = 24
    MessageHash = 254


class Handshake(BaseModel):
    msg_type: HandshakeType
    length: int
    body: bytes | ClientHello

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        # msgType(1バイト): ハンドシェイクメッセージの種類(ClientHello, ServerHelloとか)
        msg_type = HandshakeType(int.from_bytes(data[0:1], "big"))
        if msg_type not in HandshakeType:
            raise ValueError(f"Invalid handshake type: {msg_type}")
        # length(3バイト): ハンドシェイクメッセージの長さ
        length = int.from_bytes(data[1:4], "big")
        # 4バイト目以降がボディ
        body = data[4:]
        parsed_body: bytes | ClientHello = body
        if msg_type == HandshakeType.ClientHello:
            parsed_body = ClientHello.from_bytes(body)
        return cls(msg_type=msg_type, length=length, body=parsed_body)
