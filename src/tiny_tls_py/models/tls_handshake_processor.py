import socket
from typing import Final

from tiny_tls_py.models.client_hello import ClientHello
from tiny_tls_py.models.extension import Extension, ExtensionType, KeyShare
from tiny_tls_py.models.handshake import Handshake, HandshakeType
from tiny_tls_py.models.key_service import KeyService
from tiny_tls_py.models.server_hello import ServerHello
from tiny_tls_py.models.tls_record import ContentType, ProtocolVersion, TlsRecord


class TlsHandshakeProcessor:
    @classmethod
    def process(self, tls_record: TlsRecord, socket: socket.socket):
        print("ハンドシェイク処理を開始")
        # HandShakeかつClientHelloではならValueError
        if not (
            isinstance(tls_record.fragment, Handshake)
            and isinstance(tls_record.fragment.body, ClientHello)
        ):
            raise ValueError("tls_record.fragment must be ClientHello")
        client_hello: Final[ClientHello] = tls_record.fragment.body
        client_key_shares: Final[list[Extension]] = list(
            filter(
                lambda x: x.extension_type == ExtensionType.KeyShare,
                client_hello.extensions,
            )
        )
        if not client_key_shares:
            return
        client_key_share = client_key_shares[0]
        raw_client_pubkey = None
        if isinstance(client_key_share.data, KeyShare):
            raw_client_pubkey = client_key_share.data.x2559Key()
            print(f"x25519 key: {raw_client_pubkey.hex()}")
        else:
            print("client_key_share.data is not a KeyShare instance")
        key_pair = KeyService.generate_X25519_KeyPair()
        server_hello = ServerHello.from_bytes(
            client_sessionid=client_hello.session_id, key_pair=key_pair
        )
        server_hello_buffer = server_hello.bytes()
        server_hello_handshake = Handshake(
            msg_type=HandshakeType.ServerHello,
            length=len(server_hello_buffer),
            body=server_hello_buffer,
        )
        server_hello_tls_record = TlsRecord(
            content_type=ContentType.handshake,
            legacy_record_version=ProtocolVersion.TLS_1_2,
            length=len(server_hello_handshake.bytes()),
            fragment=server_hello_handshake,
        )
        print("ServerHelloを送信")
        socket.sendall(server_hello_tls_record.bytes())
        print("ハンドシェイク処理を終了")
