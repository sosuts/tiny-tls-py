import pprint
import socket
from typing import Final

from tiny_tls_py.models.client_hello import ClientHello
from tiny_tls_py.models.extension import Extension, ExtensionType, KeyShare
from tiny_tls_py.models.handshake import Handshake
from tiny_tls_py.models.tls_record import TlsRecord


class TlsHandshakeProcessor:
    @classmethod
    def process(self, tls_record: TlsRecord, socket: socket.socket):
        print("ハンドシェイク処理を開始")
        # HandShakeかつClientHelloではならValueError
        if not (isinstance(tls_record.fragment, Handshake)) and not (
            isinstance(tls_record.fragment.body, ClientHello)
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
