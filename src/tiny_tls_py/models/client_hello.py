from enum import Enum, IntEnum

from pydantic import BaseModel

from tiny_tls_py.models.extension import (
    Extension,
    ExtensionType,
    KeyShare,
    SupportedVersion,
)


class ProtocolVersion(IntEnum):
    TLS_1_2 = 0x0303


class ClientHello(BaseModel):
    protocol_version: ProtocolVersion = ProtocolVersion.TLS_1_2
    session_id: bytes
    random: bytes
    cipher_suites: bytes
    extensions: list[Extension]
    # _originalはTranscript-Hashの導出に使うらしい
    # クラス内でしか使わない気がするからアンダースコアをつけた
    _original_data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "ClientHello":
        if int.from_bytes(data[:2], "big") not in ProtocolVersion:
            raise ValueError(f"Unsupported protocol version: {data[:2]}")
        protocol_version = ProtocolVersion(int.from_bytes(data[:2]))

        random = data[2:34]
        session_id_length = data[34]
        session_id = data[35 : 35 + session_id_length]
        cipher_suites_length_start_index = 35 + session_id_length
        cipher_suites_length = int.from_bytes(
            data[
                cipher_suites_length_start_index : cipher_suites_length_start_index + 2
            ],
            "big",
        )
        cipher_suites_end_index = (
            cipher_suites_length_start_index + 2 + cipher_suites_length
        )
        cipher_suites = data[
            cipher_suites_length_start_index + 2 : cipher_suites_end_index
        ]
        # NOTE:
        extensions_length_start_index = cipher_suites_end_index + 2
        extensions_length = int.from_bytes(
            data[extensions_length_start_index : extensions_length_start_index + 2],
            "big",
        )
        extensions_start_index = extensions_length_start_index + 2
        extensions = data[
            extensions_start_index : extensions_start_index + extensions_length
        ]
        return cls(
            protocol_version=protocol_version,
            session_id=session_id,
            random=random,
            cipher_suites=cipher_suites,
            extensions=cls.parse_extensions(extensions),
            _original_data=data,
        )

    @classmethod
    def parse_extensions(cls, data: bytes) -> list[Extension]:
        extensions: list[Extension] = []
        offset = 0
        while offset < len(data):
            extension_type = ExtensionType(
                int.from_bytes(data[offset : offset + 2], "big")
            )
            length = int.from_bytes(data[offset + 2 : offset + 4], "big")
            extension_data = data[offset + 4 : offset + 4 + length]
            if extension_type == ExtensionType.SupportedVersions:
                extension = Extension(
                    extension_type=extension_type,
                    data=SupportedVersion.from_bytes(extension_data),
                )
            elif extension_type == ExtensionType.KeyShare:
                extension = Extension(
                    extension_type=extension_type,
                    data=KeyShare.from_bytes(extension_data),
                )
            else:
                extension = Extension(
                    extension_type=extension_type,
                    data=extension_data,
                )
            offset += 4 + length
            extensions.append(extension)
        return extensions
