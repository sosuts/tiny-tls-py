from enum import IntEnum
from typing import Self, Union

from pydantic import BaseModel


class ExtensionType(IntEnum):
    ServerName = 0x0000
    PreSharedKey = 0x0029
    SupportedVersions = 0x002B
    KeyShare = 0x0033

    @classmethod
    def _missing_(cls, value):
        # 未定義値でもそのままインスタンス化
        # TypeScript の数値 enum のように「ただの数値」として保持
        obj = int.__new__(cls, value)
        obj._name_ = None  # 名前は存在しない
        obj._value_ = value
        return obj


class Extension(BaseModel):
    extension_type: ExtensionType
    data: Union[bytes, "SupportedVersion", "KeyShare"]

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        extension_type = ExtensionType(int.from_bytes(data[:2], "big"))
        length = int.from_bytes(data[2:4], "big")
        raw_extension_data = data[4 : 4 + length]
        match extension_type:
            case ExtensionType.SupportedVersions:
                return cls(
                    extension_type=extension_type,
                    data=SupportedVersion.from_bytes(raw_extension_data),
                )
            case ExtensionType.KeyShare:
                return cls(
                    extension_type=extension_type,
                    data=KeyShare.from_bytes(raw_extension_data),
                )
            case _:
                raise ValueError(f"Invalid extension type: {extension_type.name}")


class SupportedVersion(BaseModel):
    version: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        return cls(version=data)


class KeyShare(BaseModel):
    length: int
    entries: list["KeyShareEntry"]

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        length = int.from_bytes(data[0:2], "big")
        entries: list[KeyShareEntry] = []
        offset: int = 2

        # 最初の2バイトが長さ
        # length以外はデータ
        while offset < len(data[offset:]):
            # 本来は2バイトでx25519, secp256r1などのグループを識別するが、
            # tiny-tls-pyではed25519のみをサポート
            group = data[offset : offset + 2]
            entry_length = int.from_bytes(data[offset + 2 : offset + 4], "big")
            entry = KeyShareEntry.from_bytes(data[offset : offset + 4 + entry_length])
            entries.append(entry)
            offset += 4 + entry_length
        return cls(length=length, entries=entries)


class KeyShareEntry(BaseModel):
    group: bytes
    length: int
    key_exchange: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        # 最初の2バイトがグループ
        group = data[:2]
        # 次の2バイトが長さ
        # const length = data.readUInt16BE(2);
        length = int.from_bytes(data[2:4], "big")
        # 次のlengthバイトがkeyExchange
        key_exchange = data[4 : 4 + length]
        return cls(group=group, length=length, key_exchange=key_exchange)
