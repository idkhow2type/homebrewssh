from dataclasses import dataclass, fields
from io import BufferedIOBase
import secrets

from .primitives import *
from .packet import Payload
import proto_algorithms
from proto_algorithms.collection import AlgoCollection

@dataclass
class KexInit(Payload):
    CODE = bytes([20])
    cookie: bytes
    name_lists: dict[str, NameList]
    first_kex_packet_follows: bool
    reserved: int

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Self:
        return cls(
            stream.read(16),
            {
                field.name: NameList.from_stream(stream)
                for field in fields(proto_algorithms.collection.AlgoCollection)
            },
            bool(int.from_bytes(stream.read(1), "big")),
            int.from_bytes(stream.read(4)),
        )

    def to_bytes(self) -> bytes:
        return (
            self.CODE
            + self.cookie
            + b"".join(nl.to_bytes() for nl in self.name_lists.values())
            + self.first_kex_packet_follows.to_bytes()
            + self.reserved.to_bytes(4)
        )

    @classmethod
    def build(cls) -> Self:
        return cls(
            secrets.token_bytes(16),
            {
                field.name: NameList.build(
                    list(getattr(proto_algorithms, field.name).registry["proto_name"].keys())
                )
                for field in fields(AlgoCollection)
            },
            False,
            0,
        )


@dataclass
class KexDHInit(Payload):
    CODE = bytes([30])
    e: int

    @classmethod
    def from_stream(cls, stream: BufferedIOBase, *args, **kwargs) -> Self:
        # the client shouldn't need to read this from stream
        raise NotImplementedError

    def to_bytes(self) -> bytes:
        return self.CODE + Mpint.build(self.e).to_bytes()

    @classmethod
    def build(cls, e: int) -> Self:
        return cls(e)


@dataclass
class KexDHReply(Payload):
    CODE = bytes([31])
    public_key: String
    f: Mpint
    exchange_signature: String

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Self:
        return cls(
            String.from_stream(stream),
            Mpint.from_stream(stream),
            String.from_stream(stream),
        )

    def to_bytes(self) -> bytes:
        return self.CODE + self.public_key + self.f + self.exchange_signature

    @classmethod
    def build(cls, *args, **kwargs) -> Self:
        raise NotImplementedError


# this is stupid
@dataclass
class NewKeys(Payload):
    CODE = bytes([21])

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Self:
        return cls()

    def to_bytes(self) -> bytes:
        return self.CODE

    @classmethod
    def build(cls) -> Self:
        return cls()