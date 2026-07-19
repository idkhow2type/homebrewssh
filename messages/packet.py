from abc import ABC
from dataclasses import dataclass, fields
from typing import ClassVar, Callable
from io import BufferedIOBase
import secrets

from .primitives import *
import proto_algorithms
from proto_algorithms.collection import AlgoCollection


@dataclass
class Payload(StructuredBytes, ABC):
    CODE: ClassVar[bytes]


@dataclass
class Packet[T: Payload](StructuredBytes):
    packet_length: int
    padding_length: int
    payload: T
    random_padding: bytes
    mac: bytes

    @classmethod
    def from_stream(cls, stream: BufferedIOBase, mac_length: int) -> Packet:
        packet_length = int.from_bytes(stream.read(4), "big")
        padding_length = int.from_bytes(stream.read(1), "big")
        payload_type = PAYLOADS[stream.read(1)]
        payload = payload_type.from_stream(stream)
        random_padding = stream.read(padding_length)
        mac = stream.read(mac_length)
        return Packet(packet_length, padding_length, payload, random_padding, mac)

    def to_bytes(
        self,
        encryption: Callable[[bytes], bytes] | None = None,
    ) -> bytes:
        content = (
            self.packet_length.to_bytes(4, "big")
            + self.padding_length.to_bytes(1, "big")
            + self.payload.to_bytes()
            + self.random_padding
        )
        if encryption:
            content = encryption(content)
        return content + self.mac

    def compute_mac(self, mac: Callable[[bytes, bytes], bytes], key: bytes):
        content = (
            self.packet_length.to_bytes(4, "big")
            + self.padding_length.to_bytes(1, "big")
            + self.payload.to_bytes()
            + self.random_padding
        )
        return mac(content, key)

    @classmethod
    def build[U: Payload](
        cls,
        payload: U,
        mac: Callable[[bytes, bytes], bytes] | None = None,
        key: bytes | None = None,
    ) -> "Packet[U]":
        # TODO: store structuredbytes size instead of doing this
        payload_length = len(payload.to_bytes())
        padding_length = (8 - (4 + 1 + payload_length) % 8) % 8
        if padding_length < 4:
            padding_length += 8
        packet_length = 1 + payload_length + padding_length

        packet = Packet(
            packet_length,
            padding_length,
            payload,
            secrets.token_bytes(padding_length),
            b"",
        )
        if mac and key:
            packet.mac = packet.compute_mac(mac, key)
        return packet


@dataclass
class KexInit(Payload):
    CODE = bytes([20])
    cookie: bytes
    name_lists: dict[str, NameList]
    first_kex_packet_follows: bool
    reserved: int

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> KexInit:
        return KexInit(
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
    def build(cls) -> KexInit:
        return KexInit(
            secrets.token_bytes(16),
            {
                field.name: NameList.build(
                    getattr(proto_algorithms, field.name).registry["proto_name"].keys()
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
    def from_stream(cls, stream: BufferedIOBase, *args, **kwargs) -> KexDHInit:
        # the client shouldn't need to read this from stream
        return NotImplemented

    def to_bytes(self) -> bytes:
        return self.CODE + Mpint.build(self.e).to_bytes()

    @classmethod
    def build(cls, e: int) -> KexDHInit:
        return KexDHInit(e)


@dataclass
class KexDHReply(Payload):
    CODE = bytes([31])
    public_key: String
    f: Mpint
    exchange_signature: String

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> KexDHReply:
        return KexDHReply(
            String.from_stream(stream),
            Mpint.from_stream(stream),
            String.from_stream(stream),
        )

    def to_bytes(self) -> bytes:
        return self.CODE + self.public_key + self.f + self.exchange_signature

    @classmethod
    def build(cls, *args, **kwargs) -> Self:
        return NotImplemented


# this is stupid
@dataclass
class NewKeys(Payload):
    CODE = bytes([21])

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> NewKeys:
        return NewKeys()

    def to_bytes(self) -> bytes:
        return self.CODE

    @classmethod
    def build(cls) -> NewKeys:
        return NewKeys()


@dataclass
class Disconnect(Payload):
    CODE = bytes([1])
    reason_code: int
    description: String
    language_tag: String

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Disconnect:
        return Disconnect(
            int.from_bytes(stream.read(4)),
            String.from_stream(stream),
            String.from_stream(stream),
        )

    def to_bytes(self) -> bytes:
        return (
            self.CODE
            + self.reason_code.to_bytes(4)
            + self.description.to_bytes()
            + self.language_tag.to_bytes()
        )

    @classmethod
    def build(
        cls, reason_code: int, description: bytes, language_tag: bytes
    ) -> Disconnect:
        return Disconnect(
            reason_code, String.build(description), String.build(language_tag)
        )


@dataclass
class Ignore(Payload):
    CODE = bytes([2])
    data: String

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Ignore:
        return Ignore(String.from_stream(stream))

    def to_bytes(self) -> bytes:
        return self.CODE + self.data.to_bytes()

    @classmethod
    def build(cls, data: bytes) -> Ignore:
        return Ignore(String.build(data))


@dataclass
class Debug(Payload):
    CODE = bytes([4])
    always_display: bool
    message: String
    language_tag: String

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Debug:
        return Debug(
            bool(stream.read(1)), String.from_stream(stream), String.from_stream(stream)
        )

    def to_bytes(self) -> bytes:
        return (
            self.CODE
            + self.always_display.to_bytes()
            + self.message
            + self.language_tag
        )

    @classmethod
    def build(cls, always_display: bool, message: bytes, language_tag: bytes) -> Debug:
        return Debug(always_display, String.build(message), String.build(language_tag))


@dataclass
class Unimplemented(Payload):
    CODE = bytes([3])
    sequence_number: int

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Unimplemented:
        return Unimplemented(int.from_bytes(stream.read(4)))

    def to_bytes(self) -> bytes:
        return self.CODE + self.sequence_number.to_bytes(4)

    @classmethod
    def build(cls, sequence_number: int) -> Unimplemented:
        return Unimplemented(sequence_number)


PAYLOADS = {}
for cls in Payload.__subclasses__():
    PAYLOADS[cls.CODE] = cls
