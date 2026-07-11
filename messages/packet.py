from abc import ABC
from dataclasses import dataclass
from typing import IO
import secrets

from stream_readers import require
from .primitives import StructuredBytes, NameList, MessageNumbers, Mpint
import algorithms as algos


@dataclass
class Payload(StructuredBytes, ABC):
    pass


@dataclass
class Packet[T: Payload](StructuredBytes):
    packet_length: int
    padding_length: int
    payload: T
    random_padding: bytes
    mac: bytes

    @classmethod
    def from_stream[U: Payload](
        cls, stream: IO[bytes], payload_type: type[U], mac_length: int
    ) -> "Packet[U]":
        packet_length = int.from_bytes(stream.read(4), "big")
        padding_length = int.from_bytes(stream.read(1), "big")
        payload = payload_type.from_stream(stream)
        random_padding = stream.read(padding_length)
        mac = stream.read(mac_length)
        return Packet(packet_length, padding_length, payload, random_padding, mac)

    def to_bytes(self, include_mac=True) -> bytes:
        return (
            self.packet_length.to_bytes(4, "big")
            + self.padding_length.to_bytes(1, "big")
            + self.payload.to_bytes()
            + self.random_padding
            + (self.mac if include_mac else bytes())
        )

    @classmethod
    def build[U: Payload](cls, payload: U) -> "Packet[U]":
        # TODO: store structuredbytes size instead of doing this
        payload_length = len(payload.to_bytes())
        padding_length = (8 - (4 + 1 + payload_length) % 8) % 8
        if padding_length < 4:
            padding_length += 8
        packet_length = 1 + payload_length + padding_length
        return Packet(
            packet_length,
            padding_length,
            payload,
            secrets.token_bytes(padding_length),
            bytes(),
        )


@dataclass
class KexDHInit(Payload):
    e: int

    @classmethod
    def from_stream(cls, stream: IO[bytes], *args, **kwargs) -> KexDHInit:
        # the client shouldn't need to read this from stream
        return NotImplemented

    def to_bytes(self) -> bytes:
        return bytes([30]) + Mpint.build(self.e).to_bytes()

    @classmethod
    def build(cls, e: int) -> KexDHInit:
        return KexDHInit(e)


@dataclass
class AlgoExchange(Payload):
    cookie: bytes
    kex_algorithms: NameList
    server_host_key_algorithms: NameList
    encryption_algorithms_client_to_server: NameList
    encryption_algorithms_server_to_client: NameList
    mac_algorithms_client_to_server: NameList
    mac_algorithms_server_to_client: NameList
    compression_algorithms_client_to_server: NameList
    compression_algorithms_server_to_client: NameList
    languages_client_to_server: NameList
    languages_server_to_client: NameList
    first_kex_packet_follows: bool

    @classmethod
    def from_stream(cls, stream: IO[bytes]) -> AlgoExchange:
        require(stream, MessageNumbers.SSH_MSG_KEXINIT)
        return AlgoExchange(
            stream.read(16),
            NameList.from_stream(stream),
            NameList.from_stream(stream),
            NameList.from_stream(stream),
            NameList.from_stream(stream),
            NameList.from_stream(stream),
            NameList.from_stream(stream),
            NameList.from_stream(stream),
            NameList.from_stream(stream),
            NameList.from_stream(stream),
            NameList.from_stream(stream),
            bool(int.from_bytes(stream.read(1), "big")),
        )

    def to_bytes(self) -> bytes:
        return (
            MessageNumbers.SSH_MSG_KEXINIT
            + self.cookie
            + self.kex_algorithms
            + self.server_host_key_algorithms
            + self.encryption_algorithms_client_to_server
            + self.encryption_algorithms_server_to_client
            + self.mac_algorithms_client_to_server
            + self.mac_algorithms_server_to_client
            + self.compression_algorithms_client_to_server
            + self.compression_algorithms_server_to_client
            + self.languages_client_to_server
            + self.languages_server_to_client
            + bytes([self.first_kex_packet_follows])
            + bytes([0, 0, 0, 0])  # reserved
        )

    @classmethod
    def build(cls) -> AlgoExchange:
        return AlgoExchange(
            secrets.token_bytes(16),
            NameList.build(list(algos.kex.registry["proto_name"].keys())),
            NameList.build(list(algos.server_host_key.registry["proto_name"].keys())),
            NameList.build(list(algos.encryption.registry["proto_name"].keys())),
            NameList.build(list(algos.encryption.registry["proto_name"].keys())),
            NameList.build(list(algos.mac.registry["proto_name"].keys())),
            NameList.build(list(algos.mac.registry["proto_name"].keys())),
            NameList.build(list(algos.compression.registry["proto_name"].keys())),
            NameList.build(list(algos.compression.registry["proto_name"].keys())),
            NameList.build(list(algos.language.registry["proto_name"].keys())),
            NameList.build(list(algos.language.registry["proto_name"].keys())),
            False,
        )
