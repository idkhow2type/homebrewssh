from typing import cast, Self, IO
from dataclasses import dataclass
from abc import ABC, abstractmethod

@dataclass
class StructuredBytes(ABC):
    @classmethod
    @abstractmethod
    def from_stream(cls, stream: IO[bytes], *args, **kwargs) -> Self:
        pass

    @abstractmethod
    def to_bytes(self) -> bytes:
        pass

    def __add__(self, other: "StructuredBytes | bytes") -> bytes:
        return self.to_bytes() + (
            other.to_bytes() if isinstance(other, StructuredBytes) else other
        )

    def __radd__(self, other: "StructuredBytes | bytes") -> bytes:
        return (
            other.to_bytes()
            if isinstance(other, StructuredBytes)
            else cast(bytes, other)  # not very nice but we trust ourselves
        ) + self.to_bytes()


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

    def to_bytes(self) -> bytes:
        return (
            self.packet_length.to_bytes(4, "big")
            + self.padding_length.to_bytes(1, "big")
            + self.payload.to_bytes()
            + self.random_padding
            + self.mac
        )


@dataclass
class NameList(StructuredBytes):
    length: int
    names: list[bytes]

    @classmethod
    def from_stream(cls, stream: IO[bytes]) -> "NameList":
        length = int.from_bytes(stream.read(4), "big")
        names = stream.read(length).split(b",")
        return NameList(length, names)

    def to_bytes(self) -> bytes:
        return self.length.to_bytes(4, "big") + b",".join(self.names)


@dataclass
class AlgoExchange(Payload):
    SSH_MSG_KEXINIT: int
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
    def from_stream(cls, stream: IO[bytes]) -> "AlgoExchange":
        return AlgoExchange(
            int.from_bytes(stream.read(1), "big"),
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
            self.SSH_MSG_KEXINIT.to_bytes(1)
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
        )