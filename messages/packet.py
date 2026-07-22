from abc import ABC
from dataclasses import dataclass
from typing import ClassVar
from io import BufferedIOBase, BytesIO, SEEK_END
import secrets

from .primitives import *
from proto_algorithms.encryption_ctos import Algorithm as Encryption
from proto_algorithms.encryption_stoc import Algorithm as Decryption
from proto_algorithms.mac_ctos import Algorithm as MacCtos
from proto_algorithms.mac_stoc import Algorithm as MacStoc

PAYLOADS: dict[bytes, type[Payload]] = {}


@dataclass
class Payload(StructuredBytes, ABC):
    CODE: ClassVar[bytes]

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        PAYLOADS[cls.CODE] = cls


@dataclass
class Packet[T: Payload](StructuredBytes):
    packet_length: int
    padding_length: int
    payload: T
    random_padding: bytes
    mac: bytes

    @classmethod
    def from_stream(
        cls,
        stream: BufferedIOBase,
        decryption: Decryption | None,
        mac: MacStoc | None,
        seq_num: int | None,
    ) -> Self:
        if decryption is None or decryption._cipher is None:
            packet_length = int.from_bytes(stream.read(4), "big")
            raw_stream = stream
        else:
            chunk = stream.read(decryption.block_size)
            raw_stream = BytesIO(decryption.decrypt(chunk))

            packet_length = int.from_bytes(raw_stream.read(4), "big")

            leftover = stream.read(4 + packet_length - decryption.block_size)
            read_pos = raw_stream.tell()
            raw_stream.seek(0, SEEK_END)
            if leftover:
                raw_stream.write(decryption.decrypt(leftover))
            raw_stream.write(stream.read(mac.key_len if mac and mac.key else 0))
            raw_stream.seek(read_pos)

        padding_length = int.from_bytes(raw_stream.read(1), "big")
        payload_type = cast(type[T], PAYLOADS[raw_stream.read(1)])
        payload = payload_type.from_stream(raw_stream)
        random_padding = raw_stream.read(padding_length)
        pack_mac = raw_stream.read(mac.key_len if mac and mac.key else 0)

        packet = cls(packet_length, padding_length, payload, random_padding, b"")
        if mac and mac.key and seq_num is not None:
            actual_mac = packet.compute_mac(mac, seq_num)
            assert pack_mac == actual_mac
        return packet

    def to_bytes(self, encryption: Encryption | None) -> bytes:
        content = (
            self.packet_length.to_bytes(4, "big")
            + self.padding_length.to_bytes(1, "big")
            + self.payload.to_bytes()
            + self.random_padding
        )
        if encryption and encryption._cipher:
            content = encryption.encrypt(content)
        return content + self.mac

    def compute_mac(self, mac: MacCtos | MacStoc, seq_num: int):
        content = (
            seq_num.to_bytes(4)
            + self.packet_length.to_bytes(4, "big")
            + self.padding_length.to_bytes(1, "big")
            + self.payload.to_bytes()
            + self.random_padding
        )
        return mac.compute(content)

    @classmethod
    def build[U: Payload](
        cls,
        payload: U,
        block_size: int | None,
        mac: MacCtos | None,
        seq_num: int | None,
    ) -> "Packet[U]":
        # TODO: store structuredbytes size instead of doing this
        payload_length = len(payload.to_bytes())
        if block_size is None:
            block_size = 8
        block_size = max(8, block_size)
        padding_length = (-(4 + 1 + payload_length)) % block_size
        if padding_length < 4:
            padding_length += block_size
        packet_length = 1 + payload_length + padding_length

        packet = Packet(
            packet_length,
            padding_length,
            payload,
            secrets.token_bytes(padding_length),
            b"",
        )
        if mac is not None and mac.key and seq_num is not None:
            packet.mac = packet.compute_mac(mac, seq_num)
        return packet
