from typing import cast, Self
from io import BufferedIOBase
from dataclasses import dataclass
from abc import ABC, abstractmethod
from enum import Enum


# TODO: default impl for abstract methods?
@dataclass
class StructuredBytes(ABC):
    @classmethod
    @abstractmethod
    def from_stream(cls, stream: BufferedIOBase, *args, **kwargs) -> Self:
        pass

    @abstractmethod
    def to_bytes(self, *args, **kwargs) -> bytes:
        pass

    @classmethod
    @abstractmethod
    def build(cls, *args, **kwargs) -> Self:
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

    def __bytes__(self):
        return self.to_bytes()


@dataclass
class String(StructuredBytes):
    length: int
    data: bytes

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> String:
        length = int.from_bytes(stream.read(4))
        return String(length, stream.read(length))

    def to_bytes(self) -> bytes:
        return self.length.to_bytes(4) + self.data

    @classmethod
    def build(cls, data: bytes) -> String:
        return String(len(data), data)


@dataclass
class Mpint(StructuredBytes):
    num: int

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> "Mpint":
        string = String.from_stream(stream)
        return Mpint(int.from_bytes(string.data))

    def to_bytes(self) -> bytes:
        data = (b"\x00" if self.num >= 0 else b"") + self.num.to_bytes(
            (self.num.bit_length() + 7) // 8
        )
        return String(len(data), data).to_bytes()

    @classmethod
    def build(cls, num: int) -> "Mpint":
        return Mpint(num)


@dataclass
class NameList(StructuredBytes):
    length: int
    names: list[bytes]

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> "NameList":
        length = int.from_bytes(stream.read(4), "big")
        names = stream.read(length).split(b",")
        return NameList(length, names)

    def to_bytes(self) -> bytes:
        return self.length.to_bytes(4, "big") + b",".join(self.names)

    @classmethod
    def build(cls, names: list[bytes]) -> "NameList":
        data = b",".join(names)
        return NameList(len(data), names)
