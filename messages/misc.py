from dataclasses import dataclass
from io import BufferedIOBase

from .primitives import *
from .packet import Payload


@dataclass
class Disconnect(Payload):
    CODE = bytes([1])
    reason_code: int
    description: String
    language_tag: String

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Self:
        return cls(
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
    def build(cls, reason_code: int, description: bytes, language_tag: bytes) -> Self:
        return cls(reason_code, String.build(description), String.build(language_tag))


@dataclass
class Ignore(Payload):
    CODE = bytes([2])
    data: String

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Self:
        return cls(String.from_stream(stream))

    def to_bytes(self) -> bytes:
        return self.CODE + self.data.to_bytes()

    @classmethod
    def build(cls, data: bytes) -> Self:
        return cls(String.build(data))


@dataclass
class Debug(Payload):
    CODE = bytes([4])
    always_display: bool
    message: String
    language_tag: String

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Self:
        return cls(
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
    def build(cls, always_display: bool, message: bytes, language_tag: bytes) -> Self:
        return cls(always_display, String.build(message), String.build(language_tag))


@dataclass
class Unimplemented(Payload):
    CODE = bytes([3])
    sequence_number: int

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Self:
        return cls(int.from_bytes(stream.read(4)))

    def to_bytes(self) -> bytes:
        return self.CODE + self.sequence_number.to_bytes(4)

    @classmethod
    def build(cls, sequence_number: int) -> Self:
        return cls(sequence_number)


@dataclass
class ServiceRequest(Payload):
    CODE = bytes([5])
    service_name: String

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Self:
        return cls(String.from_stream(stream))

    def to_bytes(self) -> bytes:
        return self.CODE + self.service_name

    @classmethod
    def build(cls, service_name: bytes) -> Self:
        return cls(String.build(service_name))
    
@dataclass
class ServiceAccept(Payload):
    CODE = bytes([6])
    service_name: String

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Self:
        return cls(String.from_stream(stream))

    def to_bytes(self) -> bytes:
        return self.CODE + self.service_name

    @classmethod
    def build(cls, service_name: bytes) -> Self:
        return cls(String.build(service_name))
