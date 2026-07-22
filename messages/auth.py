from dataclasses import dataclass
from typing import ClassVar
from io import BufferedIOBase

from .primitives import *
from .packet import Payload


@dataclass
class UserAuthRequest(Payload):
    CODE = bytes([50])
    username: String
    service_name = String.build(b"ssh-userauth")
    method_name: ClassVar[String]

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Self:
        raise NotImplementedError

    def to_bytes(self) -> bytes:
        return self.CODE + self.username + self.service_name + self.method_name

    @classmethod
    def build(cls, username: bytes, *args, **kwargs) -> Self:
        return cls(String.build(username))


@dataclass
class UserAuthRequest_None(UserAuthRequest):
    method_name = String.build(b"none")

    def to_bytes(self) -> bytes:
        return self.CODE + self.username + self.service_name + self.method_name

    @classmethod
    def build(cls, username: bytes) -> Self:
        return cls(String.build(username))


@dataclass
class UserAuthRequest_Publickey(UserAuthRequest):
    method_name = String.build(b"publickey")
    algo_name: String
    pub_key: String
    signature: String

    def to_bytes(self) -> bytes:
        return (
            self.CODE
            + self.username
            + self.service_name
            + self.method_name
            + True.to_bytes()
            + self.algo_name
            + self.pub_key
            + self.signature
        )

    @classmethod
    def build(
        cls, username: bytes, algo_name: bytes, pub_key: bytes, signature: bytes
    ) -> Self:
        return cls(
            String.build(username),
            String.build(algo_name),
            String.build(pub_key),
            String.build(signature),
        )

@dataclass
class UserAuthFailure(Payload):
    CODE=bytes([51])
    supported_methods: NameList
    partial_success: bool

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> Self:
        return cls(
            NameList.from_stream(stream),
            bool.from_bytes(stream.read(1))
        )

    def to_bytes(self) -> bytes:
        return self.supported_methods+self.partial_success.to_bytes()

    @classmethod
    def build(cls) -> Self:
        raise NotImplementedError