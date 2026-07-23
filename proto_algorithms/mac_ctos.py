from registry import Registry
from typing import Protocol
from abc import abstractmethod
from dataclasses import dataclass
from hashlib import sha1, sha256
import hmac


class Mac(type):
    key: bytes=b''

    @classmethod
    @abstractmethod
    def setup(cls, key: bytes) -> None: ...
    @classmethod
    @abstractmethod
    def compute(cls, data: bytes) -> bytes: ...


@dataclass
class Metadata:
    proto_name: bytes
    key_len: int


class Algorithm(Mac, Metadata):
    pass


registry: Registry[Mac, Algorithm, Metadata] = Registry()

@registry.register(Metadata(proto_name=b"hmac-sha2-256", key_len=32))
class hmac_sha2_256(metaclass=Mac):
    @classmethod
    def setup(cls, key: bytes) -> None:
        cls.key = key

    @classmethod
    def compute(cls, data: bytes) -> bytes:
        return hmac.new(cls.key, data, sha256).digest()

@registry.register(Metadata(proto_name=b"hmac-sha1", key_len=20))
class hmac_sha1(metaclass=Mac):
    @classmethod
    def setup(cls, key: bytes) -> None:
        cls.key = key

    @classmethod
    def compute(cls, data: bytes) -> bytes:
        return hmac.new(cls.key, data, sha1).digest()
    