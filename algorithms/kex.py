from registry import Registry
from typing import Protocol
from dataclasses import dataclass


class InputFunc(Protocol):
    __name__: str

    def __call__(self, data: bytes) -> bytes: ...


@dataclass
class Metadata:
    proto_name: bytes


class Algorithm(InputFunc, Metadata):
    pass


registry: Registry[InputFunc, Algorithm, Metadata] = Registry()


@registry.register(Metadata(proto_name=b"diffie-hellman-group1-sha1"))
def dh1(data: bytes) -> bytes:
    return data

@registry.register(Metadata(proto_name=b"diffie-hellman-group14-sha1"))
def dh14(data: bytes) -> bytes:
    return data