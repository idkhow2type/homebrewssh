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


@registry.register(Metadata(proto_name=b"rsa-sha2-256"))
def rsa_sha2_256(data: bytes) -> bytes:
    return data