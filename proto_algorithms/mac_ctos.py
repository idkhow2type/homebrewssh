from registry import Registry
from typing import Protocol
from dataclasses import dataclass
from hashlib import sha1
import hmac


class InputFunc(Protocol):
    __name__: str

    def __call__(self, data: bytes, key: bytes) -> bytes: ...


@dataclass
class Metadata:
    proto_name: bytes
    key_len: int


class Algorithm(InputFunc, Metadata):
    pass


registry: Registry[InputFunc, Algorithm, Metadata] = Registry()


@registry.register(Metadata(proto_name=b"hmac-sha1", key_len=20))
def hmac_sha1(data: bytes, key: bytes) -> bytes:
    hmac_obj = hmac.new(key, data, sha1)
    return hmac_obj.digest()
