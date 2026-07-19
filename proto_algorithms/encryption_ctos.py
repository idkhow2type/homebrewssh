from registry import Registry
from abc import abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar
from Crypto.Cipher import AES
from Crypto.Util import Counter


# this is a truly fucked up way to do it, and yet it works o well
# i actually cannot begin to describe hhow cursed this is
# no words can do it justice
class Cipher(type):
    _cipher: Any | None = None
    block_size: ClassVar[int]

    @classmethod
    @abstractmethod
    def setup(cls, key: bytes, iv: bytes) -> None: ...
    @classmethod
    @abstractmethod
    def encrypt(cls, data: bytes) -> bytes: ...


@dataclass
class Metadata:
    proto_name: bytes


class Algorithm(Cipher, Metadata):
    pass


registry: Registry[Cipher, Algorithm, Metadata] = Registry()


@registry.register(Metadata(proto_name=b"aes128-ctr"))
class aes128_ctr(metaclass=Cipher):
    block_size = 16

    @classmethod
    def setup(cls, key: bytes, iv: bytes) -> None:
        cls._cipher = AES.new(
            key,
            AES.MODE_CTR,
            counter=Counter.new(cls.block_size * 8, initial_value=int.from_bytes(iv)),
        )

    @classmethod
    def encrypt(cls, data: bytes) -> bytes:
        assert cls._cipher
        return cls._cipher.encrypt(data)
