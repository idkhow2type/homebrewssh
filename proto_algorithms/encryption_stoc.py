from registry import Registry
from abc import ABC, ABCMeta, abstractmethod
from dataclasses import dataclass
from Crypto.Cipher import AES


class ABCSingletonMeta(ABCMeta):
    def __call__(cls, *args, **kwargs):
        return super().__call__(*args, **kwargs)


class Cipher(ABC, metaclass=ABCSingletonMeta):
    @abstractmethod
    def __init__(self, key: bytes, iv: bytes) -> None: ...
    @abstractmethod
    def encrypt(self, data: bytes) -> bytes: ...


@dataclass
class Metadata:
    proto_name: bytes
    block_size: int


class Algorithm(Cipher, Metadata):
    pass


registry: Registry[type[Cipher], Algorithm, Metadata] = Registry()


@registry.register(Metadata(proto_name=b"aes128-ctr", block_size=16))
class aes128_ctr(Cipher):
    def __init__(self, key: bytes, iv: bytes) -> None:
        self.cipher = AES.new(key, AES.MODE_CTR, nonce=iv)

    def encrypt(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)
