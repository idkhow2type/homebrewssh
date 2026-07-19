from dataclasses import dataclass
from typing import cast, overload
import socket
from io import BytesIO
import sys

from messages.packet import (
    Packet,
    KexInit,
    NewKeys,
    Payload,
    Disconnect,
    Ignore,
    Unimplemented,
    Debug,
)
from stream_readers import consume_until, require
from proto_algorithms.collection import AlgoCollection, DefaultAlgoCollection


@dataclass
class Metadata:
    proto_version: str = "2.0"
    software_version: str = "HomebrewSSH"

    @property
    def ident_string(self):
        return f"SSH-{self.proto_version}-{self.software_version}".encode()


METADATA = Metadata()


class Server[T: AlgoCollection | DefaultAlgoCollection = DefaultAlgoCollection]:
    def __init__(self, host: str, port=22, metadata=METADATA) -> None:
        self.host = host
        self.port = port

        self.client_meta = metadata
        self.software_version: str
        self.ident_string = b""

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.algos: T = cast(T, DefaultAlgoCollection())
        self.I_C: bytes
        self.I_S: bytes
        self.exchange_hash: bytes
        self.session_id: bytes = b""
        self.IV_ctos: bytes
        self.IV_stoc: bytes
        self.encryption_key_ctos: bytes
        self.encryption_key_stoc: bytes
        self.integrity_key_ctos: bytes
        self.integrity_key_stoc: bytes

    def connect(self):
        self.socket.connect((self.host, self.port))
        with self.socket.makefile("rb") as sock_file:
            # parse identification string
            msg = consume_until(sock_file, b"SSH-")
            # TODO: add a logging config system for this
            # sys.stdout.buffer.write(msg[0])
            self.ident_string = consume_until(sock_file, b"\r\n")[0]
            ident_file = BytesIO(self.ident_string + b"\r\n")
            self.ident_string = b"SSH-" + self.ident_string
            require(ident_file, self.client_meta.proto_version.encode() + b"-")
            version, end = consume_until(ident_file, [b" ", b"\r\n"])
            self.software_version = version.decode()
            if end == b" ":
                # this is the comments of the header
                consume_until(ident_file, b"\r\n")
            # send identification string
            self.socket.sendall(self.client_meta.ident_string + b"\r\n")

    def negotiate_algos(self) -> Server[AlgoCollection]:
        server_payload = self.recv(KexInit)
        client_payload = KexInit.build()
        self.send(client_payload)
        self.I_C = client_payload.to_bytes()
        self.I_S = server_payload.to_bytes()

        self.algos = cast(T, AlgoCollection(client_payload, server_payload))
        return cast(Server[AlgoCollection], self)

    @overload
    def disconnect(self): ...
    @overload
    def disconnect(self, payload: None): ...
    @overload
    def disconnect(self, payload: Disconnect): ...
    def disconnect(self, payload=None):
        # imagine having to free in a gc language
        if payload:
            self.send(payload)
        self.socket.close()

    def send(self, payload: Payload):
        server.socket.sendall(
            Packet.build(payload).to_bytes(
                self.algos.encryption_ctos.encrypt
                if self.algos.encryption_ctos and self.algos.encryption_ctos._cipher
                else None
            )
        )

    @overload
    def recv(self) -> Payload: ...
    @overload
    def recv(self, payload_type: None) -> Payload: ...
    @overload
    def recv[U: Payload](self, payload_type: type[U]) -> U: ...
    def recv(self, payload_type=None):
        with self.socket.makefile("rb") as sock_file:
            payload = Packet.from_stream(sock_file, 0).payload
            if payload_type and isinstance(payload, payload_type):
                return payload
            else:
                match payload.CODE:
                    case Disconnect.CODE:
                        payload = cast(Disconnect, payload)
                        sys.stdout.buffer.write(payload.description.data)
                        server.disconnect()
                    case Ignore.CODE:
                        pass
                    case Unimplemented.CODE:
                        pass
                    case Debug.CODE:
                        payload = cast(Debug, payload)
                        sys.stdout.buffer.write(payload.message.data)
                return payload


if __name__ == "__main__":
    server = Server("127.0.0.1", int(sys.argv[1]) if len(sys.argv) >= 2 else 22)
    server.connect()
    server = server.negotiate_algos()
    server.algos.kex(server)
    server.send(NewKeys.build())
    server.algos.encryption_ctos.setup(server.encryption_key_ctos,server.IV_ctos)
    server.disconnect(Disconnect.build(11, b"sorry i died", b""))
