from dataclasses import dataclass
from typing import cast, overload, Callable, Any
import socket
from io import BytesIO
import sys

from messages.primitives import Mpint
from messages.packet import Packet, Payload, PacketError
from messages.kex import KexInit, NewKeys
from messages.misc import (
    Disconnect,
    Ignore,
    Unimplemented,
    Debug,
    ServiceRequest,
    ServiceAccept,
)
from messages.auth import UserAuthRequest_None, UserAuthRequest_Publickey

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
        self.sock_file = None

        self.algos: T = cast(T, DefaultAlgoCollection())
        self.I_C: KexInit
        self.I_S: KexInit
        self.K: Mpint
        self.exchange_hash: bytes
        self.session_id: bytes = b""
        self.IV_ctos: bytes
        self.IV_stoc: bytes
        self.encryption_key_ctos: bytes
        self.encryption_key_stoc: bytes
        self.integrity_key_ctos: bytes = b""
        self.integrity_key_stoc: bytes = b""
        self.client_seq_num = 0
        self.server_seq_num = 0

        self.payload_handlers: list[Callable[[Server[Any], Payload]]] = []
        self.packet_error_handlers: list[Callable[[Server[Any], PacketError]]] = []

    def write_keylog(self, filename="keylog"):
        with open(filename, "w") as f:
            cookie = self.I_S.cookie.hex()
            shared_secret = self.K.to_bytes()[(4 + 0) :].hex()
            f.write(f"{cookie} SHARED_SECRET {shared_secret}\n")

    def connect(self):
        self.socket.connect((self.host, self.port))
        self.sock_file = self.socket.makefile("rb")
        # parse identification string
        msg = consume_until(self.sock_file, b"SSH-")
        # TODO: add a logging config system for this
        # sys.stdout.buffer.write(msg[0])
        self.ident_string = consume_until(self.sock_file, b"\r\n")[0]
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
        server_payload = cast(KexInit, self.recv())
        client_payload = KexInit.build()
        self.send(client_payload)
        self.I_C = client_payload
        self.I_S = server_payload

        self.algos = cast(T, AlgoCollection(client_payload, server_payload))
        return cast(Server[AlgoCollection], self)

    def disconnect(self, payload: Disconnect | None = None):

        # imagine having to free in a gc language
        if self.sock_file:
            self.sock_file.close()
        if not self.socket._closed:
            self.send(payload or Disconnect.build(11, b"Closing connection", b""))
            self.socket.close()

    def send(self, payload: Payload):
        packet = Packet.build(
            payload,
            (
                self.algos.encryption_ctos.block_size
                if self.algos.encryption_ctos
                else None
            ),
            self.algos.mac_ctos,
            self.client_seq_num,
        ).to_bytes(self.algos.encryption_ctos)
        self.socket.sendall(packet)
        self.client_seq_num += 1

    def recv(self) -> Payload | None:
        if not self.sock_file:
            raise RuntimeError("Socket stream is not initialized")

        payload = None
        try:
            payload = Packet.from_stream(
                self.sock_file,
                self.algos.encryption_stoc,
                self.algos.mac_stoc,
                self.server_seq_num,
            ).payload
        except PacketError as e:
            for handler in self.packet_error_handlers:
                handler(self, e)

        if payload:
            for handler in self.payload_handlers:
                handler(self, payload)

        self.server_seq_num += 1
        return payload


def misc_payload(server: Server[Any], payload: Payload):
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


def packet_error(server: Server[Any], e: PacketError):
    match e.code:
        case 5:
            server.disconnect(Disconnect.build(5, b"Corrupted MAC", b""))


if __name__ == "__main__":
    server = Server("127.0.0.1", int(sys.argv[1]) if len(sys.argv) >= 2 else 22)
    server.payload_handlers.append(misc_payload)
    server.packet_error_handlers.append(packet_error)

    server.connect()
    server = server.negotiate_algos()
    server.algos.kex(server)
    server.write_keylog()
    server.send(NewKeys.build())
    print(server.recv())

    server.algos.encryption_ctos.setup(server.encryption_key_ctos, server.IV_ctos)
    server.algos.encryption_stoc.setup(server.encryption_key_stoc, server.IV_stoc)
    server.algos.mac_ctos.setup(server.integrity_key_ctos)
    server.algos.mac_stoc.setup(server.integrity_key_stoc)

    assert server.sock_file

    server.send(ServiceRequest.build(b"ssh-userauth"))
    print(server.recv())
    server.send(UserAuthRequest_None.build(b"idkhow2type"))
    input()
    payload = server.recv()
    # print(payload)

    server.disconnect()
