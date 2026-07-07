from dataclasses import dataclass
import socket
import sys

from packet import Packet, AlgoExchange
from stream_readers import consume_until, require


@dataclass
class Metadata:
    proto_version: str = "2.0"
    software_version: str = "HomebrewSSH"

    @property
    def ident_string(self):
        return f"SSH-{self.proto_version}-{self.software_version} \r\n"


METADATA = Metadata()


class Server:
    def __init__(self, host: str, port=22, metadata=METADATA, verbose=True) -> None:
        self.host = host
        self.port = port
        self.metadata = metadata
        self.socket: socket.socket | None = None
        self.software_version: str | None = None
        self.verbose = verbose

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

        sock_file = self.socket.makefile("rb")

        msg = consume_until(sock_file, b"SSH-")
        if self.verbose:
            sys.stdout.buffer.write(msg[0])
        require(sock_file, self.metadata.proto_version.encode() + b"-")
        version, end = consume_until(sock_file, [b" ", b"\r\n"])
        self.software_version = version.decode()
        if end == b" ":
            # this is the comments of the header
            consume_until(sock_file, b"\r\n")
        self.socket.sendall(self.metadata.ident_string.encode())
        pack = Packet.from_stream(sock_file, AlgoExchange, 0)

        print(len(pack.to_bytes()), pack.packet_length)
        print(self.host, self.port, self.metadata.proto_version, self.software_version)

    def disconnect(self):
        # imagine having to free in a gc language
        assert isinstance(self.socket, socket.socket)
        self.socket.close()


if __name__ == "__main__":
    server = Server("127.0.0.1")
    server.connect()
    server.disconnect()
