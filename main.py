from dataclasses import dataclass
import socket
from io import BytesIO
import sys

from messages.packet import Packet, AlgoExchange
from stream_readers import consume_until, require
import algorithms


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
        self.ident_string = ""

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

        with self.socket.makefile("rb") as sock_file:
            # parse identification string
            msg = consume_until(sock_file, b"SSH-")
            if self.verbose:
                sys.stdout.buffer.write(msg[0])
            self.ident_string = consume_until(sock_file, b"\r\n")[0] + b"\r\n"
            ident_file = BytesIO(self.ident_string)
            self.ident_string = b"SSH-" + self.ident_string
            require(ident_file, self.metadata.proto_version.encode() + b"-")
            version, end = consume_until(ident_file, [b" ", b"\r\n"])
            self.software_version = version.decode()
            if end == b" ":
                # this is the comments of the header
                consume_until(ident_file, b"\r\n")
            # send identification string
            self.socket.sendall(self.metadata.ident_string.encode())
            print(
                self.ident_string,
                self.host,
                self.port,
                self.metadata.proto_version,
                self.software_version,
            )

            # parse algo negotiation
            client_packet = Packet.build(AlgoExchange.build())
            self.socket.sendall(client_packet.to_bytes())
            server_pack = Packet.from_stream(sock_file, AlgoExchange, 0)
            # print(
            #     len(server_pack.to_bytes()),
            #     server_pack.packet_length,
            #     len(client_packet.to_bytes()),
            #     client_packet.packet_length
            # )

        for algo in client_packet.payload.kex_algorithms.names:
            if algo in server_pack.payload.kex_algorithms.names:
                algorithms.kex.registry['proto_name'][algo](self)
                break

    def disconnect(self):
        # imagine having to free in a gc language
        assert isinstance(self.socket, socket.socket)
        self.socket.close()


if __name__ == "__main__":
    server = Server("127.0.0.1")
    server.connect()
    server.disconnect()
