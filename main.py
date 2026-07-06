from dataclasses import dataclass
from trie import Trie
import socket
import sys


@dataclass
class Metadata:
    proto_version: str = "2.0"
    software_version: str = "HomebrewSSH"

    @property
    def ident_string(self):
        return f"SSH-{self.proto_version}-{self.software_version} \r\n"


METADATA = Metadata()


def consume_until(
    s: socket.socket, end: bytes | list[bytes] | Trie, include_end=False
) -> bytes:
    """
    Consumes the socket non-greedily until end is found,
    returns consumed bytes (excluding end)
    """
    if isinstance(end, bytes):
        end = Trie([end])
    elif isinstance(end, list):
        end = Trie(end)
    assert isinstance(end, Trie)

    ret: bytes = bytes()
    buf: bytes = bytes()
    walker = end.create_walker()
    next(walker)
    while True:
        c = s.recv(1)
        if not c:
            raise ConnectionAbortedError()
        trie_state = walker.send(c[0])
        match trie_state:
            case Trie.WalkState.START:
                ret += buf+c
                buf = bytes()
            case Trie.WalkState.WALKING:
                buf+=c
            case Trie.WalkState.RESET:
                ret+=buf
                buf = c
                next(walker)
            case Trie.WalkState.END:
                if include_end:
                    ret += buf+c
                return ret


def require(s: socket.socket, pref: bytes):
    # asserts the next bytes in the socket match pref
    assert s.recv(len(pref)) == pref


class Server:
    def __init__(self, host: str, port=22, metadata=METADATA, verbose=True) -> None:
        self.host = host
        self.port = port
        self.metadata = metadata
        self.socket: socket.socket | None = None
        self.software_version: str | None = None
        self.verbose = verbose

    def connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            # print(s.recv(1024))
            msg = consume_until(s, b"SSH-")
            if self.verbose:
                sys.stdout.buffer.write(msg)
            require(s, self.metadata.proto_version.encode() + b"-")
            self.software_version = consume_until(s, b" ").decode()
            consume_until(s, b"\r\n")
            s.sendall(self.metadata.ident_string.encode())

        print(self.host, self.port, self.metadata.proto_version, self.software_version)


if __name__ == "__main__":
    server = Server("127.0.0.1")
    server.connect()
