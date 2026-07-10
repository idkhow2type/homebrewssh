from typing import IO
from trie import Trie

def consume_until(s: IO[bytes], end: bytes | list[bytes] | Trie) -> tuple[bytes, bytes]:
    """
    Consumes the socket non-greedily until end is found,
    returns (consumed bytes, end)
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
        c = s.read(1)
        if not c:
            raise ConnectionAbortedError()
        trie_state = walker.send(c[0])
        match trie_state:
            case Trie.WalkState.START:
                ret += buf + c
                buf = bytes()
            case Trie.WalkState.WALKING:
                buf += c
            case Trie.WalkState.RESET:
                ret += buf
                buf = c
                next(walker)
            case Trie.WalkState.END:
                return (ret, buf + c)


def require(s: IO[bytes], pref: bytes):
    assert s.read(len(pref)) == pref