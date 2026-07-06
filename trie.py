from typing import cast
from enum import Enum


class Trie:
    def __init__(self, keys: list[bytes] | None = None) -> None:
        self.children: list[Trie | None] = [None] * 256
        self.is_word_end = False
        if keys:
            for word in keys:
                self.insert(word)

    def insert(self, key: bytes):
        curr = self
        for c in key:
            if curr.children[c] is None:
                curr.children[c] = Trie()
            curr = cast(Trie, curr.children[c])
        curr.is_word_end = True

    def search(self, key: bytes):
        curr = self
        for c in key:
            if curr.children[c] is None:
                return False
            curr = cast(Trie, curr.children[c])
        return curr.is_word_end

    class WalkState(Enum):
        START = 0
        WALKING = 1
        RESET=2
        END = 3

    def create_walker(self):
        """
        Try to walk down the trie with given byte, reset if unable
        Returns true when any key is found
        """
        curr = self
        c = yield self.WalkState.START
        while True:
            if curr.children[c] is None:
                if curr==self:
                    c = yield self.WalkState.START
                else:
                    yield self.WalkState.RESET
                curr = self
            else:
                curr = cast(Trie, curr.children[c])
                if curr.is_word_end:
                    yield self.WalkState.END
                    return
                c = yield self.WalkState.WALKING


__all__ = ["Trie"]
