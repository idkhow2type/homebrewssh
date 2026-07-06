import socket
import unittest

from main import consume_until
from trie import Trie


class TrieTests(unittest.TestCase):
    def test_search_matches_exact_words_only(self):
        trie = Trie([b"abc", b"abd"])

        self.assertTrue(trie.search(b"abc"))
        self.assertTrue(trie.search(b"abd"))
        self.assertFalse(trie.search(b"ab"))
        self.assertFalse(trie.search(b"abe"))

    def test_walker_reports_overlap_and_match(self):
        trie = Trie([b"bab"])
        walker = trie.create_walker()

        self.assertEqual(next(walker), Trie.WalkState.START)
        self.assertEqual(walker.send(ord("b")), Trie.WalkState.WALKING)
        self.assertEqual(walker.send(ord("a")), Trie.WalkState.WALKING)
        self.assertEqual(walker.send(ord("b")), Trie.WalkState.END)


class ConsumeUntilTests(unittest.TestCase):
    def test_stops_before_sentinel(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)

        right.sendall(b"bbab")

        self.assertEqual(consume_until(left, [b"bab"]), b"b")

    def test_include_end_marker(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)

        right.sendall(b"helloENDworld")

        self.assertEqual(consume_until(left, b"END", include_end=True), b"helloEND")

    def test_multiple_end_marker(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)

        right.sendall(b"comment \r\n")

        self.assertEqual(consume_until(left, [b' ',b'\r\n']), b"comment")

    def test_multiple_end_marker_include(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)

        right.sendall(b"comment \r\n")

        self.assertEqual(consume_until(left, [b' ',b'\r\n'],include_end=True), b"comment ")

    def test_multiple_end_marker_partial_match(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)

        right.sendall(b"commenta\r\n")

        self.assertEqual(consume_until(left, [b'ab',b'\r\n']), b"commenta")

    def test_multiple_end_marker_partial_match_include(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)

        right.sendall(b"commenta\r\n")

        self.assertEqual(consume_until(left, [b'ab',b'\r\n'],include_end=True), b"commenta\r\n")

    


if __name__ == "__main__":
    unittest.main()
