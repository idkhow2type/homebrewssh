import unittest
from io import BytesIO
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
