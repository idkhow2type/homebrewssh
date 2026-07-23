import unittest
from io import BytesIO
from stream_readers import consume_until

class ConsumeUntilTests(unittest.TestCase):
    def test_stops_before_sentinel(self):
        stream = BytesIO(b"bbab")

        consumed, marker = consume_until(stream, [b"bab"])
        self.assertEqual(consumed, b"b")
        self.assertEqual(marker, b"bab")

    def test_multiple_end_marker(self):
        stream = BytesIO(b"comment \r\n")

        consumed, marker = consume_until(stream, [b" ", b"\r\n"])
        self.assertEqual(consumed, b"comment")
        self.assertEqual(marker, b" ")

    def test_multiple_end_marker_partial_match(self):
        stream = BytesIO(b"commenta\r\n")

        consumed, marker = consume_until(stream, [b"ab", b"\r\n"])
        self.assertEqual(consumed, b"commenta")
        self.assertEqual(marker, b"\r\n")
