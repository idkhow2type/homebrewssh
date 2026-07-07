from dataclasses import dataclass
from io import BytesIO
import unittest

from packet import AlgoExchange, NameList, Packet, Payload
from stream_readers import consume_until
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


@dataclass
class DummyPayload(Payload):
    message_type: int
    body: bytes

    @classmethod
    def from_stream(cls, stream: BytesIO) -> "DummyPayload":
        message_type = int.from_bytes(stream.read(1), "big")
        body_length = int.from_bytes(stream.read(1), "big")
        body = stream.read(body_length)
        return cls(message_type, body)

    def to_bytes(self) -> bytes:
        return (
            self.message_type.to_bytes(1, "big")
            + len(self.body).to_bytes(1, "big")
            + self.body
        )


class PacketTests(unittest.TestCase):
    def test_name_list_round_trip(self):
        names = [b"curve25519-sha256", b"ecdh-sha2-nistp256"]
        payload = NameList(len(b"curve25519-sha256,ecdh-sha2-nistp256"), names)

        raw = payload.to_bytes()
        restored = NameList.from_stream(BytesIO(raw))

        self.assertEqual(restored.length, payload.length)
        self.assertEqual(restored.names, names)
        self.assertEqual(restored.to_bytes(), raw)

    def test_packet_round_trip_preserves_payload_padding_and_mac(self):
        payload = DummyPayload(7, b"hello")
        packet = Packet(
            packet_length=14,
            padding_length=4,
            payload=payload,
            random_padding=b"abcd",
            mac=b"mac",
        )

        raw = packet.to_bytes()
        restored = Packet.from_stream(BytesIO(raw), DummyPayload, mac_length=3)

        self.assertEqual(restored.packet_length, packet.packet_length)
        self.assertEqual(restored.padding_length, packet.padding_length)
        self.assertEqual(restored.payload, payload)
        self.assertEqual(restored.random_padding, packet.random_padding)
        self.assertEqual(restored.mac, packet.mac)
        self.assertEqual(restored.to_bytes(), raw)

    def test_algo_exchange_round_trip(self):
        def nlist(*names: bytes) -> NameList:
            raw_names = b",".join(names)
            return NameList(len(raw_names), list(names))

        payload = AlgoExchange(
            SSH_MSG_KEXINIT=20,
            cookie=b"0123456789abcdef",
            kex_algorithms=nlist(b"curve25519-sha256"),
            server_host_key_algorithms=nlist(b"ssh-ed25519"),
            encryption_algorithms_client_to_server=nlist(b"aes128-ctr", b"aes256-ctr"),
            encryption_algorithms_server_to_client=nlist(b"aes128-ctr", b"aes256-ctr"),
            mac_algorithms_client_to_server=nlist(b"hmac-sha2-256"),
            mac_algorithms_server_to_client=nlist(b"hmac-sha2-256"),
            compression_algorithms_client_to_server=nlist(b"none"),
            compression_algorithms_server_to_client=nlist(b"none"),
            languages_client_to_server=nlist(b"en-US"),
            languages_server_to_client=nlist(b"en-US"),
            first_kex_packet_follows=True,
        )

        raw = payload.to_bytes()
        restored = AlgoExchange.from_stream(BytesIO(raw))

        self.assertEqual(restored, payload)
        self.assertEqual(restored.to_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
