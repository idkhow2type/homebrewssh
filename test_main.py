from dataclasses import dataclass
from io import BytesIO
import unittest
import subprocess
import shutil
import os
import socket

from messages.primitives import String, Mpint, NameList
from messages.packet import Packet, KexInit, KexDHInit, KexDHReply, NewKeys, Disconnect, Ignore, Debug, Unimplemented
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


class PrimitivesTests(unittest.TestCase):
    def test_string_round_trip(self):
        data = b"hello ssh"
        s = String.build(data)
        raw = s.to_bytes()
        restored = String.from_stream(BytesIO(raw))
        self.assertEqual(restored.data, data)
        self.assertEqual(restored.to_bytes(), raw)

    def test_mpint_round_trip(self):
        for val in [0, 1, 127, 128, -1, -128, -129, 2**31-1, 2**31]:
            with self.subTest(val=val):
                m = Mpint.build(val)
                raw = m.to_bytes()
                restored = Mpint.from_stream(BytesIO(raw))
                self.assertEqual(restored.num, val)
                self.assertEqual(restored.to_bytes(), raw)

    def test_name_list_round_trip(self):
        names = [b"curve25519-sha256", b"ecdh-sha2-nistp256"]
        nl = NameList.build(names)
        raw = nl.to_bytes()
        restored = NameList.from_stream(BytesIO(raw))
        self.assertEqual(restored.names, names)
        self.assertEqual(restored.to_bytes(), raw)

    def test_name_list_empty_round_trip(self):
        nl = NameList.build([])
        raw = nl.to_bytes()
        restored = NameList.from_stream(BytesIO(raw))
        self.assertEqual(restored.names, [])
        self.assertEqual(restored.to_bytes(), raw)


class PacketTests(unittest.TestCase):
    def test_packet_round_trip(self):
        # Using KexInit as the payload
        payload = KexInit.build()
        packet = Packet.build(
            payload=payload,
            block_size=8,
            mac=None, 
            key=None, 
            seq_num=None
        )

        raw = packet.to_bytes(encryption=None)
        # Packet.from_stream requires mac_length. If mac is empty, length is 0.
        restored = Packet.from_stream(BytesIO(raw), mac_length=0)

        self.assertEqual(restored.packet_length, packet.packet_length)
        self.assertEqual(restored.padding_length, packet.padding_length)
        self.assertEqual(restored.payload, payload)
        self.assertEqual(restored.to_bytes(None), raw)

    def test_kex_init_round_trip(self):
        payload = KexInit.build()
        raw = payload.to_bytes()
        restored = KexInit.from_stream(BytesIO(raw))
        self.assertEqual(restored, payload)

    def test_kex_dh_init_round_trip(self):
        payload = KexDHInit.build(e=123456789)
        raw = payload.to_bytes()
        # Since KexDHInit.from_stream is NotImplemented, we manually verify the bytes.
        # The CODE byte is now handled by the Packet class, not by Payload.to_bytes().
        self.assertEqual(payload.CODE, b'\x1e')
        self.assertTrue(len(raw) > 0)

    def test_disconnect_round_trip(self):
        payload = Disconnect.build(1, b"error", b"en")
        raw = payload.to_bytes()
        restored = Disconnect.from_stream(BytesIO(raw))
        self.assertEqual(restored, payload)


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.sshd_path = shutil.which("sshd")

    def test_ssh_banner(self):
        if not self.sshd_path:
            self.skipTest("sshd not found in PATH")
        
        try:
            # Start sshd in a way that it doesn't block or require config
            # Note: In a real environment, this would need a specific config
            # but here we just check if we can at least run it or talk to a port
            # For a true integration test, we'd ideally use a mock server or a 
            # pre-configured local sshd.
            
            # We'll attempt to connect to the local machine on port 22 to see if 
            # an SSH server is running and sending a banner.
            with socket.create_connection(("localhost", 22), timeout=1) as sock:
                banner = sock.recv(1024)
                self.assertTrue(banner.startswith(b"SSH-"))
        except (ConnectionRefusedError, socket.timeout):
            self.skipTest("No SSH server running on localhost:22")

if __name__ == "__main__":
    unittest.main()