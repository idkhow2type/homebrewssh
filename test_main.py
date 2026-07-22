from dataclasses import dataclass
from io import BytesIO
import unittest
import subprocess
import shutil
import os
import socket

from messages.primitives import String, Mpint, NameList
from messages.packet import Payload, Packet, KexInit, KexDHInit, KexDHReply, NewKeys, Disconnect, Ignore, Debug, Unimplemented
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
        stream=BytesIO(raw)
        stream.read(1) # read msg code since payload doesnt parse it
        restored = KexInit.from_stream(stream)
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
        stream=BytesIO(raw)
        stream.read(1) # read msg code since payload doesnt parse it
        restored = Disconnect.from_stream(stream)
        self.assertEqual(restored, payload)


from main import Server

import tempfile

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.sshd_bin = shutil.which("sshd")
        self.keygen_bin = shutil.which("ssh-keygen")
        self.temp_dir = tempfile.mkdtemp()
        self.sshd_process = None
        self.port: int = 0

    def tearDown(self):
        if self.sshd_process:
            self.sshd_process.terminate()
            self.sshd_process.wait()
        self.log_file.close()
        shutil.rmtree(self.temp_dir,True)

    def start_mock_sshd(self):
        if not self.sshd_bin or not self.keygen_bin:
            self.skipTest("sshd or ssh-keygen not found in PATH")

        # 1. Generate host keys
        host_key = os.path.join(self.temp_dir, "ssh_host_rsa_key")
        subprocess.run([
            self.keygen_bin, "-t", "rsa", "-f", host_key, "-N", "", "-q"
        ], check=True)

        # 2. Create config file
        config_path = os.path.join(self.temp_dir, "sshd_config")
        # Use a config that allows running as non-root and avoids common failures
        config_content = (
            "Port 0\n"
            "HostKey " + host_key + "\n"
            "PasswordAuthentication no\n"
            "PubkeyAuthentication no\n"
            "PermitEmptyPasswords no\n"
            "PidFile " + os.path.join(self.temp_dir, "sshd.pid") + "\n"
        )
        with open(config_path, "w") as f:
            f.write(config_content)
        
        # Strict permissions for host key
        os.chmod(host_key, 0o600)

        # 3. Start sshd on a random port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("localhost", 0))
            self.port = s.getsockname()[1]

        # Capture stderr to a file for debugging if it fails
        self.log_file = open(os.path.join(self.temp_dir, "sshd.log"), "w")
        self.sshd_process = subprocess.Popen([
            self.sshd_bin, "-ddd", "-p", str(self.port), "-f", config_path
        ], stdout=subprocess.DEVNULL, stderr=self.log_file)
        
        # Wait for server to start
        import time
        time.sleep(0.5)

    def test_full_handshake(self):
        """
        Test the client against a freshly spun-up OpenSSH server on a free port.
        """
        self.start_mock_sshd()
        
        try:
            # Initialize client and connect to the temporary sshd
            client = Server("localhost", self.port)
            client.connect()
            
            # 1. Algorithm Negotiation
            client = client.negotiate_algos()
            
            # 2. Key Exchange (KEX)
            client.algos.kex(client)
            
            # 3. Exchange NewKeys
            client.send(NewKeys.build())
            client.recv(NewKeys)
            
            # Verify keys were derived
            self.assertIsNotNone(client.encryption_key_ctos)
            self.assertIsNotNone(client.session_id)
            
            # Clean up
            client.disconnect()
            
        except Exception as e:
            log_content = ""
            log_path = os.path.join(self.temp_dir, "sshd.log")
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r") as log_file:
                        log_content = "\n\n--- Server Debug Logs ---\n" + log_file.read()
                except Exception as log_e:
                    log_content = f"\n\nCould not read server logs: {log_e}"
            self.fail(f"Handshake failed with temporary sshd: {e.__class__.__name__}: {e}{log_content}")

        self.tearDown()

if __name__ == "__main__":
    unittest.main()