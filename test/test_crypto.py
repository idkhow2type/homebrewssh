import unittest
from io import BytesIO
from messages.packet import Packet, Payload, PacketError
from messages.misc import Ignore
from proto_algorithms.encryption_ctos import aes128_ctr as enc_algo
from proto_algorithms.encryption_stoc import aes128_ctr as dec_algo
from proto_algorithms.mac_ctos import hmac_sha1 as mac_ctos_algo
from proto_algorithms.mac_stoc import hmac_sha1 as mac_stoc_algo

class EncryptionMACTests(unittest.TestCase):
    def setUp(self):
        # Setup common keys and IVs
        self.key = b"this is a secret key 16 bytes"[:16]
        self.iv = b"this is an iv 16 bytes"[:16]
        self.mac_key = b"mac secret key 20 bytes"[:20]
        
        # Setup algorithms
        enc_algo.setup(self.key, self.iv)
        dec_algo.setup(self.key, self.iv)
        mac_ctos_algo.setup(self.mac_key)
        mac_stoc_algo.setup(self.mac_key)

    def test_encryption_decryption_roundtrip(self):
        """Test that a packet encrypted by ctos is correctly decrypted by stoc."""
        payload = Ignore.build(b"test message")
        packet = Packet.build(
            payload=payload,
            block_size=enc_algo.block_size,
            mac=mac_ctos_algo,
            seq_num=0
        )
        
        raw_bytes = packet.to_bytes(enc_algo)
        
        # Decrypt and parse
        stream = BytesIO(raw_bytes)
        restored_packet = Packet.from_stream(
            stream,
            decryption=dec_algo,
            mac=mac_stoc_algo,
            seq_num=0
        )
        
        self.assertEqual(restored_packet.payload, payload)
        self.assertEqual(restored_packet.random_padding, packet.random_padding)

    def test_mac_verification_success(self):
        """Test that a valid MAC is accepted."""
        payload = Ignore.build(b"mac test")
        packet = Packet.build(
            payload=payload,
            block_size=enc_algo.block_size,
            mac=mac_ctos_algo,
            seq_num=10
        )
        
        # We use no encryption for this specific test to isolate MAC
        raw_bytes = packet.to_bytes(None) 
        
        stream = BytesIO(raw_bytes)
        # This should not raise PacketError
        Packet.from_stream(
            stream,
            decryption=None,
            mac=mac_stoc_algo,
            seq_num=10
        )

    def test_mac_verification_failure(self):
        """Test that an incorrect MAC raises PacketError."""
        payload = Ignore.build(b"mac fail test")
        packet = Packet.build(
            payload=payload,
            block_size=enc_algo.block_size,
            mac=mac_ctos_algo,
            seq_num=5
        )
        
        raw_bytes = bytearray(packet.to_bytes(None))
        # Corrupt the MAC (last few bytes)
        raw_bytes[-1] ^= 0xFF
        
        stream = BytesIO(bytes(raw_bytes))
        with self.assertRaises(PacketError) as cm:
            Packet.from_stream(
                stream,
                decryption=None,
                mac=mac_stoc_algo,
                seq_num=5
            )
        self.assertEqual(cm.exception.code, 5)
        self.assertEqual(cm.exception.message, "Corrupted MAC")

    def test_wrong_sequence_number_mac_failure(self):
        """Test that using the wrong sequence number results in a MAC failure."""
        payload = Ignore.build(b"seq test")
        packet = Packet.build(
            payload=payload,
            block_size=enc_algo.block_size,
            mac=mac_ctos_algo,
            seq_num=1
        )
        
        raw_bytes = packet.to_bytes(None)
        stream = BytesIO(raw_bytes)
        
        # Try to verify with seq_num=2 instead of 1
        with self.assertRaises(PacketError) as cm:
            Packet.from_stream(
                stream,
                decryption=None,
                mac=mac_stoc_algo,
                seq_num=2
            )
        self.assertEqual(cm.exception.code, 5)

    def test_payload_error_handling_sim(self):
        """Test that Packet.from_stream raises for invalid payload types."""
        # Construct a packet with an invalid payload code
        # [length 4][pad_len 1][code 1][data...][padding]
        bad_data = (
            (1).to_bytes(4, "big") + 
            (4).to_bytes(1, "big") + 
            b"\xff" + # Invalid payload code
            b"data" + 
            b"pad1pad2pad3pad4"
        )
        
        stream = BytesIO(bad_data)
        with self.assertRaises(KeyError):
            Packet.from_stream(stream, None, None, None)

if __name__ == "__main__":
    unittest.main()
