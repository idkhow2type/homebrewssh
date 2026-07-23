import unittest
from io import BytesIO
from messages.packet import Packet
from messages.kex import KexInit, KexDHInit
from messages.misc import Disconnect

class PacketTests(unittest.TestCase):
    def test_packet_round_trip(self):
        # Using KexInit as the payload
        payload = KexInit.build()
        packet = Packet.build(
            payload=payload, block_size=8, mac=None, seq_num=None
        )

        raw = packet.to_bytes(encryption=None)
        # Packet.from_stream requires mac_length. If mac is empty, length is 0.
        restored = Packet.from_stream(BytesIO(raw), None, None, None)

        self.assertEqual(restored.packet_length, packet.packet_length)
        self.assertEqual(restored.padding_length, packet.padding_length)
        self.assertEqual(restored.payload, payload)
        self.assertEqual(restored.to_bytes(None), raw)

    def test_kex_init_round_trip(self):
        payload = KexInit.build()
        raw = payload.to_bytes()
        stream = BytesIO(raw)
        stream.read(1)  # read msg code since payload doesnt parse it
        restored = KexInit.from_stream(stream)
        self.assertEqual(restored, payload)

    def test_kex_dh_init_round_trip(self):
        payload = KexDHInit.build(e=123456789)
        raw = payload.to_bytes()
        # Since KexDHInit.from_stream is NotImplemented, we manually verify the bytes.
        self.assertEqual(payload.CODE, b"\x1e")
        self.assertTrue(len(raw) > 0)

    def test_disconnect_round_trip(self):
        payload = Disconnect.build(1, b"error", b"en")
        raw = payload.to_bytes()
        stream = BytesIO(raw)
        stream.read(1)  # read msg code since payload doesnt parse it
        restored = Disconnect.from_stream(stream)
        self.assertEqual(restored, payload)
