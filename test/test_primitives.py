import unittest
from io import BytesIO
from messages.primitives import String, Mpint, NameList

class PrimitivesTests(unittest.TestCase):
    def test_string_round_trip(self):
        data = b"hello ssh"
        s = String.build(data)
        raw = s.to_bytes()
        restored = String.from_stream(BytesIO(raw))
        self.assertEqual(restored.data, data)
        self.assertEqual(restored.to_bytes(), raw)

    def test_mpint_round_trip(self):
        for val in [0, 1, 127, 128, -1, -128, -129, 2**31 - 1, 2**31]:
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
