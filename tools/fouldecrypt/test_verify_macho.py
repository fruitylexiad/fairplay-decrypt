import struct
import unittest
from verify_macho import verify
class VerificationTests(unittest.TestCase):
    def fixture(self):
        source = bytearray(0x8000)
        struct.pack_into("<IIIIIIII", source, 0, 0xfeedfacf, 0x100000c, 0, 2, 1, 24, 0, 0)
        struct.pack_into("<IIIIII", source, 32, 0x2c, 24, 0x4000, 0x4000, 1, 0)
        source[0x4000:] = b"E" * 0x4000
        out = source.copy()
        struct.pack_into("<I", out, 48, 0)
        out[0x4000:] = b"P" * 0x4000
        return source, out
    def test_valid_comparison(self):
        verify(*self.fixture())
    def test_header_only_is_rejected(self):
        source, out = self.fixture()
        out[0x4000:] = source[0x4000:]
        with self.assertRaises(ValueError): verify(source, out)
    def test_nonzero_cryptid_is_rejected(self):
        source, out = self.fixture()
        struct.pack_into("<I", out, 48, 1)
        with self.assertRaises(ValueError): verify(source, out)
    def test_unexpected_changes_are_rejected(self):
        source, out = self.fixture()
        out[100] = 1
        with self.assertRaises(ValueError): verify(source, out)
    def test_size_mismatch_is_rejected(self):
        source, out = self.fixture()
        with self.assertRaises(ValueError): verify(source, out[:-1])
if __name__ == "__main__": unittest.main()
