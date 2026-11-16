import tempfile
import unittest
from pathlib import Path

from metrics import (
    avalanche_percent,
    bit_difference,
    calculate_entropy,
    compare_files,
    compute_sha256,
    entropy_from_counts,
    is_valid_sha256_hex,
    sha256_bytes,
    sha256_file,
    throughput_mbps,
)


class TestEntropy(unittest.TestCase):
    def test_uniform_256_values_is_8_bits(self):
        self.assertAlmostEqual(entropy_from_counts([100] * 256), 8.0, places=6)

    def test_single_value_is_zero(self):
        self.assertEqual(entropy_from_counts([1000]), 0.0)

    def test_empty_is_zero(self):
        self.assertEqual(entropy_from_counts([0] * 256), 0.0)

    def test_calculate_entropy_wrapper(self):
        self.assertAlmostEqual(calculate_entropy(bytes(range(256))), 8.0, places=6)


class TestBits(unittest.TestCase):
    def test_bit_difference(self):
        self.assertEqual(bit_difference(b"\x00", b"\xff"), 8)
        self.assertEqual(bit_difference(b"\x00\x00", b"\x00\x01"), 1)

    def test_bit_difference_rejects_length_mismatch(self):
        with self.assertRaises(ValueError):
            bit_difference(b"\x00", b"\x00\x00")

    def test_avalanche_percent(self):
        self.assertAlmostEqual(avalanche_percent(1, 800), 0.125, places=6)
        self.assertIsNone(avalanche_percent(0, 0))


class TestHashAndCompare(unittest.TestCase):
    def test_sha256_known_value(self):
        self.assertEqual(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_compute_sha256_alias(self):
        self.assertEqual(compute_sha256(b"abc"), sha256_bytes(b"abc"))

    def test_sha256_file_matches_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.bin"
            data = bytes(range(256)) * 5000
            path.write_bytes(data)
            self.assertEqual(sha256_file(path, chunk_size=4096), sha256_bytes(data))

    def test_compare_identical_and_different(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.bin"
            b = Path(tmp) / "b.bin"
            a.write_bytes(b"abcdef")
            b.write_bytes(b"abXdef")
            cmp = compare_files(a, b)
            self.assertFalse(cmp.hash_match)
            self.assertEqual(cmp.differing_bytes, 1)
            self.assertEqual(cmp.first_difference_offset, 2)
            b.write_bytes(b"abcdef")
            cmp = compare_files(a, b)
            self.assertTrue(cmp.hash_match)
            self.assertEqual(cmp.differing_bytes, 0)
            self.assertIsNone(cmp.first_difference_offset)

    def test_compare_different_lengths(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.bin"
            b = Path(tmp) / "b.bin"
            a.write_bytes(b"abc")
            b.write_bytes(b"abcdef")
            cmp = compare_files(a, b)
            self.assertFalse(cmp.hash_match)
            self.assertEqual(cmp.first_difference_offset, 3)


class TestHelpers(unittest.TestCase):
    def test_throughput(self):
        self.assertAlmostEqual(throughput_mbps(2 * 1024 * 1024, 1.0), 2.0, places=6)
        self.assertIsNone(throughput_mbps(0, 1.0))
        self.assertIsNone(throughput_mbps(1024, 0.0))

    def test_hash_hex_validation(self):
        self.assertTrue(is_valid_sha256_hex("a" * 64))
        self.assertTrue(is_valid_sha256_hex("A" * 64))
        self.assertFalse(is_valid_sha256_hex("a" * 63))
        self.assertFalse(is_valid_sha256_hex("z" * 64))
        self.assertFalse(is_valid_sha256_hex(""))


if __name__ == "__main__":
    unittest.main()
