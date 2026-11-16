import os
import unittest

from affine_cipher import (
    build_decrypt_table,
    build_encrypt_table,
    decrypt_bytes,
    decrypt_reference,
    encrypt_bytes,
    encrypt_reference,
    mod_inverse,
    validate_keys,
)


class TestModInverse(unittest.TestCase):
    def test_inverse_of_odd_keys(self):
        for a in range(1, 256, 2):
            inv = mod_inverse(a)
            self.assertEqual((a * inv) % 256, 1, f"a={a}")

    def test_even_key_raises(self):
        for a in (0, 2, 128, 254):
            with self.assertRaises(ValueError):
                mod_inverse(a)


class TestValidateKeys(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate_keys(7, 13), (True, ""))

    def test_a_even(self):
        ok, msg = validate_keys(4, 13)
        self.assertFalse(ok)
        self.assertIn("ganjil", msg)

    def test_a_out_of_range(self):
        for a in (0, -3, 257, 511):
            self.assertFalse(validate_keys(a, 13)[0])

    def test_b_out_of_range(self):
        for b in (-1, 256):
            self.assertFalse(validate_keys(7, b)[0])


class TestTables(unittest.TestCase):
    def test_encrypt_table_matches_formula(self):
        table = build_encrypt_table(7, 13)
        self.assertEqual(len(table), 256)
        for p in range(256):
            self.assertEqual(table[p], (7 * p + 13) % 256)

    def test_decrypt_table_is_inverse(self):
        enc = build_encrypt_table(7, 13)
        dec = build_decrypt_table(7, 13)
        for p in range(256):
            self.assertEqual(dec[enc[p]], p)


class TestTransform(unittest.TestCase):
    def test_table_equals_reference_for_all_bytes(self):
        data = bytes(range(256))
        for a, b in ((1, 0), (7, 13), (255, 255), (21, 200)):
            self.assertEqual(encrypt_bytes(data, a, b), encrypt_reference(data, a, b))
            self.assertEqual(decrypt_bytes(data, a, b), decrypt_reference(data, a, b))

    def test_roundtrip_random(self):
        data = os.urandom(4096)
        for a, b in ((7, 13), (11, 0), (255, 128)):
            self.assertEqual(decrypt_bytes(encrypt_bytes(data, a, b), a, b), data)

    def test_empty_data(self):
        self.assertEqual(encrypt_bytes(b"", 7, 13), b"")
        self.assertEqual(decrypt_bytes(b"", 7, 13), b"")

    def test_wrong_key_produces_different_bytes(self):
        data = b"tugas akhir kriptografi"
        self.assertNotEqual(decrypt_bytes(encrypt_bytes(data, 7, 13), 7, 14), data)


if __name__ == "__main__":
    unittest.main()
