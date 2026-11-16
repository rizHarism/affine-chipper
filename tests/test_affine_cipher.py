import unittest

from affine_cipher import mod_inverse, validate_keys


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


if __name__ == "__main__":
    unittest.main()
