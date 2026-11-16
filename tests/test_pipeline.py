import os
import tempfile
import unittest
from pathlib import Path

from affine_cipher import encrypt_bytes
from metrics import bit_difference
from pipeline import CHUNK_SIZE, decrypt_file, encrypt_file, measure_avalanche, output_names


class TestOutputNames(unittest.TestCase):
    def test_encrypt_name(self):
        self.assertEqual(output_names(Path("C:/x/tugas.pdf"), "enc").name, "tugas.pdf.enc")

    def test_decrypt_name(self):
        self.assertEqual(output_names(Path("C:/x/tugas.pdf.enc"), "dec").name, "tugas_decrypted.pdf")
        self.assertEqual(output_names(Path("C:/x/lagu.mp3.enc"), "dec").name, "lagu_decrypted.mp3")

    def test_decrypt_name_without_enc_suffix(self):
        self.assertEqual(output_names(Path("C:/x/tugas.pdf"), "dec").name, "tugas_decrypted.pdf")

    def test_decrypt_name_same_folder(self):
        self.assertEqual(
            output_names(Path("D:/data/a.txt.enc"), "dec").parent,
            Path("D:/data"),
        )

    def test_invalid_mode(self):
        with self.assertRaises(ValueError):
            output_names(Path("C:/x/a.txt"), "lain")


class TestPipeline(unittest.TestCase):
    def test_roundtrip_and_sizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "besar.mp4"
            src.write_bytes(os.urandom(CHUNK_SIZE + 12345))
            enc = Path(tmp) / "besar.mp4.enc"
            dec = Path(tmp) / "besar_decrypted.mp4"
            r1 = encrypt_file(src, enc, 7, 13)
            r2 = decrypt_file(enc, dec, 7, 13)
            self.assertEqual(enc.stat().st_size, src.stat().st_size)
            self.assertEqual(dec.read_bytes(), src.read_bytes())
            self.assertAlmostEqual(r1.entropy_plain, r1.entropy_cipher, places=6)
            self.assertAlmostEqual(r1.entropy_plain, r2.entropy_cipher, places=6)
            self.assertEqual(r1.hash_plain, r2.hash_plain)
            self.assertIsNotNone(r1.avalanche_plain)
            self.assertIsNone(r2.avalanche_plain)
            self.assertEqual(r1.plain_extension, "mp4")

    def test_decrypt_result_normalizes_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "tugas.pdf"
            src.write_bytes(b"isi")
            enc = Path(tmp) / "tugas.pdf.enc"
            encrypt_file(src, enc, 7, 13)
            r = decrypt_file(enc, Path(tmp) / "tugas_decrypted.pdf", 7, 13)
            self.assertEqual(r.plain_name, "tugas.pdf")
            self.assertEqual(r.plain_extension, "pdf")

    def test_progress_reaches_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "p.bin"
            src.write_bytes(b"x" * (CHUNK_SIZE * 2 + 10))
            seen = []
            encrypt_file(src, Path(tmp) / "p.bin.enc", 7, 13, progress=seen.append)
            self.assertEqual(seen[-1], 1.0)

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "kosong.txt"
            src.write_bytes(b"")
            r = encrypt_file(src, Path(tmp) / "kosong.txt.enc", 7, 13)
            self.assertEqual(r.plain_size, 0)
            self.assertEqual(r.entropy_plain, 0.0)
            self.assertIsNone(r.throughput_mbps)
            self.assertEqual(
                r.hash_plain,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )

    def test_file_without_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "tanpaext"
            src.write_bytes(b"abc")
            r = encrypt_file(src, Path(tmp) / "tanpaext.enc", 7, 13)
            self.assertEqual(r.plain_extension, "")
            self.assertEqual(output_names(Path(tmp) / "tanpaext.enc", "dec").name, "tanpaext_decrypted")

    def test_large_file_does_not_grow_memory(self):
        import tracemalloc

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "besar.bin"
            with src.open("wb") as handle:
                for _ in range(5):
                    handle.write(bytes(CHUNK_SIZE))
            tracemalloc.start()
            encrypt_file(src, Path(tmp) / "besar.bin.enc", 7, 13)
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            # 20 MB file: pembacaan utuh per pass akan melewati 40 MB, streaming tetap ~30 MB
            self.assertLess(peak, 36 * 1024 * 1024)


class TestAvalanche(unittest.TestCase):
    def test_plaintext_avalanche_only_changes_first_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "a.txt"
            data = b"A" * 1000
            src.write_bytes(data)
            plain, _ = measure_avalanche(src, 7, 13)
            expected = bit_difference(
                encrypt_bytes(b"A", 7, 13),
                encrypt_bytes(bytes([0x41 ^ 0x01]), 7, 13),
            ) / (len(data) * 8) * 100
            self.assertAlmostEqual(plain, expected, places=6)
            self.assertAlmostEqual(plain, 0.0375, places=6)

    def test_key_avalanche_reasonable(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "b.bin"
            src.write_bytes(os.urandom(4096))
            _, key = measure_avalanche(src, 7, 13)
            self.assertGreater(key, 0.0)
            self.assertLessEqual(key, 100.0)

    def test_empty_file_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "kosong.bin"
            src.write_bytes(b"")
            self.assertEqual(measure_avalanche(src, 7, 13), (None, None))

    def test_encrypt_file_fills_avalanche(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "c.bin"
            src.write_bytes(os.urandom(8192))
            r = encrypt_file(src, Path(tmp) / "c.bin.enc", 7, 13)
            self.assertIsNotNone(r.avalanche_plain)
            self.assertIsNotNone(r.avalanche_key)


if __name__ == "__main__":
    unittest.main()
