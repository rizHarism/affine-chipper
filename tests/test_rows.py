import unittest
from dataclasses import replace
from pathlib import Path

from logger import (
    build_decrypt_update,
    build_encrypt_row,
    build_standalone_decrypt_row,
    build_verify_update,
)
from pipeline import TransformResult


def make_result(**overrides):
    base = TransformResult(
        plain_name="tugas.pdf",
        plain_extension="pdf",
        plain_size=1048576,
        cipher_size=1048576,
        transform_seconds=0.001953125,
        throughput_mbps=512.0,
        entropy_plain=7.5,
        entropy_cipher=7.5,
        avalanche_plain=0.0375,
        avalanche_key=19.25,
        cpu_percent=12.5,
        ram_mb=64.5,
        hash_plain="h-plain",
        hash_cipher="h-cipher",
        output_path=Path("C:/x/tugas.pdf.enc"),
    )
    return replace(base, **overrides)


class TestEncryptRow(unittest.TestCase):
    def test_formats_and_stage(self):
        row = build_encrypt_row(make_result(), 7, 13, "2026-11-16 10:00:00", "run 1/3")
        self.assertEqual(row["Operasi"], "Enkripsi")
        self.assertEqual(row["Kunci_a"], "7")
        self.assertEqual(row["Kunci_b"], "13")
        self.assertEqual(row["Nama_File"], "tugas.pdf")
        self.assertEqual(row["Ekstensi"], "pdf")
        self.assertEqual(row["Ukuran_Asli_Byte"], "1048576")
        self.assertEqual(row["Tambahan_Ukuran_Persen"], "0.00")
        self.assertEqual(row["Waktu_Enkripsi_Detik"], "0.001953")
        self.assertEqual(row["Throughput_Enkripsi_MBps"], "512.00")
        self.assertEqual(row["Entropi_Plainteks"], "7.5000")
        self.assertEqual(row["Avalanche_Kunci_Persen"], "19.2500")
        self.assertEqual(row["CPU_Usage_Enkripsi_Persen"], "12.50")
        self.assertEqual(row["RAM_Usage_Enkripsi_MB"], "64.50")
        self.assertEqual(row["Hash_SHA256_Asli"], "h-plain")
        self.assertEqual(row["Catatan_Pengujian"], "run 1/3")
        self.assertEqual(row["Waktu_Dekripsi_Detik"], "-")
        self.assertEqual(row["Hash_SHA256_Dekripsi"], "-")
        self.assertEqual(row["Status_Hash_Cocok"], "-")

    def test_zero_size_uses_dash(self):
        row = build_encrypt_row(make_result(plain_size=0, throughput_mbps=None), 7, 13, "s", "")
        self.assertEqual(row["Tambahan_Ukuran_Persen"], "-")
        self.assertEqual(row["Throughput_Enkripsi_MBps"], "-")
        self.assertEqual(row["Catatan_Pengujian"], "-")


class TestDecryptRows(unittest.TestCase):
    def test_decrypt_update_only_touches_decryption_columns(self):
        update = build_decrypt_update(make_result(), 7, 13, "")
        allowed = {
            "Operasi",
            "Waktu_Dekripsi_Detik",
            "Throughput_Dekripsi_MBps",
            "CPU_Usage_Dekripsi_Persen",
            "RAM_Usage_Dekripsi_MB",
            "Hash_SHA256_Dekripsi",
            "Catatan_Pengujian",
        }
        self.assertLessEqual(set(update), allowed)
        self.assertEqual(update["Operasi"], "Enkripsi+Dekripsi")
        self.assertEqual(update["Hash_SHA256_Dekripsi"], "h-plain")
        self.assertEqual(update["Waktu_Dekripsi_Detik"], "0.001953")
        self.assertNotIn("Catatan_Pengujian", update)

    def test_decrypt_update_keeps_note_when_given(self):
        update = build_decrypt_update(make_result(), 7, 13, "kunci benar")
        self.assertEqual(update["Catatan_Pengujian"], "kunci benar")

    def test_standalone_row(self):
        row = build_standalone_decrypt_row(
            make_result(avalanche_plain=None, avalanche_key=None),
            7,
            14,
            "2026-11-16 10:05:00",
            "kunci salah",
        )
        self.assertEqual(row["Operasi"], "Dekripsi")
        self.assertEqual(row["Hash_SHA256_Asli"], "-")
        self.assertEqual(row["Hash_SHA256_Dekripsi"], "h-plain")
        self.assertEqual(row["Waktu_Enkripsi_Detik"], "-")
        self.assertEqual(row["Waktu_Dekripsi_Detik"], "0.001953")
        self.assertEqual(row["Avalanche_Plainteks_Persen"], "-")
        self.assertEqual(row["Catatan_Pengujian"], "kunci salah")


class TestVerifyUpdate(unittest.TestCase):
    def test_advances_stage_and_merges_note(self):
        row = {"Operasi": "Enkripsi+Dekripsi", "Catatan_Pengujian": "run 1/3"}
        update = build_verify_update(row, "COCOK", "banding hash manual")
        self.assertEqual(update["Operasi"], "Enkripsi+Dekripsi+Verifikasi")
        self.assertEqual(update["Status_Hash_Cocok"], "COCOK")
        self.assertEqual(update["Catatan_Pengujian"], "run 1/3; banding hash manual")

    def test_standalone_decrypt_row(self):
        row = {"Operasi": "Dekripsi", "Catatan_Pengujian": "-"}
        update = build_verify_update(row, "TIDAK_COCOK", "banding dua file")
        self.assertEqual(update["Operasi"], "Dekripsi+Verifikasi")
        self.assertEqual(update["Status_Hash_Cocok"], "TIDAK_COCOK")
        self.assertEqual(update["Catatan_Pengujian"], "banding dua file")


if __name__ == "__main__":
    unittest.main()
