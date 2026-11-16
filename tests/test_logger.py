import csv
import os
import tempfile
import unittest
from pathlib import Path

from logger import CSV_HEADER, ResultLog, now_stamp, plain_name_of

EXPECTED_HEADER = (
    "Timestamp",
    "Nama_File",
    "Ekstensi",
    "Ukuran_Asli_Byte",
    "Ukuran_Hasil_Byte",
    "Tambahan_Ukuran_Persen",
    "Kunci_a",
    "Kunci_b",
    "Operasi",
    "Waktu_Enkripsi_Detik",
    "Waktu_Dekripsi_Detik",
    "Throughput_Enkripsi_MBps",
    "Throughput_Dekripsi_MBps",
    "Entropi_Plainteks",
    "Entropi_Cipherteks",
    "Avalanche_Plainteks_Persen",
    "Avalanche_Kunci_Persen",
    "CPU_Usage_Enkripsi_Persen",
    "RAM_Usage_Enkripsi_MB",
    "CPU_Usage_Dekripsi_Persen",
    "RAM_Usage_Dekripsi_MB",
    "Hash_SHA256_Asli",
    "Hash_SHA256_Dekripsi",
    "Status_Hash_Cocok",
    "Catatan_Pengujian",
)


class TestHelpers(unittest.TestCase):
    def test_header_exact(self):
        self.assertEqual(CSV_HEADER, EXPECTED_HEADER)

    def test_plain_name_of(self):
        self.assertEqual(plain_name_of(Path("x/tugas.pdf.enc")), "tugas.pdf")
        self.assertEqual(plain_name_of(Path("x/tugas.pdf")), "tugas.pdf")

    def test_now_stamp_format(self):
        self.assertRegex(now_stamp(), r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")


class TestResultLog(unittest.TestCase):
    def test_creates_file_with_header_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "output" / "hasil.csv"
            log = ResultLog(path)
            log.add_trial({"Nama_File": "a.txt"})
            log.add_trial({"Nama_File": "b.txt"})
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(rows[0], list(CSV_HEADER))
            self.assertEqual(len(rows), 3)

    def test_missing_columns_are_dash(self):
        with tempfile.TemporaryDirectory() as tmp:
            ResultLog(Path(tmp) / "h.csv").add_trial({"Nama_File": "a.txt"})
            self.assertEqual(ResultLog(Path(tmp) / "h.csv").rows[0]["Status_Hash_Cocok"], "-")

    def test_reloads_existing_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hasil.csv"
            ResultLog(path).add_trial({"Nama_File": "a.txt"})
            self.assertEqual(len(ResultLog(path).rows), 1)

    def test_unicode_and_comma_names_survive_last_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hasil.csv"
            name = 'laporan, final "v2" ünï.pdf'
            log = ResultLog(path)
            log.add_trial({"Nama_File": name, "Catatan_Pengujian": "run 1, ünï"})
            row = ResultLog(path).rows[0]
            self.assertEqual(row["Nama_File"], name)
            self.assertEqual(row["Catatan_Pengujian"], "run 1, ünï")
            self.assertNotIn(b"\r\r\n", path.read_bytes())

    def test_update_persists_immediately(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hasil.csv"
            log = ResultLog(path)
            log.add_trial({"Nama_File": "a.txt"})
            log.add_trial({"Nama_File": "b.txt"})
            log.update(1, {"Status_Hash_Cocok": "COCOK"})
            reloaded = ResultLog(path)
            self.assertEqual(reloaded.rows[1]["Status_Hash_Cocok"], "COCOK")
            self.assertEqual(len(reloaded.rows), 2)

    def test_locked_file_records_error_and_resets_later(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hasil.csv"
            log = ResultLog(path)
            log.add_trial({"Nama_File": "a.txt"})
            original_replace = os.replace
            try:
                os.replace = lambda *args, **kwargs: (_ for _ in ()).throw(PermissionError("locked"))
                log.add_trial({"Nama_File": "b.txt"})
            finally:
                os.replace = original_replace
            self.assertIsNotNone(log.last_error)
            self.assertIn("Excel", log.last_error)
            log.add_trial({"Nama_File": "c.txt"})
            self.assertIsNone(log.last_error)


if __name__ == "__main__":
    unittest.main()
