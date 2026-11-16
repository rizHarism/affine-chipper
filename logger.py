"""Pencatatan hasil pengujian ke satu file CSV (satu baris per percobaan)."""

from __future__ import annotations

import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Mapping

CSV_HEADER: tuple[str, ...] = (
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


def plain_name_of(path: Path) -> str:
    """Nama file dengan akhiran ``.enc`` dilepas."""
    return path.name[:-4] if path.name.lower().endswith(".enc") else path.name


def now_stamp() -> str:
    """Waktu lokal pada format ``YYYY-MM-DD HH:MM:SS``."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def empty_cell(value: object, decimals: int | None = None) -> str:
    """Nilai siap-tulis CSV: ``-`` bila kosong, atau angka dengan jumlah desimal tertentu."""
    if value is None or value == "":
        return "-"
    if decimals is None:
        return str(value)
    if isinstance(value, str):
        return value
    return f"{float(value):.{decimals}f}"


class ResultLog:
    """Pengelola ``hasil_pengujian.csv``: baca saat start, tulis atomik saat berubah."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.rows: list[dict[str, str]] = []
        self.last_error: str | None = None
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8-sig", newline="") as handle:
            for raw in csv.DictReader(handle):
                self.rows.append(
                    {column: (raw.get(column) or "-") for column in CSV_HEADER}
                )

    def save(self) -> None:
        self.last_error = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + ".tmp")
        try:
            with temporary.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=CSV_HEADER)
                writer.writeheader()
                writer.writerows(self.rows)
            os.replace(temporary, self.path)
        except OSError:
            self.last_error = "Gagal menulis CSV, tutup file di Excel lalu coba lagi."
        finally:
            if temporary.exists():
                try:
                    temporary.unlink()
                except OSError:
                    pass

    def add_trial(self, values: Mapping[str, object]) -> int:
        """Menambah satu baris percobaan baru dan langsung menyimpannya."""
        row = {column: "-" for column in CSV_HEADER}
        for key, value in values.items():
            if key in row:
                row[key] = empty_cell(value)
        self.rows.append(row)
        index = len(self.rows) - 1
        self.save()
        return index

    def update(self, row: int, values: Mapping[str, object]) -> None:
        """Memperbarui satu baris dan langsung menyimpannya."""
        target = self.rows[row]
        for key, value in values.items():
            if key in target:
                target[key] = empty_cell(value)
        self.save()
