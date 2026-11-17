"""Pencatatan hasil pengujian ke satu file CSV (satu baris per percobaan)."""

from __future__ import annotations

import csv
import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Mapping

if TYPE_CHECKING:
    from pipeline import TransformResult

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
        self.notice: str | None = None
        self._load()

    def _backup_unreadable(self) -> Path:
        """Memindahkan CSV yang tidak bisa dibaca agar tidak tertimpa data baru."""
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = self.path.with_name(f"{self.path.name}.rusak-{stamp}")
        try:
            os.replace(self.path, backup)
        except OSError:
            return self.path
        return backup

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            with self.path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                fieldnames = reader.fieldnames or []
                if tuple(fieldnames) != CSV_HEADER:
                    raise ValueError("header CSV tidak sesuai")
                for raw in reader:
                    self.rows.append(
                        {column: (raw.get(column) or "-") for column in CSV_HEADER}
                    )
        except (UnicodeDecodeError, ValueError):
            self.rows.clear()
            backup = self._backup_unreadable()
            self.notice = (
                f"File CSV lama tidak dapat dibaca dan telah dipindahkan ke '{backup.name}'. "
                "Pengujian baru akan memakai file CSV yang bersih."
            )

    def save(self) -> None:
        self.last_error = None
        temporary = self.path.with_name(self.path.name + ".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
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

    def find_for_decryption(self, decrypted_hash: str, a: int, b: int) -> int | None:
        """Baris percobaan yang cocok untuk diisi hasil dekripsi (hash asli + kunci sama)."""
        for index, row in enumerate(self.rows):
            if (
                row["Hash_SHA256_Asli"] == decrypted_hash
                and row["Kunci_a"] == str(a)
                and row["Kunci_b"] == str(b)
                and row["Hash_SHA256_Dekripsi"] == "-"
            ):
                return index
        return None

    def find_for_verification(self, decrypted_hash: str) -> int | None:
        """Baris percobaan yang cocok menerima status verifikasi.

        Hanya baris yang kolom ``Hash_SHA256_Dekripsi``-nya sama dengan file yang
        diperiksa yang boleh menerima status. Pencocokan berbasis hash asli sengaja
        tidak dipakai: file yang hash-nya tidak tercatat sebagai hasil dekripsi mana
        pun tidak boleh menodai baris percobaan lain.
        """
        for index, row in enumerate(self.rows):
            if (
                row["Hash_SHA256_Dekripsi"] == decrypted_hash
                and row["Status_Hash_Cocok"] == "-"
            ):
                return index
        return None


def _size_addition_percent(plain_size: int, cipher_size: int) -> str:
    if not plain_size:
        return "-"
    return f"{(cipher_size - plain_size) / plain_size * 100:.2f}"


def _merge_note(previous: str, addition: str) -> str:
    """Menggabungkan catatan lama dan baru dengan ``"; "`` tanpa mengulang isi sama."""
    previous = (previous or "").strip()
    addition = (addition or "").strip()
    if previous in ("", "-"):
        return addition or "-"
    if not addition or addition == previous or addition in previous.split("; "):
        return previous
    return f"{previous}; {addition}"


def build_encrypt_row(
    result: "TransformResult",
    a: int,
    b: int,
    stamp: str,
    note: str,
) -> dict[str, str]:
    """Baris lengkap untuk percobaan enkripsi (kolom dekripsi berisi ``-``)."""
    row = {column: "-" for column in CSV_HEADER}
    row.update(
        {
            "Timestamp": stamp,
            "Nama_File": result.plain_name,
            "Ekstensi": result.plain_extension,
            "Ukuran_Asli_Byte": str(result.plain_size),
            "Ukuran_Hasil_Byte": str(result.cipher_size),
            "Tambahan_Ukuran_Persen": _size_addition_percent(result.plain_size, result.cipher_size),
            "Kunci_a": str(a),
            "Kunci_b": str(b),
            "Operasi": "Enkripsi",
            "Waktu_Enkripsi_Detik": empty_cell(result.elapsed_seconds, 6),
            "Throughput_Enkripsi_MBps": empty_cell(result.throughput_mbps, 2),
            "Entropi_Plainteks": empty_cell(result.entropy_plain, 4),
            "Entropi_Cipherteks": empty_cell(result.entropy_cipher, 4),
            "Avalanche_Plainteks_Persen": empty_cell(result.avalanche_plain, 4),
            "Avalanche_Kunci_Persen": empty_cell(result.avalanche_key, 4),
            "CPU_Usage_Enkripsi_Persen": empty_cell(result.cpu_percent, 2),
            "RAM_Usage_Enkripsi_MB": empty_cell(result.ram_mb, 2),
            "Hash_SHA256_Asli": result.hash_plain,
            "Catatan_Pengujian": note or "-",
        }
    )
    return row


def build_decrypt_update(
    result: "TransformResult",
    a: int,
    b: int,
    note: str,
    previous_note: str = "-",
) -> dict[str, str]:
    """Kolom yang diperbarui pada baris percobaan saat dekripsi berhasil dipasangkan."""
    update = {
        "Operasi": "Enkripsi+Dekripsi",
        "Waktu_Dekripsi_Detik": empty_cell(result.elapsed_seconds, 6),
        "Throughput_Dekripsi_MBps": empty_cell(result.throughput_mbps, 2),
        "CPU_Usage_Dekripsi_Persen": empty_cell(result.cpu_percent, 2),
        "RAM_Usage_Dekripsi_MB": empty_cell(result.ram_mb, 2),
        "Hash_SHA256_Dekripsi": result.hash_plain,
    }
    if note:
        update["Catatan_Pengujian"] = _merge_note(previous_note, note)
    return update


def build_standalone_decrypt_row(
    result: "TransformResult",
    a: int,
    b: int,
    stamp: str,
    note: str,
) -> dict[str, str]:
    """Baris lengkap untuk dekripsi yang tidak punya pasangan enkripsi (mis. kunci salah)."""
    row = {column: "-" for column in CSV_HEADER}
    row.update(
        {
            "Timestamp": stamp,
            "Nama_File": result.plain_name,
            "Ekstensi": result.plain_extension,
            "Ukuran_Asli_Byte": str(result.plain_size),
            "Ukuran_Hasil_Byte": str(result.cipher_size),
            "Tambahan_Ukuran_Persen": _size_addition_percent(result.plain_size, result.cipher_size),
            "Kunci_a": str(a),
            "Kunci_b": str(b),
            "Operasi": "Dekripsi",
            "Waktu_Dekripsi_Detik": empty_cell(result.elapsed_seconds, 6),
            "Throughput_Dekripsi_MBps": empty_cell(result.throughput_mbps, 2),
            "Entropi_Plainteks": empty_cell(result.entropy_plain, 4),
            "Entropi_Cipherteks": empty_cell(result.entropy_cipher, 4),
            "CPU_Usage_Dekripsi_Persen": empty_cell(result.cpu_percent, 2),
            "RAM_Usage_Dekripsi_MB": empty_cell(result.ram_mb, 2),
            "Hash_SHA256_Asli": "-",
            "Hash_SHA256_Dekripsi": result.hash_plain,
            "Catatan_Pengujian": note or "-",
        }
    )
    return row


def build_verify_update(
    row: Mapping[str, str],
    status: str,
    method_note: str,
) -> dict[str, str]:
    """Kolom yang diperbarui saat verifikasi menempel pada sebuah baris percobaan."""
    current_stage = row.get("Operasi", "")
    if current_stage.startswith("Enkripsi"):
        stage = "Enkripsi+Dekripsi+Verifikasi"
    elif current_stage.startswith("Dekripsi"):
        stage = "Dekripsi+Verifikasi"
    else:
        stage = current_stage

    previous_note = row.get("Catatan_Pengujian", "-")
    return {
        "Operasi": stage,
        "Status_Hash_Cocok": status,
        "Catatan_Pengujian": _merge_note(previous_note, method_note),
    }
