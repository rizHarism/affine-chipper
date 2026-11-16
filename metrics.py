"""Metrik pengukuran: hash SHA-256, entropi Shannon, avalanche, throughput, CPU/RAM."""

from __future__ import annotations

import hashlib
import math
import operator
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import psutil

from affine_cipher import encrypt_bytes

CHUNK_SIZE = 4 * 1024 * 1024
_PROCESS = psutil.Process()


def sha256_bytes(data: bytes) -> str:
    """Hash SHA-256 dari sekumpulan byte, dalam bentuk hex huruf kecil."""
    return hashlib.sha256(data).hexdigest()


#: Alias sesuai penamaan pada spesifikasi tugas.
compute_sha256 = sha256_bytes


class Sha256Accumulator:
    """Hash SHA-256 inkremental untuk pemrosesan per potongan."""

    def __init__(self) -> None:
        self._hash = hashlib.sha256()

    def update(self, data: bytes) -> None:
        self._hash.update(data)

    def hexdigest(self) -> str:
        return self._hash.hexdigest()


def sha256_file(path: Path, chunk_size: int = CHUNK_SIZE) -> str:
    """Hash SHA-256 sebuah file tanpa memuat seluruh isinya ke memori."""
    accumulator = Sha256Accumulator()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            accumulator.update(chunk)
    return accumulator.hexdigest()


def entropy_from_counts(counts: Sequence[int]) -> float:
    """Entropi Shannon (bit per byte) dari hitungan frekuensi nilai byte."""
    total = sum(counts)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy


def calculate_entropy(data: bytes) -> float:
    """Entropi Shannon data di memori (dipakai untuk keperluan uji/verifikasi)."""
    counts = [0] * 256
    for value, count in Counter(data).items():
        counts[value] = count
    return entropy_from_counts(counts)


def bit_difference(a: bytes, b: bytes) -> int:
    """Jumlah bit berbeda (Hamming distance) antara dua data berukuran sama."""
    if len(a) != len(b):
        raise ValueError("Perbandingan bit membutuhkan dua data dengan panjang sama.")
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).bit_count()


def avalanche_percent(diff_bits: int, total_bits: int) -> float | None:
    """Persentase bit berbeda; ``None`` bila tidak ada bit yang dibandingkan."""
    if total_bits <= 0:
        return None
    return diff_bits / total_bits * 100


def calculate_avalanche_plaintext(original_data: bytes, a: int, b: int) -> float | None:
    """Avalanche plainteks di memori: byte pertama di-XOR ``0x01`` lalu dienkripsi ulang.

    Versi referensi; aplikasi memakai ``pipeline.measure_avalanche`` yang streaming.
    """
    if not original_data:
        return None
    flipped = bytes((original_data[0] ^ 0x01,)) + original_data[1:]
    difference = bit_difference(
        encrypt_bytes(original_data, a, b), encrypt_bytes(flipped, a, b)
    )
    return avalanche_percent(difference, len(original_data) * 8)


def calculate_avalanche_key(original_data: bytes, a: int, b: int) -> float | None:
    """Avalanche kunci di memori: ``b`` diubah tepat satu bit (``b ^ 0x01``).

    Versi referensi; aplikasi memakai ``pipeline.measure_avalanche`` yang streaming.
    """
    if not original_data:
        return None
    difference = bit_difference(
        encrypt_bytes(original_data, a, b), encrypt_bytes(original_data, a, b ^ 0x01)
    )
    return avalanche_percent(difference, len(original_data) * 8)


def throughput_mbps(size_bytes: int, seconds: float) -> float | None:
    """Throughput dalam MB/s (1 MB = 1024 x 1024 byte); ``None`` bila tak terdefinisi."""
    if size_bytes <= 0 or seconds <= 0:
        return None
    return (size_bytes / (1024 * 1024)) / seconds


def prime_cpu_percent() -> None:
    """Memulai pengukuran interval CPU agar pembacaan pertama tidak bernilai 0."""
    psutil.cpu_percent(interval=None)


def cpu_percent() -> float:
    """Pemakaian CPU (system-wide) sejak pembacaan sebelumnya, dalam persen."""
    return psutil.cpu_percent(interval=None)


def ram_mb() -> float:
    """RSS proses aplikasi dalam MB."""
    return _PROCESS.memory_info().rss / (1024 * 1024)


def is_valid_sha256_hex(text: str) -> bool:
    """True bila teks berupa hash SHA-256 hex sepanjang 64 karakter."""
    if len(text) != 64:
        return False
    return all(character in "0123456789abcdefABCDEF" for character in text)


@dataclass
class FileComparison:
    """Hasil perbandingan dua file."""

    hash_a: str
    hash_b: str
    hash_match: bool
    differing_bytes: int
    first_difference_offset: int | None


def compare_files(
    path_a: Path,
    path_b: Path,
    chunk_size: int = CHUNK_SIZE,
) -> FileComparison:
    """Membandingkan dua file per potongan: hash, jumlah byte berbeda, offset pertama."""
    accumulator_a = Sha256Accumulator()
    accumulator_b = Sha256Accumulator()
    differing = 0
    first_offset: int | None = None
    offset = 0

    with open(path_a, "rb") as file_a, open(path_b, "rb") as file_b:
        while True:
            chunk_a = file_a.read(chunk_size)
            chunk_b = file_b.read(chunk_size)
            if not chunk_a and not chunk_b:
                break
            accumulator_a.update(chunk_a)
            accumulator_b.update(chunk_b)
            if chunk_a != chunk_b:
                shared = min(len(chunk_a), len(chunk_b))
                shared_a = chunk_a[:shared]
                shared_b = chunk_b[:shared]
                differing += sum(map(operator.ne, shared_a, shared_b))
                if first_offset is None:
                    index = next(
                        (i for i, (x, y) in enumerate(zip(shared_a, shared_b)) if x != y),
                        None,
                    )
                    first_offset = offset + (index if index is not None else shared)
                if len(chunk_a) != len(chunk_b):
                    differing += abs(len(chunk_a) - len(chunk_b))
            offset += max(len(chunk_a), len(chunk_b))

    hash_a = accumulator_a.hexdigest()
    hash_b = accumulator_b.hexdigest()
    return FileComparison(
        hash_a=hash_a,
        hash_b=hash_b,
        hash_match=hash_a == hash_b,
        differing_bytes=differing,
        first_difference_offset=first_offset,
    )
