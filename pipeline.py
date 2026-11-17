"""Orkestrasi pemrosesan file per potongan 4 MB beserta pengukuran metriknya."""

from __future__ import annotations

import os
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from affine_cipher import apply_table, build_decrypt_table, build_encrypt_table
from metrics import (
    Sha256Accumulator,
    bit_difference,
    cpu_percent,
    entropy_from_counts,
    ram_mb,
    throughput_mbps,
)

CHUNK_SIZE = 4 * 1024 * 1024

#: Callback progres: ``(nama_tahap, fraksi_progres_keseluruhan)`` dengan fraksi 0.0-1.0.
ProgressCallback = Callable[[str, float], None]

STAGE_TRANSFORM = "Membaca & mentransformasi potongan file"
STAGE_AVALANCHE = "Menghitung avalanche plainteks & kunci"
STAGE_DONE = "Selesai"

#: Porsi bilah progres untuk pass transformasi; sisanya untuk pass avalanche.
#: Pada file besar pass avalanche membaca file sekali lagi dengan dua tabel,
#: jadi bilah diberi ruang agar tidak terlihat berhenti di 75%.
TRANSFORM_SHARE = 0.75


@dataclass
class TransformResult:
    """Hasil satu operasi transformasi file."""

    plain_name: str
    plain_extension: str
    plain_size: int
    cipher_size: int
    transform_seconds: float
    throughput_mbps: float | None
    entropy_plain: float
    entropy_cipher: float
    avalanche_plain: float | None
    avalanche_key: float | None
    cpu_percent: float
    ram_mb: float
    hash_plain: str
    hash_cipher: str
    output_path: Path


def output_names(src: Path, mode: str) -> Path:
    """Path hasil operasi: ``<nama>.<ext>.enc`` atau ``<nama>_decrypted.<ext>``."""
    if mode == "enc":
        return src.with_name(src.name + ".enc")
    if mode == "dec":
        name = src.name[:-4] if src.name.lower().endswith(".enc") else src.name
        plain = Path(name)
        if plain.suffix:
            return src.with_name(f"{plain.stem}_decrypted{plain.suffix}")
        return src.with_name(f"{name}_decrypted")
    raise ValueError(f"Mode tidak dikenal: {mode}")


def _plain_identity(path: Path) -> tuple[str, str]:
    """Nama dan ekstensi sisi plainteks (akhiran ``.enc`` dilepas, ekstensi tanpa titik)."""
    name = path.name[:-4] if path.name.lower().endswith(".enc") else path.name
    suffix = Path(name).suffix
    return name, (suffix[1:] if suffix else "")


def _count_values(chunk: bytes) -> dict[int, int]:
    return Counter(chunk)


def _run(
    src: Path,
    dst: Path,
    table: bytes,
    progress: ProgressCallback | None,
    span: tuple[float, float] = (0.0, 1.0),
) -> tuple[int, int, float, int, float, str, str, float, float]:
    """Menjalankan transformasi streaming.

    ``span`` menentukan porsi bilah progres yang dipakai pass ini, sehingga
    tahap berikutnya (mis. avalanche) bisa melanjutkan dari posisi terakhir.

    Returns:
        (processed, output_size, seconds, entropy_input, entropy_output,
         hash_input, hash_output, cpu, ram)
    """
    span_start, span_end = span
    source_size = src.stat().st_size
    hash_in = Sha256Accumulator()
    hash_out = Sha256Accumulator()
    counts_in = [0] * 256
    counts_out = [0] * 256
    processed = 0
    seconds = 0.0

    dst.parent.mkdir(parents=True, exist_ok=True)
    # Tulis ke file sementara agar kegagalan di tengah jalan tidak meninggalkan
    # file hasil setengah jadi yang namanya terlihat sah.
    temporary = dst.with_name(dst.name + ".part")
    cpu_percent()  # memulai interval CPU; nilainya tidak dipakai

    try:
        with open(src, "rb") as handle_in, open(temporary, "wb") as handle_out:
            while True:
                chunk = handle_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                started = time.perf_counter()
                transformed = apply_table(chunk, table)
                seconds += time.perf_counter() - started

                hash_in.update(chunk)
                hash_out.update(transformed)
                # Satu pass Counter saja: frekuensi keluaran diturunkan lewat tabel
                # karena substitusi bersifat satu-ke-satu.
                for value, count in _count_values(chunk).items():
                    counts_in[value] += count
                    counts_out[table[value]] += count

                handle_out.write(transformed)
                processed += len(chunk)
                if progress is not None and source_size:
                    fraction = span_start + (span_end - span_start) * processed / source_size
                    progress(STAGE_TRANSFORM, fraction)
        os.replace(temporary, dst)
    except BaseException:
        try:
            if temporary.exists():
                temporary.unlink()
        except OSError:
            pass
        raise

    if progress is not None:
        progress(STAGE_TRANSFORM, span_end)

    return (
        processed,
        dst.stat().st_size,
        seconds,
        entropy_from_counts(counts_in),
        entropy_from_counts(counts_out),
        hash_in.hexdigest(),
        hash_out.hexdigest(),
        cpu_percent(),
        ram_mb(),
    )


def measure_avalanche(
    src: Path,
    a: int,
    b: int,
    progress: Callable[[float], None] | None = None,
) -> tuple[float | None, float | None]:
    """Menghitung avalanche plainteks dan kunci dalam persen (streaming).

    Pass plainteks: byte pertama di-XOR 0x01. Pass kunci: ``b' = b ^ 0x01``.
    Kedua pass tidak masuk hitungan ``transform_seconds``. Bila ``progress``
    diberikan, ia menerima fraksi 0.0-1.0 khusus pass ini.
    """
    source_size = src.stat().st_size
    if source_size == 0:
        return (None, None)

    table = build_encrypt_table(a, b)
    key_table = build_encrypt_table(a, b ^ 0x01)
    diff_plain = 0
    diff_key = 0
    first_chunk = True
    processed = 0

    with open(src, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            if first_chunk:
                flipped = bytes((chunk[0] ^ 0x01,)) + chunk[1:]
                first_chunk = False
            else:
                flipped = chunk
            original = apply_table(chunk, table)
            diff_plain += bit_difference(original, apply_table(flipped, table))
            diff_key += bit_difference(original, apply_table(chunk, key_table))
            processed += len(chunk)
            if progress is not None:
                progress(processed / source_size)

    total_bits = source_size * 8
    return (diff_plain / total_bits * 100, diff_key / total_bits * 100)


def encrypt_file(
    src: Path,
    dst: Path,
    a: int,
    b: int,
    progress: ProgressCallback | None = None,
) -> TransformResult:
    """Mengenkripsi ``src`` ke ``dst`` per potongan dan mengembalikan metriknya."""
    table = build_encrypt_table(a, b)

    def avalanche_progress(fraction: float) -> None:
        assert progress is not None
        progress(STAGE_AVALANCHE, TRANSFORM_SHARE + (1.0 - TRANSFORM_SHARE) * fraction)

    plain_size, cipher_size, seconds, entropy_plain, entropy_cipher, hash_plain, hash_cipher, cpu, ram = _run(
        src, dst, table, progress, span=(0.0, TRANSFORM_SHARE)
    )
    avalanche_plain, avalanche_key = measure_avalanche(
        src, a, b, progress=avalanche_progress if progress is not None else None
    )
    if progress is not None:
        progress(STAGE_DONE, 1.0)

    plain_name, plain_extension = _plain_identity(src)
    return TransformResult(
        plain_name=plain_name,
        plain_extension=plain_extension,
        plain_size=plain_size,
        cipher_size=cipher_size,
        transform_seconds=seconds,
        throughput_mbps=throughput_mbps(plain_size, seconds),
        entropy_plain=entropy_plain,
        entropy_cipher=entropy_cipher,
        avalanche_plain=avalanche_plain,
        avalanche_key=avalanche_key,
        cpu_percent=cpu,
        ram_mb=ram,
        hash_plain=hash_plain,
        hash_cipher=hash_cipher,
        output_path=dst,
    )


def decrypt_file(
    src: Path,
    dst: Path,
    a: int,
    b: int,
    progress: ProgressCallback | None = None,
) -> TransformResult:
    """Mendekripsi ``src`` ke ``dst`` per potongan dan mengembalikan metriknya."""
    table = build_decrypt_table(a, b)
    cipher_size, plain_size, seconds, entropy_cipher, entropy_plain, hash_cipher, hash_plain, cpu, ram = _run(
        src, dst, table, progress
    )
    if progress is not None:
        progress(STAGE_DONE, 1.0)

    plain_name, plain_extension = _plain_identity(src)
    return TransformResult(
        plain_name=plain_name,
        plain_extension=plain_extension,
        plain_size=plain_size,
        cipher_size=cipher_size,
        transform_seconds=seconds,
        throughput_mbps=throughput_mbps(plain_size, seconds),
        entropy_plain=entropy_plain,
        entropy_cipher=entropy_cipher,
        avalanche_plain=None,
        avalanche_key=None,
        cpu_percent=cpu,
        ram_mb=ram,
        hash_plain=hash_plain,
        hash_cipher=hash_cipher,
        output_path=dst,
    )
