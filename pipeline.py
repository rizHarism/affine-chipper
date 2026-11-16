"""Orkestrasi pemrosesan file per potongan 4 MB beserta pengukuran metriknya."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from affine_cipher import apply_table, build_decrypt_table, build_encrypt_table
from metrics import (
    Sha256Accumulator,
    cpu_percent,
    entropy_from_counts,
    ram_mb,
    throughput_mbps,
)

CHUNK_SIZE = 4 * 1024 * 1024


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
    progress: Callable[[float], None] | None,
) -> tuple[int, int, float, int, float, str, str, float, float]:
    """Menjalankan transformasi streaming.

    Returns:
        (processed, output_size, seconds, entropy_input, entropy_output,
         hash_input, hash_output, cpu, ram)
    """
    source_size = src.stat().st_size
    hash_in = Sha256Accumulator()
    hash_out = Sha256Accumulator()
    counts_in = [0] * 256
    counts_out = [0] * 256
    processed = 0
    seconds = 0.0

    dst.parent.mkdir(parents=True, exist_ok=True)
    cpu_percent()  # memulai interval CPU; nilainya tidak dipakai

    with open(src, "rb") as handle_in, open(dst, "wb") as handle_out:
        while True:
            chunk = handle_in.read(CHUNK_SIZE)
            if not chunk:
                break
            started = time.perf_counter()
            transformed = apply_table(chunk, table)
            seconds += time.perf_counter() - started

            hash_in.update(chunk)
            hash_out.update(transformed)
            for value, count in _count_values(chunk).items():
                counts_in[value] += count
            for value, count in _count_values(transformed).items():
                counts_out[value] += count

            handle_out.write(transformed)
            processed += len(chunk)
            if progress is not None and source_size:
                progress(processed / source_size)

    if progress is not None:
        progress(1.0)

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


def encrypt_file(
    src: Path,
    dst: Path,
    a: int,
    b: int,
    progress: Callable[[float], None] | None = None,
) -> TransformResult:
    """Mengenkripsi ``src`` ke ``dst`` per potongan dan mengembalikan metriknya."""
    table = build_encrypt_table(a, b)
    plain_size, cipher_size, seconds, entropy_plain, entropy_cipher, hash_plain, hash_cipher, cpu, ram = _run(
        src, dst, table, progress
    )
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


def decrypt_file(
    src: Path,
    dst: Path,
    a: int,
    b: int,
    progress: Callable[[float], None] | None = None,
) -> TransformResult:
    """Mendekripsi ``src`` ke ``dst`` per potongan dan mengembalikan metriknya."""
    table = build_decrypt_table(a, b)
    cipher_size, plain_size, seconds, entropy_cipher, entropy_plain, hash_cipher, hash_plain, cpu, ram = _run(
        src, dst, table, progress
    )
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
