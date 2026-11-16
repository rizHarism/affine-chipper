"""Affine Cipher mode byte.

Mengoperasikan rumus affine langsung pada nilai byte (0..255):

    enkripsi: C = (a * P + b) mod 256
    dekripsi: P = a^-1 * (C - b) mod 256

Kunci ``a`` wajib ganjil agar memiliki invers modulo 256.
"""

from __future__ import annotations

MODULUS = 256


def mod_inverse(a: int, m: int = MODULUS) -> int:
    """Menghitung balikan perkalian ``a`` modulo ``m`` (Extended Euclidean).

    Raises:
        ValueError: bila ``gcd(a, m) != 1`` sehingga balikan tidak ada.
    """
    a %= m
    old_r, r = a, m
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        raise ValueError(
            f"Kunci a={a} tidak punya invers modulo {m} karena gcd(a, {m}) != 1. "
            "Kunci a harus ganjil."
        )
    return old_s % m


def validate_keys(a: int, b: int) -> tuple[bool, str]:
    """Memeriksa keabsahan pasangan kunci.

    Returns:
        ``(True, "")`` bila valid, selain itu ``(False, pesan)`` berbahasa Indonesia.
    """
    if isinstance(a, bool) or isinstance(b, bool) or not isinstance(a, int) or not isinstance(b, int):
        return False, "Kunci harus berupa angka bulat."
    if a % 2 == 0:
        return False, f"Kunci a={a} harus ganjil agar punya invers modulo 256."
    if not 1 <= a <= 255:
        return False, f"Kunci a={a} di luar rentang 1-255."
    if not 0 <= b <= 255:
        return False, f"Kunci b={b} di luar rentang 0-255."
    return True, ""


def _require_valid_keys(a: int, b: int) -> None:
    ok, message = validate_keys(a, b)
    if not ok:
        raise ValueError(message)


def build_encrypt_table(a: int, b: int) -> bytes:
    """Tabel substitusi 256 entri: ``table[p] = (a*p + b) mod 256``."""
    _require_valid_keys(a, b)
    return bytes((a * p + b) % MODULUS for p in range(MODULUS))


def build_decrypt_table(a: int, b: int) -> bytes:
    """Tabel invers: ``table[c] = a^-1 * (c - b) mod 256``."""
    _require_valid_keys(a, b)
    inverse = mod_inverse(a, MODULUS)
    return bytes((inverse * (c - b)) % MODULUS for c in range(MODULUS))


def apply_table(data: bytes, table: bytes) -> bytes:
    """Menerapkan tabel substitusi 256 entri pada data (dieksekusi di C)."""
    return data.translate(table)


def encrypt_bytes(data: bytes, a: int, b: int) -> bytes:
    """Enkripsi byte dengan tabel rumus affine."""
    return apply_table(data, build_encrypt_table(a, b))


def decrypt_bytes(data: bytes, a: int, b: int) -> bytes:
    """Dekripsi byte dengan tabel invers affine."""
    return apply_table(data, build_decrypt_table(a, b))


def encrypt_reference(data: bytes, a: int, b: int) -> bytes:
    """Implementasi referensi: loop per byte, langsung dari rumus."""
    _require_valid_keys(a, b)
    return bytes((a * p + b) % MODULUS for p in data)


def decrypt_reference(data: bytes, a: int, b: int) -> bytes:
    """Implementasi referensi: loop per byte dengan balikan modular."""
    _require_valid_keys(a, b)
    inverse = mod_inverse(a, MODULUS)
    return bytes((inverse * (c - b)) % MODULUS for c in data)
