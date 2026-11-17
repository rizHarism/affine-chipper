"""Aplikasi desktop Affine Cipher mode byte.

GUI Tkinter dengan tiga tab: Enkripsi, Dekripsi, dan Cek Kesamaan File.
Semua pemrosesan file berjalan di thread terpisah agar UI tetap responsif.
"""

from __future__ import annotations

import queue
import sys
import threading
import tkinter as tk
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import metrics
import pipeline
from affine_cipher import validate_keys
from logger import (
    ResultLog,
    build_decrypt_update,
    build_encrypt_row,
    build_standalone_decrypt_row,
    build_verify_update,
    now_stamp,
)
from pipeline import TransformResult

APP_TITLE = "Affine Cipher — Enkripsi & Dekripsi File"
DEFAULT_A = "7"
DEFAULT_B = "13"
TIME_HINT = (
    "Waktu & throughput yang dicatat hanya menghitung pass transformasi byte "
    "murni (tanpa baca/tulis disk, hash, entropi, dan avalanche)."
)

ENCRYPT_FIELDS: tuple[tuple[str, str], ...] = (
    ("waktu", "Waktu enkripsi (detik, algoritma)"),
    ("throughput", "Throughput (MB/s, algoritma)"),
    ("entropi_plain", "Entropi plainteks"),
    ("entropi_cipher", "Entropi cipherteks"),
    ("avalanche_plain", "Avalanche plainteks (%)"),
    ("avalanche_key", "Avalanche kunci (%)"),
    ("cpu", "CPU (persen)"),
    ("ram", "RAM (MB)"),
    ("ukuran_asli", "Ukuran asli (byte)"),
    ("ukuran_hasil", "Ukuran hasil (byte)"),
    ("output", "File hasil"),
    ("hash", "Hash SHA-256 asli"),
)

DECRYPT_FIELDS: tuple[tuple[str, str], ...] = (
    ("waktu", "Waktu dekripsi (detik, algoritma)"),
    ("throughput", "Throughput (MB/s, algoritma)"),
    ("entropi_cipher", "Entropi cipherteks"),
    ("entropi_plain", "Entropi plainteks"),
    ("cpu", "CPU (persen)"),
    ("ram", "RAM (MB)"),
    ("ukuran_asli", "Ukuran cipherteks (byte)"),
    ("ukuran_hasil", "Ukuran hasil (byte)"),
    ("output", "File hasil"),
    ("hash", "Hash SHA-256 hasil"),
)


def app_dir() -> Path:
    """Folder aplikasi, termasuk saat dibungkus PyInstaller ``--onefile``."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def format_size(size: int) -> str:
    """Ukuran byte dalam bentuk yang mudah dibaca (B/KB/MB/GB)."""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{int(value)} B" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024
    return f"{size} B"


def describe_error(path: Path, error: Exception) -> str:
    """Pesan kesalahan berbahasa Indonesia untuk masalah file yang umum."""
    filename = getattr(error, "filename", None)
    target = Path(filename) if filename else path
    if isinstance(error, PermissionError):
        return (
            f"Tidak punya izin mengakses '{target.name}'. "
            "Tutup file bila sedang dibuka aplikasi lain, atau periksa izin folder tujuan, "
            "lalu coba lagi."
        )
    if isinstance(error, FileNotFoundError):
        return f"File tidak ditemukan: {path}"
    if isinstance(error, ValueError):
        return str(error)
    if isinstance(error, OSError):
        if error.errno == 28:  # ENOSPC
            return "Ruang disk penuh. Kosongkan sebagian disk lalu coba lagi."
        detail = error.strerror or str(error)
        return f"Operasi file gagal pada '{target.name}': {detail}"
    return f"Terjadi kesalahan tak terduga: {error}"


class TransformWorker(threading.Thread):
    """Menjalankan enkripsi/dekripsi di thread terpisah dan melapor lewat queue."""

    def __init__(
        self,
        emit: Callable[[tuple[str, object]], None],
        operation: str,
        src: Path,
        dst: Path,
        a: int,
        b: int,
    ) -> None:
        super().__init__(daemon=True, name=f"transform-{operation}")
        self._emit = emit
        self._operation = operation
        self._src = src
        self._dst = dst
        self._a = a
        self._b = b
        self._last_marker: tuple[str, int] | None = None

    def _progress(self, stage: str, fraction: float) -> None:
        marker = (stage, int(fraction * 100))
        if marker != self._last_marker:
            self._last_marker = marker
            self._emit(("progress", (stage, fraction)))

    def run(self) -> None:
        try:
            if self._operation == "encrypt":
                transform = pipeline.encrypt_file
            else:
                transform = pipeline.decrypt_file
            result = transform(self._src, self._dst, self._a, self._b, progress=self._progress)
        except (OSError, ValueError) as error:
            self._emit(("error", describe_error(self._src, error)))
        except Exception as error:  # jaring pengaman agar UI tidak menunggu selamanya
            self._emit(("error", f"Terjadi kesalahan tak terduga: {error}"))
        else:
            self._emit(("done", result))


class VerifyWorker(threading.Thread):
    """Memeriksa kesamaan file (hash manual atau dua file) di thread terpisah."""

    def __init__(
        self,
        emit: Callable[[tuple[str, object]], None],
        mode: str,
        first: Path,
        second: Path | None = None,
        expected: str | None = None,
    ) -> None:
        super().__init__(daemon=True, name=f"verify-{mode}")
        self._emit = emit
        self._mode = mode
        self._first = first
        self._second = second
        self._expected = expected or ""

    def _hash_payload(self, expected: str, actual: str) -> dict[str, object]:
        return {
            "mode": "hash",
            "status": "COCOK" if actual == expected else "TIDAK_COCOK",
            "hash_a": expected,
            "hash_b": actual,
            "differing_bytes": None,
            "first_difference_offset": None,
            "plain_hash": expected,
            "decrypted_hash": actual,
            "method_note": "banding hash manual",
        }

    def run(self) -> None:
        try:
            if self._mode == "hash":
                actual = metrics.sha256_file(self._first)
                payload = self._hash_payload(self._expected.lower(), actual)
            else:
                assert self._second is not None
                comparison = metrics.compare_files(self._first, self._second)
                if comparison.differing_bytes == 0:
                    detail = "banding dua file; byte berbeda: 0"
                else:
                    detail = (
                        "banding dua file; byte berbeda: "
                        f"{comparison.differing_bytes}, offset pertama: "
                        f"{comparison.first_difference_offset}"
                    )
                payload = {
                    "mode": "files",
                    "status": "COCOK" if comparison.hash_match else "TIDAK_COCOK",
                    "hash_a": comparison.hash_a,
                    "hash_b": comparison.hash_b,
                    "differing_bytes": comparison.differing_bytes,
                    "first_difference_offset": comparison.first_difference_offset,
                    "plain_hash": comparison.hash_a,
                    "decrypted_hash": comparison.hash_b,
                    "method_note": detail,
                }
        except (OSError, ValueError) as error:
            self._emit(("error", describe_error(self._first, error)))
        except Exception as error:  # jaring pengaman agar UI tidak menunggu selamanya
            self._emit(("error", f"Terjadi kesalahan tak terduga: {error}"))
        else:
            self._emit(("verify", payload))


class FilePanel(ttk.LabelFrame):
    """Panel pemilihan file beserta nama, path, ukuran, dan ekstensinya."""

    def __init__(self, master: tk.Misc, title: str, dialog_title: str = "Pilih file") -> None:
        super().__init__(master, text=title, padding=10)
        self.path: Path | None = None
        self._on_change: Callable[[Path], None] | None = None
        self._dialog_title = dialog_title

        self.columnconfigure(2, weight=1)
        ttk.Button(self, text="Pilih File…", command=self.choose).grid(
            row=0, column=0, rowspan=4, sticky="nw"
        )

        self._nama = tk.StringVar(value="Belum ada file dipilih.")
        self._path_text = tk.StringVar(value="-")
        self._ukuran = tk.StringVar(value="-")
        self._ekstensi = tk.StringVar(value="-")

        rows: tuple[tuple[str, tk.StringVar, dict[str, object]], ...] = (
            ("Nama", self._nama, {"font": ("Segoe UI", 10, "bold")}),
            ("Path", self._path_text, {"foreground": "#555555"}),
            ("Ukuran", self._ukuran, {}),
            ("Ekstensi", self._ekstensi, {}),
        )
        for index, (caption, variable, options) in enumerate(rows):
            ttk.Label(self, text=f"{caption}:").grid(
                row=index, column=1, sticky="w", padx=(12, 6), pady=1
            )
            ttk.Label(self, textvariable=variable, **options).grid(
                row=index, column=2, sticky="w", pady=1
            )

    def choose(self) -> None:
        """Membuka dialog pemilihan file lalu memperbarui tampilan panel."""
        selected = filedialog.askopenfilename(
            parent=self.winfo_toplevel(),
            title=self._dialog_title,
            filetypes=[("Semua file", "*.*")],
        )
        if selected:
            self.set_path(Path(selected))

    def set_path(self, path: Path) -> None:
        """Menetapkan file terpilih tanpa membuka dialog."""
        self.path = path
        self._nama.set(path.name)
        self._path_text.set(str(path))
        try:
            size = path.stat().st_size
        except OSError:
            self._ukuran.set("tidak diketahui")
        else:
            self._ukuran.set(f"{size} byte ({format_size(size)})")
        suffix = path.suffix
        self._ekstensi.set(suffix[1:] if suffix else "(tanpa ekstensi)")
        if self._on_change is not None:
            self._on_change(path)

    def set_on_change(self, callback: Callable[[Path], None]) -> None:
        """Callback yang dipanggil setiap kali file terpilih berubah."""
        self._on_change = callback


class KeyPanel(ttk.LabelFrame):
    """Input kunci ``a`` dan ``b`` beserta validasinya."""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, text="Kunci", padding=10)
        self.a_var = tk.StringVar(value=DEFAULT_A)
        self.b_var = tk.StringVar(value=DEFAULT_B)

        ttk.Label(self, text="Kunci a (ganjil, 1–255):").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(self, from_=1, to=255, textvariable=self.a_var, width=8).grid(
            row=0, column=1, sticky="w", padx=(6, 20)
        )
        ttk.Label(self, text="Kunci b (0–255):").grid(row=0, column=2, sticky="w")
        ttk.Spinbox(self, from_=0, to=255, textvariable=self.b_var, width=8).grid(
            row=0, column=3, sticky="w", padx=(6, 0)
        )

    def read(self) -> tuple[int, int] | None:
        """Mengembalikan ``(a, b)`` yang valid, atau ``None`` setelah menampilkan pesan."""
        try:
            a = int(self.a_var.get().strip())
            b = int(self.b_var.get().strip())
        except ValueError:
            messagebox.showerror(
                "Kunci tidak valid",
                "Kunci harus berupa angka bulat.",
                parent=self.winfo_toplevel(),
            )
            return None
        valid, message = validate_keys(a, b)
        if not valid:
            messagebox.showerror("Kunci tidak valid", message, parent=self.winfo_toplevel())
            return None
        return a, b


class NotePanel(ttk.Frame):
    """Kolom catatan opsional untuk kolom ``Catatan_Pengujian``."""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        ttk.Label(self, text="Catatan (opsional, mis. run 1/3):").pack(side="left")
        self.note_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.note_var, width=44).pack(side="left", padx=(8, 0))

    def value(self) -> str:
        """Catatan tanpa spasi tepi; string kosong berarti ``-`` di CSV."""
        return self.note_var.get().strip()


class ResultCards(ttk.LabelFrame):
    """Kumpulan label hasil dengan tata letak dua kolom."""

    def __init__(
        self,
        master: tk.Misc,
        title: str,
        fields: Sequence[tuple[str, str]],
        full_width: Sequence[str] = ("output", "hash"),
    ) -> None:
        super().__init__(master, text=title, padding=10)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self._vars: dict[str, tk.StringVar] = {}

        row = 0
        column = 0
        for key, caption in fields:
            variable = tk.StringVar(value="-")
            self._vars[key] = variable
            frame = ttk.Frame(self)
            if key in full_width:
                if column:
                    row += 1
                    column = 0
                frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=2)
                row += 1
            else:
                frame.grid(row=row, column=column, sticky="ew", padx=(0, 12), pady=2)
                column += 1
                if column == 2:
                    column = 0
                    row += 1
            ttk.Label(frame, text=f"{caption}:", width=24).pack(side="left")
            ttk.Label(
                frame,
                textvariable=variable,
                font=("Consolas", 10),
                wraplength=700,
                justify="left",
            ).pack(side="left", fill="x", expand=True)

    def show(self, values: Mapping[str, str]) -> None:
        """Mengisi kartu dari mapping; kunci yang tidak diberikan menjadi ``-``."""
        for key, variable in self._vars.items():
            variable.set(values.get(key, "-"))

    def clear(self) -> None:
        """Mengosongkan seluruh kartu."""
        for variable in self._vars.values():
            variable.set("-")


class AffineApp(tk.Tk):
    """Jendela utama aplikasi."""

    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x740")
        self.minsize(900, 680)

        self.output_dir = app_dir() / "output"
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            self.output_dir = Path.home() / "AffineCipher"
            try:
                self.output_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
        self.log = ResultLog(self.output_dir / "hasil_pengujian.csv")
        if not self.log.path.exists():
            self.log.save()
        metrics.prime_cpu_percent()

        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._worker: TransformWorker | None = None
        self._job: dict[str, object] | None = None

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(10, 0))

        self._build_encrypt_tab()
        self._build_decrypt_tab()
        self._build_verify_tab()

        self._status_var = tk.StringVar()
        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=10, pady=(8, 0))
        ttk.Label(self, textvariable=self._status_var, anchor="w").pack(
            fill="x", padx=12, pady=6
        )
        self._update_status()
        if self.log.notice:
            self.after(
                200,
                lambda: messagebox.showwarning(
                    "Perhatian pada file CSV", self.log.notice, parent=self
                ),
            )
        self.after(100, self._drain_queue)

    # ------------------------------------------------------------------ tab --

    def _build_encrypt_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Enkripsi")
        tab.columnconfigure(0, weight=1)

        self.encrypt_file = FilePanel(tab, "File yang akan dienkripsi", "Pilih file untuk dienkripsi")
        self.encrypt_file.grid(row=0, column=0, sticky="ew")

        self.encrypt_keys = KeyPanel(tab)
        self.encrypt_keys.grid(row=1, column=0, sticky="ew", pady=(10, 0))

        self.encrypt_note = NotePanel(tab)
        self.encrypt_note.grid(row=2, column=0, sticky="ew", pady=(10, 0))

        actions = ttk.Frame(tab)
        actions.grid(row=3, column=0, sticky="ew", pady=(12, 0))
        self.encrypt_button = ttk.Button(actions, text="Enkripsi File", command=self._on_encrypt)
        self.encrypt_button.pack(side="left")
        self.encrypt_progress = ttk.Progressbar(actions, mode="determinate", maximum=100.0)
        self.encrypt_progress.pack(side="left", fill="x", expand=True, padx=12)

        self.encrypt_status = tk.StringVar(value="Siap.")
        ttk.Label(tab, textvariable=self.encrypt_status, foreground="#333333").grid(
            row=4, column=0, sticky="w", pady=(6, 0)
        )
        ttk.Label(
            tab, text=TIME_HINT, foreground="#666666", wraplength=880, justify="left"
        ).grid(row=5, column=0, sticky="w", pady=(2, 0))

        self.encrypt_cards = ResultCards(tab, "Hasil Enkripsi", ENCRYPT_FIELDS)
        self.encrypt_cards.grid(row=6, column=0, sticky="ew", pady=(12, 0))

    def _build_decrypt_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Dekripsi")
        tab.columnconfigure(0, weight=1)

        self.decrypt_file = FilePanel(
            tab, "File yang akan didekripsi", "Pilih file terenkripsi (.enc)"
        )
        self.decrypt_file.grid(row=0, column=0, sticky="ew")

        self.decrypt_keys = KeyPanel(tab)
        self.decrypt_keys.grid(row=1, column=0, sticky="ew", pady=(10, 0))

        self.decrypt_note = NotePanel(tab)
        self.decrypt_note.grid(row=2, column=0, sticky="ew", pady=(10, 0))

        actions = ttk.Frame(tab)
        actions.grid(row=3, column=0, sticky="ew", pady=(12, 0))
        self.decrypt_button = ttk.Button(actions, text="Dekripsi File", command=self._on_decrypt)
        self.decrypt_button.pack(side="left")
        self.decrypt_progress = ttk.Progressbar(actions, mode="determinate", maximum=100.0)
        self.decrypt_progress.pack(side="left", fill="x", expand=True, padx=12)

        self.decrypt_status = tk.StringVar(value="Siap.")
        ttk.Label(tab, textvariable=self.decrypt_status, foreground="#333333").grid(
            row=4, column=0, sticky="w", pady=(6, 0)
        )
        ttk.Label(
            tab, text=TIME_HINT, foreground="#666666", wraplength=880, justify="left"
        ).grid(row=5, column=0, sticky="w", pady=(2, 0))

        self.decrypt_cards = ResultCards(tab, "Hasil Dekripsi", DECRYPT_FIELDS)
        self.decrypt_cards.grid(row=6, column=0, sticky="ew", pady=(12, 0))

    def _build_verify_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Cek Kesamaan File")
        tab.columnconfigure(0, weight=1)

        modes = ttk.LabelFrame(tab, text="Metode pemeriksaan", padding=10)
        modes.grid(row=0, column=0, sticky="ew")
        self.verify_mode = tk.StringVar(value="hash")
        ttk.Radiobutton(
            modes,
            text="Mode hash — bandingkan hash SHA-256 asli dari CSV dengan hash file",
            value="hash",
            variable=self.verify_mode,
            command=self._sync_verify_mode,
        ).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(
            modes,
            text="Mode dua file — bandingkan file asli dengan file hasil dekripsi",
            value="files",
            variable=self.verify_mode,
            command=self._sync_verify_mode,
        ).grid(row=1, column=0, sticky="w")

        self.verify_hash_frame = ttk.LabelFrame(tab, text="Hash SHA-256 asli", padding=10)
        self.verify_hash_frame.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        self.verify_hash_frame.columnconfigure(1, weight=1)
        ttk.Label(self.verify_hash_frame, text="Tempel 64 karakter hex:").grid(
            row=0, column=0, sticky="w"
        )
        self.verify_hash_var = tk.StringVar()
        ttk.Entry(self.verify_hash_frame, textvariable=self.verify_hash_var, width=72).grid(
            row=0, column=1, sticky="ew", padx=(8, 0)
        )

        self.verify_original = FilePanel(tab, "File asli", "Pilih file asli")
        self.verify_original.grid(row=2, column=0, sticky="ew", pady=(10, 0))

        self.verify_result_file = FilePanel(
            tab, "File hasil dekripsi", "Pilih file hasil dekripsi"
        )
        self.verify_result_file.grid(row=3, column=0, sticky="ew", pady=(10, 0))

        actions = ttk.Frame(tab)
        actions.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        self.verify_button = ttk.Button(
            actions, text="Bandingkan", command=self._on_verify
        )
        self.verify_button.pack(side="left")

        self.verify_status = tk.StringVar(value="Siap.")
        ttk.Label(tab, textvariable=self.verify_status, foreground="#333333").grid(
            row=5, column=0, sticky="w", pady=(6, 0)
        )

        self.verify_output = tk.Text(tab, height=7, wrap="word", font=("Consolas", 9))
        self.verify_output.grid(row=6, column=0, sticky="nsew", pady=(10, 0))
        self.verify_output.configure(state="disabled")
        tab.rowconfigure(6, weight=1)

        self._sync_verify_mode()

    # -------------------------------------------------------------- helpers --

    def _sync_verify_mode(self) -> None:
        """Menampilkan panel yang relevan sesuai metode pemeriksaan."""
        if self.verify_mode.get() == "hash":
            self.verify_hash_frame.grid()
            self.verify_original.grid_remove()
        else:
            self.verify_hash_frame.grid_remove()
            self.verify_original.grid()

    def _set_verify_text(self, text: str) -> None:
        self.verify_output.configure(state="normal")
        self.verify_output.delete("1.0", "end")
        self.verify_output.insert("1.0", text)
        self.verify_output.configure(state="disabled")

    def _update_status(self) -> None:
        parts = [f"CSV: {self.log.path}", f"{len(self.log.rows)} baris"]
        if self.log.notice:
            parts.append(f"CATATAN: {self.log.notice}")
        if self.log.last_error:
            parts.append(f"PERINGATAN: {self.log.last_error}")
        self._status_var.set(" | ".join(parts))

    def _warn_if_log_failed(self) -> None:
        if self.log.last_error:
            messagebox.showwarning(
                "Penyimpanan CSV gagal",
                "Hasil operasi tetap berhasil, tetapi CSV tidak dapat ditulis. "
                "Tutup file CSV di Excel lalu jalankan operasi berikutnya.",
                parent=self,
            )
        self._update_status()

    def _set_busy(self, busy: bool) -> None:
        """Menonaktifkan tombol aksi selama pemrosesan berjalan."""
        state = "disabled" if busy else "normal"
        for button in (self.encrypt_button, self.decrypt_button, self.verify_button):
            button.configure(state=state)

    def _drain_queue(self) -> None:
        """Mengambil event dari worker thread dan memperbarui UI."""
        try:
            while True:
                try:
                    kind, payload = self.events.get_nowait()
                except queue.Empty:
                    break
                try:
                    self._handle_event(kind, payload)
                except Exception as error:  # kesalahan UI tidak boleh mematikan polling
                    self._worker = None
                    self._job = None
                    self._set_busy(False)
                    self._update_status()
                    messagebox.showerror(
                        "Kesalahan tak terduga",
                        f"Terjadi kesalahan saat memperbarui tampilan: {error}",
                        parent=self,
                    )
        finally:
            self.after(100, self._drain_queue)

    def _handle_event(self, kind: str, payload: object) -> None:
        job = self._job
        if job is None:
            return
        if kind == "progress":
            stage, fraction = payload  # type: ignore[misc]
            self._handle_progress(str(stage), float(fraction))
            return
        if kind == "error":
            operation = str(job["operation"])
            self._worker = None
            self._job = None
            self._set_busy(False)
            if operation == "verify":
                self.verify_status.set("Pemeriksaan gagal.")
            else:
                self._set_status(str(payload), operation)
            messagebox.showerror("Operasi gagal", str(payload), parent=self)
            return
        if kind == "verify":
            self._worker = None
            self._job = None
            self._set_busy(False)
            assert isinstance(payload, dict)
            self._finish_verify(payload)
            return
        # kind == "done"
        self._worker = None
        self._job = None
        self._set_busy(False)
        result = payload
        assert isinstance(result, TransformResult)
        if job["operation"] == "encrypt":
            self._finish_encrypt(result, job)
        else:
            self._finish_decrypt(result, job)

    def _handle_progress(self, stage: str, fraction: float) -> None:
        job = self._job
        if job is None:
            return
        encrypting = job["operation"] == "encrypt"
        widget = self.encrypt_progress if encrypting else self.decrypt_progress
        widget["value"] = fraction * 100
        if stage == pipeline.STAGE_DONE:
            self._set_status("Menyiapkan hasil dan mencatat CSV…")
        else:
            self._set_status(f"{stage}… {fraction * 100:.0f}%")

    def _set_status(self, text: str, operation: str | None = None) -> None:
        if operation is None:
            job = self._job
            operation = str(job["operation"]) if job is not None else "encrypt"
        variable = self.encrypt_status if operation == "encrypt" else self.decrypt_status
        variable.set(text)

    def _begin_transform(
        self,
        operation: str,
        src: Path,
        dst: Path,
        a: int,
        b: int,
        note: str,
    ) -> None:
        """Menyiapkan UI lalu menjalankan worker transformasi."""
        if not src.exists():
            messagebox.showerror(
                "File tidak ditemukan", f"File tidak ditemukan: {src}", parent=self
            )
            return
        if dst == src:
            messagebox.showerror(
                "Output bentrok",
                "File hasil akan menimpa file masukan. Pilih file lain.",
                parent=self,
            )
            return

        self._job = {
            "operation": operation,
            "src": src,
            "dst": dst,
            "a": a,
            "b": b,
            "note": note,
        }
        encrypting = operation == "encrypt"
        progress = self.encrypt_progress if encrypting else self.decrypt_progress
        progress["value"] = 0
        cards = self.encrypt_cards if encrypting else self.decrypt_cards
        cards.clear()
        self._set_status(f"Memproses {src.name}…")
        self._set_busy(True)

        self._worker = TransformWorker(self.events.put, operation, src, dst, a, b)
        self._worker.start()

    # ------------------------------------------------------------- handlers --

    def _on_encrypt(self) -> None:
        if self._worker is not None:
            return
        src = self.encrypt_file.path
        if src is None:
            messagebox.showinfo(
                "Belum ada file",
                "Pilih file yang akan dienkripsi terlebih dahulu.",
                parent=self,
            )
            return
        keys = self.encrypt_keys.read()
        if keys is None:
            return
        a, b = keys
        self._begin_transform(
            "encrypt",
            src,
            pipeline.output_names(src, "enc"),
            a,
            b,
            self.encrypt_note.value(),
        )

    def _finish_encrypt(self, result: TransformResult, job: Mapping[str, object]) -> None:
        row = build_encrypt_row(
            result,
            int(job["a"]),  # type: ignore[arg-type]
            int(job["b"]),  # type: ignore[arg-type]
            now_stamp(),
            str(job["note"]),
        )
        self.encrypt_progress["value"] = 100
        self.encrypt_cards.show(
            {
                "waktu": row["Waktu_Enkripsi_Detik"],
                "throughput": row["Throughput_Enkripsi_MBps"],
                "entropi_plain": row["Entropi_Plainteks"],
                "entropi_cipher": row["Entropi_Cipherteks"],
                "avalanche_plain": row["Avalanche_Plainteks_Persen"],
                "avalanche_key": row["Avalanche_Kunci_Persen"],
                "cpu": row["CPU_Usage_Enkripsi_Persen"],
                "ram": row["RAM_Usage_Enkripsi_MB"],
                "ukuran_asli": row["Ukuran_Asli_Byte"],
                "ukuran_hasil": row["Ukuran_Hasil_Byte"],
                "output": str(result.output_path),
                "hash": row["Hash_SHA256_Asli"],
            }
        )
        self.log.add_trial(row)
        self.encrypt_status.set(f"Enkripsi selesai: {result.output_path.name}")
        self._warn_if_log_failed()

    def _on_decrypt(self) -> None:
        if self._worker is not None:
            return
        src = self.decrypt_file.path
        if src is None:
            messagebox.showinfo(
                "Belum ada file",
                "Pilih file terenkripsi (.enc) yang akan didekripsi terlebih dahulu.",
                parent=self,
            )
            return
        keys = self.decrypt_keys.read()
        if keys is None:
            return
        a, b = keys
        self._begin_transform(
            "decrypt",
            src,
            pipeline.output_names(src, "dec"),
            a,
            b,
            self.decrypt_note.value(),
        )

    def _finish_decrypt(self, result: TransformResult, job: Mapping[str, object]) -> None:
        a = int(job["a"])  # type: ignore[arg-type]
        b = int(job["b"])  # type: ignore[arg-type]
        note = str(job["note"])

        row_index = self.log.find_for_decryption(result.hash_plain, a, b)
        if row_index is None:
            data = build_standalone_decrypt_row(result, a, b, now_stamp(), note)
            self.log.add_trial(data)
            message = (
                "Dekripsi selesai. Tidak ada baris enkripsi yang cocok, jadi hasil ini "
                "dicatat sebagai baris Dekripsi baru. Hasil belum diverifikasi."
            )
        else:
            previous_note = self.log.rows[row_index]["Catatan_Pengujian"]
            data = build_decrypt_update(result, a, b, note, previous_note)
            self.log.update(row_index, data)
            message = (
                f"Dekripsi selesai — kolom dekripsi baris {row_index + 1} terisi. "
                "Hasil belum diverifikasi."
            )

        self.decrypt_progress["value"] = 100
        self.decrypt_cards.show(
            {
                "waktu": data["Waktu_Dekripsi_Detik"],
                "throughput": data["Throughput_Dekripsi_MBps"],
                "entropi_cipher": f"{result.entropy_cipher:.4f}",
                "entropi_plain": f"{result.entropy_plain:.4f}",
                "cpu": data["CPU_Usage_Dekripsi_Persen"],
                "ram": data["RAM_Usage_Dekripsi_MB"],
                "ukuran_asli": str(result.cipher_size),
                "ukuran_hasil": str(result.plain_size),
                "output": str(result.output_path),
                "hash": data["Hash_SHA256_Dekripsi"],
            }
        )
        self.decrypt_status.set(message)
        self._warn_if_log_failed()

    def _on_verify(self) -> None:
        if self._worker is not None:
            return
        if self.verify_mode.get() == "hash":
            typed = self.verify_hash_var.get().strip()
            if not metrics.is_valid_sha256_hex(typed):
                messagebox.showerror(
                    "Hash tidak valid",
                    "Hash SHA-256 harus terdiri dari 64 karakter hex (0-9, a-f).",
                    parent=self,
                )
                return
            target = self.verify_result_file.path
            if target is None:
                messagebox.showinfo(
                    "Belum ada file",
                    "Pilih file hasil dekripsi yang akan diperiksa.",
                    parent=self,
                )
                return
            self._start_verify(
                VerifyWorker(self.events.put, "hash", target, expected=typed)
            )
            return

        original = self.verify_original.path
        result = self.verify_result_file.path
        if original is None or result is None:
            messagebox.showinfo(
                "Belum ada file",
                "Pilih file asli dan file hasil dekripsi terlebih dahulu.",
                parent=self,
            )
            return
        self._start_verify(VerifyWorker(self.events.put, "files", original, second=result))

    def _start_verify(self, worker: VerifyWorker) -> None:
        self._job = {"operation": "verify"}
        self.verify_status.set("Memeriksa…")
        self._set_verify_text("")
        self._set_busy(True)
        self._worker = worker
        self._worker.start()

    def _verify_report(self, data: Mapping[str, object]) -> str:
        lines = [f"Status: {data['status']}"]
        if data["mode"] == "hash":
            lines.append(f"Hash yang ditempel : {data['hash_a']}")
            lines.append(f"Hash file          : {data['hash_b']}")
        else:
            lines.append(f"Hash file asli     : {data['hash_a']}")
            lines.append(f"Hash file dekripsi : {data['hash_b']}")
            if data["differing_bytes"] == 0:
                lines.append("Isi file           : identik byte-per-byte, tidak ada perbedaan.")
            else:
                lines.append(f"Byte berbeda       : {data['differing_bytes']}")
                lines.append(f"Offset pertama     : {data['first_difference_offset']}")
        return "\n".join(lines)

    def _finish_verify(self, data: Mapping[str, object]) -> None:
        status = str(data["status"])
        self._set_verify_text(self._verify_report(data))
        row_index = self.log.find_for_verification(str(data["decrypted_hash"]))
        if row_index is None:
            self.verify_status.set(
                "Pemeriksaan selesai, tetapi hasilnya tidak dapat dipasangkan ke percobaan mana pun."
            )
            messagebox.showinfo(
                "Tidak dapat dipasangkan",
                "Hasil pemeriksaan tidak dapat dipasangkan ke percobaan mana pun, "
                "sehingga CSV tidak diubah. Pastikan file yang diperiksa adalah hasil "
                "dekripsi yang tercatat di CSV.",
                parent=self,
            )
            return
        update = build_verify_update(
            self.log.rows[row_index], status, str(data["method_note"])
        )
        self.log.update(row_index, update)
        self.verify_status.set(
            f"Pemeriksaan selesai: {status} — baris {row_index + 1} diperbarui "
            f"(Operasi={update['Operasi']})."
        )
        self._warn_if_log_failed()


if __name__ == "__main__":
    AffineApp().mainloop()
