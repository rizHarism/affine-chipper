"""Aplikasi desktop Affine Cipher mode byte.

GUI Tkinter dengan tiga tab: Enkripsi, Dekripsi, dan Cek Kesamaan File.
Semua pemrosesan file berjalan di thread terpisah agar UI tetap responsif.
"""

from __future__ import annotations

import sys
import tkinter as tk
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import metrics
from affine_cipher import validate_keys
from logger import ResultLog

APP_TITLE = "Affine Cipher — Enkripsi & Dekripsi File"
DEFAULT_A = "7"
DEFAULT_B = "13"

ENCRYPT_FIELDS: tuple[tuple[str, str], ...] = (
    ("waktu", "Waktu enkripsi (detik)"),
    ("throughput", "Throughput (MB/s)"),
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
    ("waktu", "Waktu dekripsi (detik)"),
    ("throughput", "Throughput (MB/s)"),
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
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log = ResultLog(self.output_dir / "hasil_pengujian.csv")
        self.log.save()
        metrics.prime_cpu_percent()

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

        self.encrypt_cards = ResultCards(tab, "Hasil Enkripsi", ENCRYPT_FIELDS)
        self.encrypt_cards.grid(row=5, column=0, sticky="ew", pady=(12, 0))

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

        self.decrypt_cards = ResultCards(tab, "Hasil Dekripsi", DECRYPT_FIELDS)
        self.decrypt_cards.grid(row=5, column=0, sticky="ew", pady=(12, 0))

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

    def _not_ready(self, feature: str) -> None:
        messagebox.showinfo(
            "Belum tersedia",
            f"Fitur {feature} diisi pada tahap implementasi berikutnya.",
            parent=self,
        )

    # ------------------------------------------------------------- handlers --

    def _on_encrypt(self) -> None:
        self._not_ready("enkripsi")

    def _on_decrypt(self) -> None:
        self._not_ready("dekripsi")

    def _on_verify(self) -> None:
        self._not_ready("verifikasi")


if __name__ == "__main__":
    AffineApp().mainloop()
