# Aplikasi Kriptografi — Affine Cipher Mode Byte

Aplikasi desktop Python (Tkinter) untuk mengenkripsi dan mendekripsi file apa pun
(`.txt`, `.docx`, `.pdf`, `.bmp`, `.jpg`, `.mp3`, `.mp4`, `.zip`, dan lainnya) dengan
**Affine Cipher mode byte**, sekaligus mengukur performanya dan mencatat setiap
percobaan ke satu file CSV.

Tugas Akhir Kriptografi — Kelompok 1, Universitas Islam Balitar (FTI):

- Dewi Nawang Wulandhary (23104410015)
- Ricko Roby Irawan (23104410011)
- Rizqi Harisma Uchrowi (23104410001)
- Ilana Rahmanisa Kholifatul Jannah (23104410002)

## Rumus

Setiap byte diproses langsung sebagai bilangan di $\mathbb{Z}_{256}$:

```
Enkripsi : C = (a * P + b) mod 256
Dekripsi : P = a^-1 * (C - b) mod 256
```

- `a` harus **ganjil** (1–255) agar punya invers modulo 256.
- `b` bebas (0–255).
- `a^-1` dihitung dengan Extended Euclidean Algorithm.
- Nilai bawaan: `a = 7`, `b = 13`. Pengguna bebas menggantinya dan nilai yang
  benar-benar dipakai selalu tercatat di kolom `Kunci_a` / `Kunci_b`.

Karena pemetaan byte bersifat satu-ke-satu, ukuran file hasil **sama persis**
dengan file aslinya (0% overhead, tanpa header/padding/metadata).

## Persyaratan

- Python 3.10 atau lebih baru (sudah termasuk `tkinter`).
- Dependensi pihak ketiga: `psutil` (lihat `requirement.txt`).

## Instalasi

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirement.txt
```

## Menjalankan aplikasi

```powershell
.venv\Scripts\python main.py
```

## Cara memakai

### Tab Enkripsi

1. Klik **Pilih File…** dan pilih file yang akan dienkripsi.
2. Isi `a` (ganjil) dan `b`, lalu isi catatan bila perlu (mis. `run 1/3`).
3. Klik **Enkripsi File**.
4. Hasil ditulis di folder yang sama dengan file asli, bernama `<nama>.<ext>.enc`.
5. Satu baris baru ditambahkan ke CSV berisi metrik enkripsi dan hash SHA-256 file asli.

### Tab Dekripsi

1. Pilih file `.enc`.
2. Isi `a` dan `b` yang dipakai saat enkripsi.
3. Klik **Dekripsi File**.
4. Hasil ditulis sebagai `<nama>_decrypted.<ext>` (akhiran `.enc` dilepas lebih dulu,
   mis. `tugas.pdf.enc` → `tugas_decrypted.pdf`).
5. Jika hasil dekripsi cocok dengan sebuah baris enkripsi (hash + pasangan kunci sama),
   kolom dekripsi **baris itu** diisi. Jika tidak (mis. kunci salah), dibuat **baris
   baru** `Operasi = Dekripsi` sehingga baris enkripsi tidak pernah tercemar.

Kunci salah tidak membuat aplikasi berhenti: file hasil tetap ditulis dan UI
menyatakan bahwa hasil belum terverifikasi.

### Tab Cek Kesamaan File

- **Mode hash** — tempel nilai `Hash_SHA256_Asli` dari CSV (64 karakter hex), pilih
  file hasil dekripsi, lalu klik **Bandingkan**. Aplikasi menghitung hash file dan
  menyatakan `COCOK` atau `TIDAK_COCOK`.
- **Mode dua file** — pilih file asli dan file hasil dekripsi. Aplikasi membandingkan
  hash **dan** isi byte-per-byte, lalu melaporkan jumlah byte berbeda serta offset
  perbedaan pertama.

Pemeriksaan tidak menambah baris baru: ia mengisi `Status_Hash_Cocok`, menambahkan
metode pemeriksaan ke `Catatan_Pengujian`, dan menaikkan `Operasi` ke tahap verifikasi.

## Urutan pengujian yang disarankan

Untuk setiap file: **enkripsi → dekripsi → verifikasi**.

Alasannya, baris CSV dipasangkan lewat hash SHA-256 dan pasangan kunci, bukan lewat
nama file. Enkripsi membuat baris, dekripsi mengisi kolom dekripsi baris tersebut, dan
verifikasi mengisi status kecocokan. Jika urutan ini diikuti, satu percobaan menempati
tepat satu baris dari awal sampai akhir.

Catatan penting:

- **Tutup file CSV di Excel** saat aplikasi sedang menulis. Bila file terkunci,
  operasi enkripsi/dekripsi tetap berhasil, file hasil tetap ada, dan aplikasi
  menampilkan peringatan; jalankan operasi berikutnya setelah Excel ditutup.
- Nama file hanya deskriptif. File yang di-rename tetap dapat dipasangkan karena
  identitas percobaan adalah hash isi file.

## File CSV hasil pengujian

Lokasi: `output/hasil_pengujian.csv` (relatif terhadap folder aplikasi / `.exe`).

Aturan:

- Satu baris = satu percobaan (satu file, satu pasangan kunci, satu kali jalan).
- Enkripsi membuat baris; dekripsi dan verifikasi memperbarui baris yang sama.
- Nilai yang tidak berlaku ditulis `-`.
- Angka: waktu 6 desimal (detik), throughput 2, entropi 4, avalanche 4, persen 2.

### Arti kolom

| Kolom | Arti |
|---|---|
| `Timestamp` | Waktu lokal percobaan dibuat (`YYYY-MM-DD HH:MM:SS`). |
| `Nama_File` | Nama file tanpa folder; akhiran `.enc` dilepas. |
| `Ekstensi` | Ekstensi file asli tanpa titik (mis. `pdf`). |
| `Ukuran_Asli_Byte` | Ukuran plainteks dalam byte. |
| `Ukuran_Hasil_Byte` | Ukuran cipherteks dalam byte. |
| `Tambahan_Ukuran_Persen` | Selisih ukuran cipherteks terhadap plainteks; selalu `0.00`, atau `-` bila plainteks 0 byte. |
| `Kunci_a` | Nilai `a` yang dipakai (ganjil). |
| `Kunci_b` | Nilai `b` yang dipakai. |
| `Operasi` | Tahap terakhir percobaan (lihat tabel di bawah). |
| `Waktu_Enkripsi_Detik` | Waktu pass transformasi enkripsi (I/O dan hash tidak dihitung). |
| `Waktu_Dekripsi_Detik` | Waktu pass transformasi dekripsi. |
| `Throughput_Enkripsi_MBps` | Kecepatan enkripsi (MB/s, 1 MB = 1024×1024 byte). |
| `Throughput_Dekripsi_MBps` | Kecepatan dekripsi. |
| `Entropi_Plainteks` | Entropi Shannon plainteks (0–8 bit/byte). |
| `Entropi_Cipherteks` | Entropi Shannon cipherteks. |
| `Avalanche_Plainteks_Persen` | Persentase bit cipherteks yang berubah saat 1 bit plainteks dibalik. |
| `Avalanche_Kunci_Persen` | Persentase bit cipherteks yang berubah saat 1 bit kunci `b` dibalik. |
| `CPU_Usage_Enkripsi_Persen` | Pemakaian CPU (system-wide) selama pass enkripsi. |
| `RAM_Usage_Enkripsi_MB` | RSS proses aplikasi setelah enkripsi (MB). |
| `CPU_Usage_Dekripsi_Persen` | Pemakaian CPU selama pass dekripsi. |
| `RAM_Usage_Dekripsi_MB` | RSS proses aplikasi setelah dekripsi (MB). |
| `Hash_SHA256_Asli` | Hash SHA-256 plainteks. |
| `Hash_SHA256_Dekripsi` | Hash SHA-256 hasil dekripsi. |
| `Status_Hash_Cocok` | `COCOK` / `TIDAK_COCOK` dari tab verifikasi. |
| `Catatan_Pengujian` | Catatan bebas (lihat konvensi di bawah). |

### Arti nilai `Operasi`

| Nilai | Kolom performa enkripsi | Kolom performa dekripsi | `Status_Hash_Cocok` |
|---|---|---|---|
| `Enkripsi` | terisi | `-` | `-` |
| `Enkripsi+Dekripsi` | terisi | terisi | `-` |
| `Enkripsi+Dekripsi+Verifikasi` | terisi | terisi | `COCOK` / `TIDAK_COCOK` |
| `Dekripsi` | `-` | terisi | `-` |
| `Dekripsi+Verifikasi` | `-` | terisi | `COCOK` / `TIDAK_COCOK` |

`Dekripsi` mandiri muncul saat file didekripsi dengan kunci salah atau file bukan hasil
enkripsi aplikasi ini, sehingga tidak ada baris enkripsi yang boleh diisi.

### Konvensi catatan

Beberapa contoh yang memudahkan penyusunan laporan:

- `run 1/3`, `run 2/3`, `run 3/3` untuk tiga pengulangan file yang sama.
- `skenario kunci-2` untuk uji variasi kunci.
- `kunci salah` untuk uji kegagalan dekripsi.

Verifikasi **menambahkan** catatan (dipisah `"; "`), tidak menimpanya.

## Catatan keamanan

- Affine cipher byte **bukan cipher yang aman**. Ruang kuncinya hanya
  128 nilai `a` × 256 nilai `b` = 32.768 kemungkinan, sehingga brute force sangat mudah.
- **Entropi tidak berubah**: substitusi 1-ke-1 hanya mengubah urutan frekuensi byte,
  bukan distribusinya. Entropi plainteks dan cipherteks selalu sama.
- **Tidak ada diffusion**: perubahan 1 bit plainteks hanya mengubah 1 byte cipherteks,
  sehingga avalanche plainteks mendekati 0%. Ini sifat algoritma, bukan bug.
- Avalanche kunci diukur dengan mengubah tepat satu bit `b` (`b ^ 0x01`), bukan `b + 1`,
  agar perbandingannya adil.
- File `.enc` tidak menyimpan header, kunci, hash, maupun jumlah padding. Akibatnya
  tidak ada mekanisme integritas/autentikasi di dalam file; verifikasi hanya bisa
  dilakukan dengan membandingkan hash plainteks yang dicatat di CSV.
- Angka CPU diukur **system-wide** lewat `psutil.cpu_percent()`, bukan pemakaian CPU
  khusus proses aplikasi. Angka RAM adalah RSS proses aplikasi, bukan RAM yang dipakai
  untuk memuat file (file diproses per potongan 4 MB).

## Struktur proyek

```
Project/
├── main.py              # GUI Tkinter (3 tab) + worker thread
├── affine_cipher.py     # mod_inverse, validate_keys, tabel substitusi, transformasi
├── metrics.py           # SHA-256, entropi, avalanche, throughput, CPU/RAM, pembanding file
├── pipeline.py          # orkestrasi streaming 4 MB + akumulasi metrik
├── logger.py            # pembentukan baris & penyimpanan CSV atomik
├── requirement.txt      # psutil
├── build_exe.bat        # skrip build PyInstaller
├── tests/               # unit test (unittest bawaan)
└── output/
    └── hasil_pengujian.csv
```

## Menjalankan unit test

```powershell
.venv\Scripts\python -m unittest discover -s tests -v
```

## Membuat file `.exe`

Jalankan:

```bat
build_exe.bat
```

Hasil build ada di `dist\AffineCipher.exe`. Aplikasi tidak menampilkan jendela konsol.

Catatan penting untuk versi `.exe`:

- Folder `output/` dibuat **di samping file `.exe`**, bukan di working directory dan
  bukan di folder sementara PyInstaller. Salin `.exe` ke folder yang dapat ditulisi
  (mis. `D:\uji\`) sebelum dijalankan.
- File hasil enkripsi/dekripsi tetap ditulis di folder file aslinya.
- Bila `.exe` diletakkan di `Program Files`, Windows dapat memblokir penulisan CSV;
  gunakan folder pengguna biasa.
