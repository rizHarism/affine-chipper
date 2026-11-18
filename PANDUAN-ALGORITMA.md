# Panduan Algoritma Affine Cipher & Aplikasi Pengujian File

Dokumen ini menjelaskan cara kerja aplikasi enkripsi/dekripsi file yang dibuat untuk
Tugas Akhir Kriptografi Kelompok 1, dengan fokus pada **algoritma Affine Cipher mode
byte**. Bahasa sengaja dibuat sederhana agar bisa dipakai langsung oleh penyusun
laporan yang belum mendalami kriptografi.

> **Catatan tentang angka.** Semua angka waktu, throughput, dan avalanche di dokumen
> ini adalah **ilustrasi** dari uji coba pengembangan (file 400 MB dan file 9,8–19,5 MB).
> Angka tersebut bukan data resmi pengujian. Untuk laporan, gunakan rata-rata dari
> `output/hasil_pengujian.csv` hasil pengujian kelompok sendiri.

---

## Daftar isi

1. [Ringkasan aplikasi](#1-ringkasan-aplikasi)
2. [Affine Cipher dalam satu menit](#2-affine-cipher-dalam-satu-menit)
3. [Contoh perhitungan: kata "Halo"](#3-contoh-perhitungan-kata-halo)
4. [Cara aplikasi memproses file](#4-cara-aplikasi-memproses-file)
5. [Metrik yang dicatat](#5-metrik-yang-dicatat)
6. [Hasil yang wajar muncul, dan alasannya](#6-hasil-yang-wajar-muncul-dan-alasannya)
7. [Keamanan dan keterbatasan](#7-keamanan-dan-keterbatasan)
8. [Skenario pengujian dan cara membaca CSV](#8-skenario-pengujian-dan-cara-membaca-csv)
9. [Contoh paragraf untuk laporan](#9-contoh-paragraf-untuk-laporan)
10. [FAQ sidang, glosarium, dan referensi](#10-faq-sidang-glosarium-dan-referensi)

---

## 1. Ringkasan aplikasi

Aplikasi desktop berbasis Python + Tkinter dengan tiga tab:

| Tab | Fungsi |
|---|---|
| **Enkripsi** | Memilih file apa pun (`.txt`, `.docx`, `.pdf`, `.jpg`, `.mp3`, `.mp4`, `.zip`, …), mengenkripsinya, lalu mencatat 25 kolom metrik ke CSV. |
| **Dekripsi** | Mengembalikan file `.enc` menjadi file aslinya dan melengkapi kolom dekripsi pada baris CSV yang sama. |
| **Cek Kesamaan File** | Membuktikan hasil dekripsi identik dengan file asli, lewat hash SHA-256 atau perbandingan dua file byte-per-byte. |

Yang penting dipahami:

- Aplikasi bekerja pada **byte**, bukan huruf. Karena itu semua jenis file bisa
  diproses, termasuk file biner seperti gambar dan video.
- File hasil (`.enc`) **tidak menyimpan apa pun selain isi file yang sudah diubah**:
  tidak ada header, nama file, atau kunci di dalamnya. Ukurannya sama persis dengan
  file asli.
- Aplikasi mencatat **satu baris per percobaan** di `output/hasil_pengujian.csv`.
  Enkripsi membuat baris; dekripsi dan verifikasi memperbarui baris yang sama.

---

## 2. Affine Cipher dalam satu menit

Affine Cipher adalah substitusi: setiap nilai diubah dengan rumus garis lurus
(fungsi affine), lalu diambil sisa baginya.

Karena file komputer terdiri dari byte bernilai 0–255, perhitungan dilakukan pada
rentang 0–255 ("modulo 256").

**Enkripsi**

$$C_i = (a \cdot P_i + b) \bmod 256$$

Versi teks: `C = (a * P + b) mod 256`

**Dekripsi**

$$P_i = a^{-1} \cdot (C_i - b) \bmod 256$$

Versi teks: `P = a_inv * (C - b) mod 256`

Keterangan:

| Simbol | Arti |
|---|---|
| $P_i$ | byte ke-$i$ dari file asli (plainteks) |
| $C_i$ | byte ke-$i$ dari file hasil (cipherteks) |
| $a$ | kunci pengali, **harus ganjil** (1, 3, 5, …, 255) |
| $b$ | kunci geser, 0–255 |
| $a^{-1}$ | kebalikan (invers) dari $a$ modulo 256 |
| $\bmod 256$ | sisa bagi setelah dibagi 256, hasilnya selalu 0–255 |

**Kenapa `a` harus ganjil?**

Agar dekripsi mungkin dilakukan, $a$ harus punya invers modulo 256, yaitu bilangan
$a^{-1}$ sehingga:

$$a \cdot a^{-1} \equiv 1 \pmod{256}$$

Versi teks: `(a * a_inv) mod 256 = 1`

Invers hanya ada bila faktor persekutuan terbesar $a$ dengan 256 adalah 1. Karena
$256 = 2^8$, syarat itu sama dengan "**a bukan bilangan genap**". Kalau `a` genap,
enkripsi masih bisa dijalankan tetapi **tidak bisa dibalik** — karena itu aplikasi
menolak nilai `a` genap dengan pesan kesalahan.

Contoh: $a = 7$ punya invers $a^{-1} = 183$, karena $7 \times 183 = 1281 = 5 \times
256 + 1$. Verifikasi: sisa bagi 1281 oleh 256 adalah 1. ✔

Nilai bawaan aplikasi: **a = 7, b = 13**. Keduanya bebas diubah, dan nilai yang
benar-benar dipakai selalu dicatat di kolom `Kunci_a` dan `Kunci_b`.

---

## 3. Contoh perhitungan: kata "Halo"

Ambil kunci `a = 7`, `b = 13`. Nilai byte tiap huruf diambil dari kode ASCII:
`H = 72`, `a = 97`, `l = 108`, `o = 111`.

| Huruf | $P$ | $7P + 13$ | $C = (7P+13) \bmod 256$ | Huruf hasil? |
|---|---|---|---|---|
| H | 72 | 517 | **5** | (bukan huruf yang bisa dibaca) |
| a | 97 | 692 | **180** | — |
| l | 108 | 769 | **1** | — |
| o | 111 | 790 | **22** | — |

Jadi cipherteks dari "Halo" adalah deretan byte `5, 180, 1, 22`. Kalau dibuka di
Notepad, isinya akan tampak sebagai karakter aneh atau kotak — itu normal, karena
hasil enkripsi memang bukan teks lagi.

**Membalikkannya (dekripsi byte pertama):**

1. Invers dari 7 modulo 256 adalah 183.
2. $P = 183 \times (5 - 13) \bmod 256 = 183 \times (-8) \bmod 256$.
3. $183 \times (-8) = -1464$. Tambahkan 256 berulang sampai hasilnya positif:
   $-1464 + 6 \times 256 = 72$.
4. Byte 72 = huruf **H**. ✔

Kalau dihitung untuk semua byte, hasilnya kembali menjadi "Halo" persis.

> Catatan: contoh ini sengaja memakai teks pendek agar mudah diikuti. Aplikasi
> sebenarnya tidak peduli isi file — semua byte diperlakukan sama, termasuk byte
> yang bukan huruf.

---

## 4. Cara aplikasi memproses file

### 4.1 Tabel substitusi: kunci kecepatan

Menghitung rumus untuk setiap byte satu per satu (misalnya file 400 MB = 419 juta
byte) akan lambat di Python. Karena itu aplikasi menyiapkan **tabel 256 entri** lebih
dulu: tabel ini menyimpan hasil rumus untuk setiap kemungkinan nilai byte.

```python
# affine_cipher.py
def build_encrypt_table(a: int, b: int) -> bytes:
    """Tabel substitusi 256 entri: table[p] = (a*p + b) mod 256."""
    _require_valid_keys(a, b)
    return bytes((a * p + b) % MODULUS for p in range(MODULUS))
```

Setelah tabel jadi, penggantian byte dilakukan sekaligus oleh `bytes.translate`,
yang dieksekusi di bagian inti Python (bahasa C), bukan loop Python:

```python
# affine_cipher.py
def apply_table(data: bytes, table: bytes) -> bytes:
    """Menerapkan tabel substitusi 256 entri pada data."""
    return data.translate(table)


def encrypt_bytes(data: bytes, a: int, b: int) -> bytes:
    return apply_table(data, build_encrypt_table(a, b))
```

Tabel dekripsi dibuat dengan rumus kebalikannya:

```python
# affine_cipher.py
def build_decrypt_table(a: int, b: int) -> bytes:
    """Tabel invers: table[c] = a^-1 * (c - b) mod 256."""
    _require_valid_keys(a, b)
    inverse = mod_inverse(a, MODULUS)
    return bytes((inverse * (c - b)) % MODULUS for c in range(MODULUS))
```

Supaya bisa dipertanggungjawabkan secara akademik, aplikasi juga menyimpan versi
"polos" yang menghitung rumus langsung per byte, tanpa tabel:

```python
# affine_cipher.py
def encrypt_reference(data: bytes, a: int, b: int) -> bytes:
    """Implementasi referensi: loop per byte, langsung dari rumus."""
    _require_valid_keys(a, b)
    return bytes((a * p + b) % MODULUS for p in data)
```

Unit test membandingkan hasil tabel dengan versi polos untuk **seluruh 256 nilai
byte** dan memastikan keduanya identik. Dengan begitu, tabel yang cepat tetap bisa
dibuktikan sama dengan rumus di laporan.

### 4.2 Diproses per potongan 4 MB (streaming)

File tidak dibaca sekaligus ke memori. Aplikasi membaca 4 MB, mengubahnya, menulis
hasilnya, lalu lanjut ke potongan berikutnya:

```python
# pipeline.py — inti proses enkripsi/dekripsi
while True:
    chunk = handle_in.read(CHUNK_SIZE)          # 4 MB
    if not chunk:
        break
    transformed = apply_table(chunk, table)     # substitusi byte
    hash_in.update(chunk)                       # SHA-256 masukan
    hash_out.update(transformed)                # SHA-256 hasil
    for value, count in _count_values(chunk).items():
        counts_in[value] += count               # frekuensi byte masukan
        counts_out[table[value]] += count       # frekuensi byte hasil
    handle_out.write(transformed)
    processed += len(chunk)
```

Konsekuensinya:

- **Memori tetap kecil** walaupun file berukuran ratusan MB, karena hanya beberapa
  buffer 4 MB yang disimpan.
- **Progress bar bergerak nyata**, karena persentase dihitung dari jumlah byte yang
  sudah diproses.
- File hasil ditulis ke `<nama>.part` dulu, lalu diganti nama setelah selesai. Kalau
  proses gagal di tengah jalan, tidak ada file hasil setengah jadi yang terlihat sah.

### 4.3 Nama file hasil

| Operasi | Masukan | Hasil |
|---|---|---|
| Enkripsi | `tugas.pdf` | `tugas.pdf.enc` |
| Dekripsi | `tugas.pdf.enc` | `tugas_decrypted.pdf` |
| Dekripsi (tanpa akhiran `.enc`) | `lagu.mp3` | `lagu_decrypted.mp3` |

Hasil selalu disimpan di folder yang sama dengan file asal.

---

## 5. Metrik yang dicatat

Setiap operasi mencatat metrik berikut ke CSV. Kolom yang tidak berlaku diisi `-`.

| Metrik | Rumus | Arti sederhana | Satuan |
|---|---|---|---|
| Waktu enkripsi/dekripsi | $t = t_{\text{baca}} + t_{\text{transformasi}} + t_{\text{hash}} + t_{\text{entropi}} + t_{\text{tulis}}$ | Lama proses dari file dibuka sampai hasil selesai ditulis, **tanpa** perhitungan avalanche | detik |
| Throughput | $T = \dfrac{\text{ukuran byte} / 1\,048\,576}{t}$ | Berapa MB yang diproses per detik | MB/s |
| Entropi | $H = -\sum_{i=0}^{255} p_i \log_2 p_i$ | Seberapa "acak" sebaran byte (0 = seragam, 8 = sangat acak) | bit/byte |
| Avalanche plainteks | $\dfrac{\text{bit berbeda}}{\text{total bit}} \times 100\%$ | Kalau 1 bit plainteks diubah, berapa persen bit cipherteks ikut berubah | % |
| Avalanche kunci | sama, tetapi kunci diubah 1 bit | Kalau kunci diubah sedikit, berapa persen hasilnya berubah | % |
| CPU | `psutil.cpu_percent()` | Pemakaian CPU komputer selama operasi | % |
| RAM | `psutil.Process().memory_info().rss` | Memori yang dipakai aplikasi | MB |
| SHA-256 | `hashlib.sha256` | Sidik jari isi file untuk membuktikan hasil dekripsi identik | 64 karakter hex |

Versi teks rumus:

- `entropi = -jumlah(p * log2(p))` untuk semua nilai byte yang muncul
- `throughput = (ukuran_byte / 1048576) / waktu_detik`
- `avalanche = (bit_berbeda / total_bit) * 100`

**Cara avalanche diukur:**

1. Plainteks asli dienkripsi → cipherteks $C$.
2. Satu bit plainteks dibalik (byte pertama di-XOR dengan `0x01`), lalu dienkripsi →
   $C'$.
3. Jumlah bit yang berbeda antara $C$ dan $C'$ dihitung (Hamming distance).
4. Persentase = bit berbeda ÷ total bit × 100.

Untuk avalanche kunci, langkahnya sama tetapi yang diubah adalah kunci: `b` diganti
`b XOR 1` (tepat satu bit berubah), sedangkan plainteksnya tetap.

**Kenapa waktunya "seluruh proses"?**

Waktu yang dicatat adalah waktu yang dirasakan penguji: membaca file, mengubah byte,
menghitung hash, menghitung entropi, dan menulis hasil. Perhitungan avalanche
**tidak** ikut dihitung, karena pass itu hanya dibuat untuk keperluan pengukuran,
bukan bagian dari enkripsi yang sebenarnya.

> **Ilustrasi (bukan data resmi pengujian):** pada file 400 MB, waktu tercatat
> **15,9 detik** dengan throughput **25,1 MB/s**. Kalau ditambah pass avalanche,
> total yang dirasakan sekitar **20,2 detik**. Dari 15,9 detik itu, penggantian byte
> sendiri hanya sekitar **0,37 detik**; sisanya didominasi penghitungan entropi dan
> hash. Ini penting disebut di laporan supaya tidak muncul kesimpulan bahwa algoritma
> Affine lambat.

---

## 6. Hasil yang wajar muncul, dan alasannya

Bagian ini menjelaskan pola hasil yang **pasti** muncul pada algoritma ini. Kalau
angka di CSV sesuai pola berikut, berarti aplikasi bekerja benar.

### 6.1 Entropi plainteks = entropi cipherteks

Substitusi Affine hanya **menukar** nilai byte: byte 65 selalu menjadi 212, byte 66
selalu menjadi 219, dan seterusnya. Jumlah kemunculan tiap nilai tidak berubah, hanya
"label" nilainya yang berpindah. Karena entropi dihitung dari jumlah kemunculan,
hasilnya **sama persis**.

Contoh ilustrasi: file acak 19,5 MB menghasilkan entropi plainteks **8,0000 bit/byte**
dan entropi cipherteks **8,0000 bit/byte**. Untuk file teks, keduanya bisa sekitar
4–5 bit/byte, tetapi tetap sama satu sama lain.

**Makna untuk laporan:** enkripsi ini **tidak menambah** keacakan. Ini berbeda dari
cipher modern yang dirancang membuat cipherteks tampak acak.

### 6.2 Avalanche plainteks mendekati 0%

Mengubah 1 bit di plainteks hanya mengubah **satu byte** cipherteks, karena setiap
byte dihitung terpisah. Maksimum hanya 8 bit yang berubah dari total seluruh bit file.

Contoh perhitungan (ilustrasi): file berisi 1000 huruf `A`.

1. `A` = 65 = `01000001`. Bit terakhir dibalik → 64 = `01000000`.
2. $C(65) = (7 \times 65 + 13) \bmod 256 = 212$.
3. $C(64) = (7 \times 64 + 13) \bmod 256 = 205$.
4. 212 = `11010100`, 205 = `11001101` → bit yang berbeda ada **3**.
5. Total bit file = 1000 × 8 = 8000.
6. Avalanche = $3 / 8000 \times 100\% = 0{,}0375\%$.

Untuk file besar, persentasenya mengecil hingga tampil `0.0000` pada pembulatan 4
desimal. **Ini sifat algoritma, bukan kesalahan aplikasi**, dan justru menjadi bahan
analisis: Affine Cipher tidak memiliki difusi.

### 6.3 Avalanche kunci sekitar 25%

Mengubah `b` menjadi `b XOR 1` membuat **semua** byte cipherteks bergeser satu
langkah: $C' = C \pm 1$. Rata-rata, menambah atau mengurangi 1 pada sebuah byte
mengubah sekitar **2 dari 8 bit** (25%).

Contoh: `b = 13` (`00001101`) → `b XOR 1 = 12` (`00001100`), jadi setiap byte hasil
berkurang 1. Ilustrasi pengukuran: **24,9%**.

**Makna untuk laporan:** perubahan kunci menyebar ke seluruh file, tetapi karena
pergeseran nilainya sederhana (bukan difusi sungguhan), pola ini tetap bisa dianalisis
penyerang.

---

## 7. Keamanan dan keterbatasan

Bagian ini penting agar laporan tidak hanya berisi "aplikasi berhasil", tetapi juga
evaluasi.

1. **Ruang kunci sangat kecil.** `a` hanya boleh ganjil (128 kemungkinan), `b` 256
   kemungkinan → total **128 × 256 = 32.768** kunci. Dengan komputer biasa, semua
   kunci bisa dicoba dalam waktu singkat.
2. **Deterministik.** Plainteks yang sama dengan kunci yang sama selalu menghasilkan
   cipherteks yang sama, karena tidak ada nilai acak (IV). Pola data bisa dikenali.
3. **Rentan analisis frekuensi.** Karena pemetaan byte satu-ke-satu, byte yang sering
   muncul di plainteks juga sering muncul di cipherteks (hanya nilainya berbeda).
4. **Tanpa difusi.** Perubahan kecil pada plainteks tidak menyebar (avalanche ≈ 0%).
5. **Tanpa autentikasi.** Tidak ada kode pemeriksa keaslian. Akibatnya, **kunci salah
   tidak menimbulkan error**: aplikasi tetap menghasilkan file (isinya sampah), dan
   baru ketahuan salah setelah dibandingkan dengan hash file asli di tab verifikasi.
6. **Tidak ada metadata.** File `.enc` tidak menyimpan kunci atau nama file, jadi
   pengguna wajib mengingat `a` dan `b` yang dipakai.

Kesimpulan yang jujur untuk laporan: algoritma ini **layak sebagai bahan pembelajaran**
karena rumusnya jelas dan mudah dibuktikan, tetapi **tidak layak dipakai untuk
keamanan nyata**. Pembanding yang tepat adalah AES, yang memakai banyak putaran,
difusi, dan kunci 128/192/256 bit.

---

## 8. Skenario pengujian dan cara membaca CSV

### 8.1 Urutan pengujian

Untuk setiap file: **enkripsi → dekripsi → verifikasi**.

Alasannya, satu percobaan menempati satu baris CSV. Enkripsi membuat baris, dekripsi
mengisi kolom dekripsi baris itu, dan verifikasi mengisi `Status_Hash_Cocok`. Kalau
urutan dibalik, baris tidak bisa dipasangkan.

### 8.2 Matriks pengujian

| Pengujian | Rincian |
|---|---|
| Matriks 10 file | 10 jenis file berbeda, masing-masing **3 kali** agar bisa dirata-rata |
| Uji kunci salah | Enkripsi dengan kunci A, dekripsi dengan kunci B (minimal 2 file) |
| Variasi kunci | 3 kombinasi kunci valid pada satu file untuk membandingkan metrik |
| Verifikasi | Setiap hasil dekripsi dicek lewat tab Cek Kesamaan File |

Isi kolom `Catatan_Pengujian` agar mudah diolah, misalnya `run 1/3`, `run 2/3`,
`skenario kunci-2`, atau `kunci salah`.

### 8.3 Arti nilai `Operasi`

| Nilai | Artinya |
|---|---|
| `Enkripsi` | Baru sampai tahap enkripsi |
| `Enkripsi+Dekripsi` | Sudah didekripsi, belum diverifikasi |
| `Enkripsi+Dekripsi+Verifikasi` | Sudah diverifikasi (lihat `Status_Hash_Cocok`) |
| `Dekripsi` | Baris mandiri, muncul saat kunci salah atau file bukan hasil enkripsi aplikasi |
| `Dekripsi+Verifikasi` | Baris mandiri yang sudah diverifikasi |

### 8.4 Hal yang perlu disebut saat membahas waktu

- Waktu bergantung juga pada **cache disk**: run pertama sering lebih lambat daripada
  run kedua untuk file yang sama. Karena itu dilakukan 3 kali lalu dirata-rata.
- Angka waktu mencakup penghitungan entropi dan SHA-256, bukan hanya penggantian byte.
- Throughput dihitung dari waktu tersebut, sehingga nilainya menggambarkan kecepatan
  **aplikasi**, bukan kecepatan cipher secara terpisah.

---

## 9. Contoh paragraf untuk laporan

Bisa diadaptasi, tinggal ganti angkanya dengan hasil CSV kelompok.

**Tentang implementasi:**

> Algoritma Affine Cipher diimplementasikan pada tingkat byte dengan modulus 256,
> sehingga seluruh jenis file dapat diproses tanpa konversi khusus. Untuk menjaga
> kinerja, aplikasi membangun tabel substitusi 256 entri terlebih dahulu dan
> menerapkannya menggunakan operasi `translate`, lalu membuktikan bahwa hasil tabel
> identik dengan perhitungan rumus langsung melalui pengujian seluruh nilai byte.

**Tentang hasil ukuran dan integritas:**

> Hasil pengujian menunjukkan ukuran cipherteks sama persis dengan ukuran plainteks
> pada seluruh file, dengan tambahan ukuran 0,00%. Hal ini sesuai sifat algoritma yang
> tidak menambahkan header, metadata, maupun padding. Integritas hasil dekripsi
> dibuktikan dengan perbandingan hash SHA-256 dan perbandingan byte-per-byte, yang
> menghasilkan status COCOK untuk seluruh file yang diuji dengan kunci benar.

**Tentang entropi dan avalanche:**

> Nilai entropi cipherteks identik dengan entropi plainteks karena substitusi byte
> bersifat satu-ke-satu sehingga hanya memindahkan frekuensi kemunculan nilai tanpa
> mengubahnya. Avalanche effect pada perubahan plainteks mendekati 0% karena perubahan
> satu bit hanya memengaruhi satu byte cipherteks. Sebaliknya, perubahan satu bit pada
> kunci mengubah seluruh byte cipherteks sehingga menghasilkan avalanche sekitar 25%.
> Kedua temuan ini menunjukkan bahwa algoritma tidak memiliki sifat difusi.

**Tentang keterbatasan:**

> Meskipun berhasil melakukan enkripsi dan dekripsi dengan benar, Affine Cipher
> memiliki ruang kunci yang sangat kecil (32.768 kemungkinan) dan bersifat
> deterministik, sehingga tidak aman untuk penggunaan nyata. Oleh karena itu algoritma
> ini diposisikan sebagai media pembelajaran konsep substitusi, bukan sebagai pengganti
> cipher modern seperti AES.

---

## 10. FAQ sidang, glosarium, dan referensi

### 10.1 Pertanyaan yang sering muncul

**"Kenapa file 400 MB hanya tercatat sekitar 16 detik, padahal kelihatannya cepat?"**
Karena angka itu adalah waktu seluruh proses (baca, substitusi, hash, entropi, tulis)
tanpa pass avalanche. Penggantian byte sendiri hanya sekitar 0,37 detik; sisanya
penghitungan metrik. Kalau ditambah pass avalanche, total yang dirasakan sekitar 20
detik.

**"Kenapa throughput sekitar 25 MB/s, tidak lebih besar?"**
Throughput dihitung dari waktu proses keseluruhan, dan penghitungan entropi di Python
menjadi bagian paling mahal. Ini sudah dijelaskan di Bab Metrik.

**"Kenapa entropi cipherteks tidak naik?"**
Karena Affine Cipher hanya menukar nilai byte, jumlah kemunculan tiap nilai tetap.
Menambah keacakan bukan tujuan algoritma ini.

**"Kenapa avalanche plainteks 0%?"**
Karena setiap byte dihitung terpisah. Mengubah 1 bit plainteks hanya mengubah 1 byte
cipherteks, sehingga persentase terhadap seluruh file sangat kecil dan bisa tampil
0,0000 setelah pembulatan.

**"Kenapa avalanche kunci 25%, bukan 50% atau 100%?"**
Perubahan satu bit pada `b` menggeser setiap byte sebesar ±1. Rata-rata pergeseran itu
mengubah 2 dari 8 bit, yaitu 25%.

**"Kenapa dekripsi dengan kunci salah tidak error?"**
Karena rumus dekripsi selalu menghasilkan byte 0–255 yang valid. Tidak ada penanda
keaslian di dalam file. Kesalahan baru terdeteksi saat hash hasil dekripsi dibandingkan
dengan hash file asli.

**"Kalau filenya `.jpg` atau `.mp4`, apakah tetap bisa?"**
Bisa. Aplikasi tidak peduli format, karena semua file pada akhirnya adalah deretan
byte. Hasil enkripsinya tidak bisa dibuka aplikasi lain sampai didekripsi kembali.

### 10.2 Glosarium

| Istilah | Arti singkat |
|---|---|
| Plainteks | Isi file asli sebelum dienkripsi |
| Cipherteks | Isi file hasil enkripsi |
| Byte | Satuan data 8 bit, bernilai 0–255 |
| Modulo (mod) | Sisa bagi; `20 mod 256 = 20`, `300 mod 256 = 44` |
| Invers modulo | Bilangan yang jika dikalikan menghasilkan sisa 1 |
| Entropi Shannon | Ukuran seberapa merata sebaran nilai byte (0–8 bit/byte) |
| Avalanche effect | Seberapa banyak bit hasil berubah saat masukan diubah sedikit |
| Hamming distance | Jumlah bit yang berbeda antara dua data |
| Throughput | Kecepatan pemrosesan data per detik |
| Deterministik | Masukan sama + kunci sama → hasil selalu sama |
| Difusi | Sifat di mana perubahan kecil menyebar ke seluruh hasil |

### 10.3 Referensi

- William Stallings, *Cryptography and Network Security: Principles and Practice*
  (bab tentang classical encryption techniques).
- Richard A. Mollin, *An Introduction to Cryptography* (bab aritmetika modular).
- Dokumentasi Python: `bytes.translate`, `hashlib`, dan `collections.Counter`.
- Dokumentasi `psutil` untuk pengukuran CPU dan memori.

---

## Berkas terkait

| Berkas | Isi |
|---|---|
| `affine_cipher.py` | Rumus Affine, tabel substitusi, implementasi referensi |
| `metrics.py` | SHA-256, entropi, avalanche, throughput, CPU/RAM |
| `pipeline.py` | Proses per potongan 4 MB, progres, akumulasi metrik |
| `logger.py` | Penulisan dan pembaruan satu baris CSV per percobaan |
| `main.py` | Tampilan Tkinter tiga tab dan pengaturan thread |
| `output/hasil_pengujian.csv` | Data pengujian yang dipakai untuk laporan |
