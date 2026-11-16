@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [GAGAL] Folder .venv tidak ditemukan.
    echo Jalankan dulu: python -m venv .venv
    echo Lalu: .venv\Scripts\pip install -r requirement.txt
    exit /b 1
)

echo [1/3] Memasang PyInstaller ke .venv ...
".venv\Scripts\python.exe" -m pip install --upgrade pyinstaller
if errorlevel 1 goto gagal

echo [2/3] Membersihkan hasil build lama ...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "AffineCipher.spec" del /q "AffineCipher.spec"

echo [3/3] Membangun AffineCipher.exe ...
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --onefile --windowed --name "AffineCipher" main.py
if errorlevel 1 goto gagal

echo.
echo Selesai. File hasil: dist\AffineCipher.exe
echo Salin .exe ke folder yang dapat ditulisi (mis. D:\uji\) sebelum dijalankan.
echo Folder output\hasil_pengujian.csv akan dibuat di samping .exe.
exit /b 0

:gagal
echo.
echo [GAGAL] Proses build berhenti. Periksa pesan di atas.
exit /b 1
