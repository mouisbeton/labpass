# @kode-komentar-id
# Fungsi File: Mengelola pembacaan dan penulisan berkas blob terenkripsi di disk fisik menggunakan UUID acak.
# File Terhubung:
# - ./app.py: Memanggil save_blob_chunk dan read_blob_chunks untuk operasi unggah dan unduh berkas
# - ./cleanup.py: Menghapus file blob fisik dari disk saat lisensi akses laboratorium kedaluwarsa

import os
import uuid

# var menyimpan direktori folder tempat berkas ciphertext blob disimpan
BLOB_DIR = os.path.join(os.path.dirname(__file__), "blobs")

# periksa apakah folder blobs sudah ada di sistem berkas
if not os.path.exists(BLOB_DIR):
    # buat folder blobs jika belum tersedia
    os.makedirs(BLOB_DIR)


# fungsi untuk menyimpankan data ciphertext ke file blob acak berbasis UUID
def save_blob_data(ciphertext_bytes: bytes) -> str:
    # var membuat nama file UUID unik acak tanpa ekstensi
    blob_id = str(uuid.uuid4())
    # var menentukan path lengkap penyimpan berkas blob di disk
    full_path = os.path.join(BLOB_DIR, blob_id)

    # buka file dalam mode tulis biner (wb)
    with open(full_path, "wb") as f:
        # tulis seluruh bytes ciphertext ke dalam disk
        f.write(ciphertext_bytes)

    return full_path


# fungsi untuk membaca bytes ciphertext dari file blob fisik
def read_blob_data(full_path: str) -> bytes:
    # cek apakah file blob fisik ada pada sistem berkas
    if not os.path.exists(full_path):
        # lempar error FileNotFoundError jika blob telah terhapus
        raise FileNotFoundError(f"Blob fisik tidak ditemukan: {full_path}")

    # buka file dalam mode baca biner (rb)
    with open(full_path, "rb") as f:
        # var membaca seluruh isi byte ciphertext dari disk
        content = f.read()

    return content


# fungsi untuk menghapus file blob fisik secara permanen (crypto-shredding)
def delete_blob_file(full_path: str) -> bool:
    # percabangan mengecek keberadaan berkas fisik sebelum dihapus
    if os.path.exists(full_path):
        # hapus berkas fisik dari disk
        os.remove(full_path)
        return True
    return False