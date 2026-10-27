# @kode-komentar-id
# Fungsi File: Mengelola inisialisasi basis data SQLite,pembuatan tabel metadata (users, items, copies, wrapped_keys), serta koneksi database.
# File Terhubung:
# - ./app.py: Menggunakan fungsi get_db dan init_db untuk operasi query metadata pengguna dan berkas terenkripsi
# - ./cleanup.py: Membaca batas waktu access_until pengguna untuk proses crypto-shredding

import sqlite3
import os
from flask import g

# var menyimpan path direktori lokasi file database SQLite berada
DB_PATH = os.path.join(os.path.dirname(__file__), "labaccess.db")


# fungsi untuk mendapatkan koneksi database SQLite aktif per request HTTP
def get_db():
    # cek apakah koneksi database sudah pernah dibuat dalam konteks request 'g' Flask
    if "db" not in g:
        # simpan instance koneksi database baru ke dalam g.db
        g.db = sqlite3.connect(DB_PATH)
        # ubah row_factory agar hasil query berupa dict (Row) yang mudah diakses berdasarkan nama kolom
        g.db.row_factory = sqlite3.Row
    return g.db


# fungsi untuk menutup koneksi database saat request berakhir
def close_db(e=None):
    # var mengambil objek koneksi database dari konteks request 'g' jika ada
    db = g.pop("db", None)

    # cek apakah objek koneksi database ditemukan
    if db is not None:
        # tutup koneksi basis data
        db.close()


# fungsi untuk menginisialisasi tabel-tabel metadata SQLite
def init_db():
    # var koneksi database SQLite langsung ke file DB_PATH
    conn = sqlite3.connect(DB_PATH)
    # var cursor database untuk mengeksekusi perintah DDL/DML
    cursor = conn.cursor()

    # eksekusi query pembuatan tabel metadata users jika belum ada
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        login_key BLOB NOT NULL,
        salt BLOB NOT NULL,
        access_until TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # eksekusi query pembuatan tabel metadata items (berkas terenkripsi) jika belum ada
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS items (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        filename_enc BLOB NOT NULL,
        mime_type_enc BLOB NOT NULL,
        sha256_orig TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );
    """)

    # eksekusi query pembuatan tabel wrapped_keys (penyimpanan KEK-wrapped item secret) jika belum ada
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS wrapped_keys (
        item_id TEXT NOT NULL,
        cipher TEXT NOT NULL,
        wrapped_secret BLOB NOT NULL,
        PRIMARY KEY (item_id, cipher),
        FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE CASCADE
    );
    """)

    # eksekusi query pembuatan tabel copies (penyimpanan jalur berkas blob fisik per algoritma) jika belum ada
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS copies (
        id TEXT PRIMARY KEY,
        item_id TEXT NOT NULL,
        cipher TEXT NOT NULL,
        blob_path TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE CASCADE
    );
    """)

    # eksekusi query pembuatan tabel records (record kecil terenkripsi: metadata berkas & data pribadi) jika belum ada
    # record_id = "<item_id>/meta" untuk nama & mime type berkas, "profile" untuk data pribadi
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS records (
        user_id TEXT NOT NULL,
        record_id TEXT NOT NULL,
        cipher TEXT NOT NULL,
        blob BLOB NOT NULL,
        wrapped_secret BLOB NOT NULL,
        PRIMARY KEY (user_id, record_id, cipher),
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );
    """)

    # simpan perubahan skema ke file database fisik
    conn.commit()
    # tutup koneksi database inisialisasi
    conn.close()


# eksekusi inisialisasi tabel saat modul dipanggil langsung
if __name__ == "__main__":
    init_db()