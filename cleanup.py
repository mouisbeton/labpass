# @kode-komentar-id
# Fungsi File: Skrip otomatis harian untuk mengecek tanggal access_until dan melakukan crypto-shredding (menghapus wrapped keys dan blob fisik) setelah akses lab berakhir.
# File Terhubung:
# - ./database.py: Membaca batas waktu akses pengguna dan menghapus record metadata SQLite
# - ./storage.py: Menghapus file fisik ciphertext blob dari disk

import os
import sqlite3
from datetime import datetime
from database import DB_PATH
from storage import delete_blob_file


# fungsi utama eksekusi penghapusan crypto-shredding harian
def run_daily_cleanup():
    # var mendapatkan tanggal dan waktu hari ini (format YYYY-MM-DD)
    today_str = datetime.utcnow().strftime("%Y-%m-%d")
    print(
        f"[{datetime.now()}] Menjalankan skrip pembersihan harian (Crypto-shredding)..."
    )

    # cek apakah file basis data SQLite tersedia
    if not os.path.exists(DB_PATH):
        print("Database belum dibuat. Pembersihan dibatalkan.")
        return

    # var koneksi langsung ke SQLite
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # 1. Cari seluruh ID pengguna yang batas masa akses labnya (access_until) telah lewat/kedaluwarsa
        cursor.execute(
            "SELECT id, username, access_until FROM users WHERE access_until < ?",
            (today_str,),
        )
        # var daftar pengguna yang izin aksesnya telah berakhir
        expired_users = cursor.fetchall()

        # percabangan jika ada pengguna yang kedaluwarsa
        if not expired_users:
            print("Tidak ada akun mahasiswa yang kedaluwarsa hari ini.")
            return

        # loop memproses pembersihan data pengguna satu per satu
        for user in expired_users:
            user_id = user["id"]
            username = user["username"]
            print(
                f"Memproses crypto-shredding untuk pengguna: {username} (ID: {user_id})"
            )

            # ambil seluruh item berkas milik pengguna yang kedaluwarsa
            cursor.execute(
                "SELECT id FROM items WHERE user_id = ?", (user_id,)
            )
            user_items = cursor.fetchall()

            # loop memproses pembersihan berkas blob dan kunci
            for item in user_items:
                item_id = item["id"]

                # ambil lokasi file blob fisik dari tabel copies
                cursor.execute(
                    "SELECT blob_path FROM copies WHERE item_id = ?",
                    (item_id,),
                )
                copies = cursor.fetchall()

                # loop hapus setiap berkas blob ciphertext dari disk fisik
                for copy_rec in copies:
                    blob_path = copy_rec["blob_path"]
                    # panggil fungsi penghapusan blob fisik
                    deleted = delete_blob_file(blob_path)
                    if deleted:
                        print(f"  -> File blob dihapus: {blob_path}")

            # hapus record terenkripsi (metadata berkas & data pribadi) milik pengguna;
            # foreign key SQLite tidak aktif, jadi CASCADE tidak berjalan
            cursor.execute("DELETE FROM records WHERE user_id = ?", (user_id,))

            # 2. Hapus data pengguna dari tabel users (FK ON DELETE CASCADE akan menghapus items, copies, & wrapped_keys)
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            print(
                f"  -> Metadata pengguna & wrapped keys {username} berhasil dihapus dari SQLite."
            )

        # simpan seluruh transaksi pembersihan ke basis data
        conn.commit()
        print("Proses pembersihan harian selesai dengan sukses.")

    except Exception as e:
        # batalkan transaksi jika terjadi kesalahan
        conn.rollback()
        print(f"Terjadi kesalahan saat pembersihan harian: {str(e)}")
    finally:
        # tutup koneksi database
        conn.close()


# eksekusi skrip pembersihan saat dipanggil langsung (dapat didaftarkan ke cron job / task scheduler)
if __name__ == "__main__":
    run_daily_cleanup()