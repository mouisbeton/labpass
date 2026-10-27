# @kode-komentar-id
# Fungsi File: Menangani rute HTTP (Upload, List, Download, Delete), pemeriksaan hak akses (ownership check), pemrosesan unggahan di RAM (In-Memory Stream), serta render UI Jinja2.
# File Terhubung:
# - ./database.py: Untuk membaca dan mengupdate tabel SQLite metadata pengguna, item, copies, dan wrapped_keys
# - ./storage.py: Untuk menyimpan dan membaca berkas blob ciphertext pada disk
# - ./crypto_stub.py (atau labcrypto): Modul kriptografi untuk enkripsi/dekripsi dan key wrapping
# - ./templates/dashboard.html: Tampilan UI antarmuka utama pengguna

import hashlib
import io
import os
import uuid
from flask import (
    Flask,
    Request,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

import auth
from database import get_db
from storage import delete_blob_file, read_blob_data, save_blob_data

# ==============================================================================
# IMPORT KRIPTO (Menggunakan Crypto Interface Person 1)
# ==============================================================================
# var modul antarmuka kriptografi (dipakai setelah Person 1 menyelesaikan modulnya)
try:
    from labcrypto import (
        decrypt_item,
        encrypt_item,
        new_item_secret,
        unwrap_secret,
        wrap_secret,
    )
except ImportError:

    # Stub sementara (Mock) apabila modul Person 1 belum siap sepenuhnya
    def new_item_secret():
        # var mengembalikan 32 byte item secret acak sementara
        return os.urandom(32)

    def wrap_secret(kek, secret, ctx):
        # var mengembalikan wrapped secret tiruan
        return b"WRAPPED_" + secret

    def unwrap_secret(kek, wrapped, ctx):
        # var mengembalikan item secret hasil unwrap
        return wrapped[8:]

    def encrypt_item(cipher, plaintext, secret, ctx):
        # var mengembalikan ciphertext tiruan sederhana
        return b"ENC_" + cipher.encode() + b"_" + plaintext

    def decrypt_item(cipher, ciphertext, secret, ctx):
        # var mengembalikan plaintext hasil dekripsi tiruan
        prefix = b"ENC_" + cipher.encode() + b"_"
        if ciphertext.startswith(prefix):
            return ciphertext[len(prefix) :]
        return ciphertext


# ==============================================================================
# IN-MEMORY UPLOAD STREAM CONFIGURATION
# ==============================================================================
# Kustomisasi Request Flask agar stream berkas yang diunggah diproses penuh di RAM (BytesIO)
class InMemoryRequest(Request):
    # override fungsi internal _get_file_stream agar plaintext tidak tersimpan di temp file disk
    # def _get_file_stream(
    #     self, total_bytes, content_type, filename=None, content_length=None
    # ):
    def _get_file_stream(self, *args, **kwargs):
        # var mengembalikan instansi BytesIO di memori RAM
        return io.BytesIO()


# inisialisasi aplikasi Flask
app = Flask(__name__)
# pasang kelas kustom request pengolah unggahan RAM
app.request_class = InMemoryRequest
# var membatasi ukuran maksimal unggahan sebesar 100 MB di memori RAM
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
# var secret key untuk cookie sesi Flask
app.secret_key = os.urandom(24)

# pasang modul auth: CSRF, flag cookie sesi, tabel users/consents, teardown database,
# serta rute /register, /login, /logout, /change-password, /withdraw-consent
auth.init_app(app)

# ==============================================================================
# FLASK ROUTES
# ==============================================================================


# Rute utama dasbor: menampilkan daftar berkas milik pengguna yang sedang login
@app.route("/")
@app.route("/dashboard")
@auth.login_required
def dashboard():
    db = get_db()
    # nama pengguna untuk sapaan di dasbor
    username = db.execute(
        "SELECT username FROM users WHERE id = ?", (g.user_id,)
    ).fetchone()["username"]
    # var mengambil daftar berkas milik pengguna saat ini (Ownership Check via WHERE user_id)
    items = db.execute(
        "SELECT id, sha256_orig, created_at FROM items WHERE user_id = ? ORDER BY created_at DESC",
        (g.user_id,),
    ).fetchall()

    return render_template("dashboard.html", items=items, username=username)


# Rute unggah berkas: diproses sepenuhnya di RAM, dienkripsi ke 3 algoritma (AES, DES, RC4)
@app.route("/upload", methods=["POST"])
@auth.login_required
def upload_file():
    # cek apakah ada berkas pada request unggahan
    if "file" not in request.files:
        flash("No file part in the request.")
        return redirect(url_for("dashboard"))

    # var berkas yang diunggah dari form
    uploaded_file = request.files["file"]

    # cek apakah nama file kosong
    if uploaded_file.filename == "":
        flash("File name must not be empty.")
        return redirect(url_for("dashboard"))

    # var membaca seluruh bytes isi berkas dari stream BytesIO di RAM
    plaintext_bytes = uploaded_file.read()

    # cek jika ukuran file melebihi 0 byte
    if len(plaintext_bytes) == 0:
        flash("Empty files cannot be uploaded.")
        return redirect(url_for("dashboard"))

    # var menghitung hash SHA-256 berkas asli untuk verifikasi keutuhan (integrity check) saat diunduh
    sha256_orig = hashlib.sha256(plaintext_bytes).hexdigest()

    # var membuat ID item berkas baru berbasis UUID
    item_id = str(uuid.uuid4())
    # KEK dari KEK cache di memori server (auth.login_required)
    kek = g.kek

    # var daftar algoritma cipher yang wajib digunakan (AES, DES, RC4)
    ciphers = ["aes-gcm", "des-cbc", "rc4"]
    # var koneksi basis data
    db = get_db()

    # var kunci rahasia item baru yang segar (fresh secret) untuk item ini
    # item_secret = new_item_secret()

    # simpan metadata dasar item ke basis data SQLite
    # Catatan: Nama berkas dan mime type dienkripsi atau disimpan secara pseudonim
    db.execute(
        "INSERT INTO items (id, user_id, filename_enc, mime_type_enc, sha256_orig) VALUES (?, ?, ?, ?, ?)",
        (
            item_id,
            g.user_id,
            uploaded_file.filename.encode("utf-8"),
            uploaded_file.mimetype.encode("utf-8"),
            sha256_orig,
        ),
    )

    # loop melakukan enkripsi berkas ke dalam 3 algoritma independen
    for cipher_name in ciphers:

        item_secret = new_item_secret()
        
        # var tuple konteks autentikasi metadata (user_id, item_id, cipher_name)
        # ctx = (g.user_id, item_id, cipher_name)
        ctx = (str(g.user_id), str(item_id), cipher_name)

        # 1. Pembungkusan Kunci (Key Wrapping) menggunakan KEK & AES-GCM
        wrapped_key = wrap_secret(kek, item_secret, ctx)

        # simpan wrapped secret per algoritma ke tabel wrapped_keys
        db.execute(
            "INSERT INTO wrapped_keys (item_id, cipher, wrapped_secret) VALUES (?, ?, ?)",
            (item_id, cipher_name, wrapped_key),
        )

        # 2. Enkripsi Berkas Polos (Plaintext) menjadi Ciphertext Blob
        ciphertext_blob = encrypt_item(
            cipher_name, plaintext_bytes, item_secret, ctx
        )

        # 3. Simpan Ciphertext Blob ke folder blob fisik disk
        blob_path = save_blob_data(ciphertext_blob)

        # var UUID untuk entri salinan berkas (copy)
        copy_id = str(uuid.uuid4())
        # simpan metadata salinan berkas ke tabel copies
        db.execute(
            "INSERT INTO copies (id, item_id, cipher, blob_path) VALUES (?, ?, ?, ?)",
            (copy_id, item_id, cipher_name, blob_path),
        )

    # simpan transaksi basis data
    db.commit()

    flash(
        f"'{uploaded_file.filename}' was encrypted and stored with 3 algorithms (AES, DES, RC4)."
    )
    return redirect(url_for("dashboard"))


# Rute unduh & dekripsi berkas: Pengguna memilih algoritma (AES, DES, atau RC4) yang akan didekripsi
@app.route("/download/<item_id>/<cipher_name>")
@auth.login_required
def download_file(item_id, cipher_name):
    # var koneksi database
    db = get_db()

    # --- OWNERSHIP CHECK ---
    # pastikan item yang diminta benar-benar milik pengguna yang sedang terautentikasi
    item = db.execute(
        "SELECT * FROM items WHERE id = ? AND user_id = ?",
        (item_id, g.user_id),
    ).fetchone()

    # percabangan mengecek keberadaan berkas dan hak akses kepemilikan
    if item is None:
        flash("Access denied or file not found.")
        return redirect(url_for("dashboard"))

    # ambil metadata salinan berkas berdasarkan cipher yang dipilih
    copy_record = db.execute(
        "SELECT * FROM copies WHERE item_id = ? AND cipher = ?",
        (item_id, cipher_name),
    ).fetchone()

    # percabangan jika salinan algoritma tidak ditemukan
    if copy_record is None:
        flash(f"Copy '{cipher_name}' not found.")
        return redirect(url_for("dashboard"))

    # ambil wrapped secret dari basis data
    wrapped_record = db.execute(
        "SELECT wrapped_secret FROM wrapped_keys WHERE item_id = ? AND cipher = ?",
        (item_id, cipher_name),
    ).fetchone()

    # var KEK dari sesi login pengguna
    kek = g.kek
    # var tuple konteks autentikasi data
    ctx = (g.user_id, item_id, cipher_name)

    try:
        # 1. Opens & Unwraps Item Secret dengan KEK
        item_secret = unwrap_secret(kek, wrapped_record["wrapped_secret"], ctx)

        # 2. Baca isi file ciphertext blob dari disk
        ciphertext_blob = read_blob_data(copy_record["blob_path"])

        # 3. Dekripsi ciphertext kembali menjadi plaintext
        plaintext_bytes = decrypt_item(
            cipher_name, ciphertext_blob, item_secret, ctx
        )

        # 4. Verifikasi keutuhan berkas (SHA-256 Integrity Validation)
        decrypted_sha256 = hashlib.sha256(plaintext_bytes).hexdigest()
        if decrypted_sha256 != item["sha256_orig"]:
            raise ValueError(
                "Integritas data rusak: SHA-256 tidak cocok dengan berkas asli!"
            )

    except Exception as err:
        flash(f"Could not decrypt or verify the file: {err}")
        return redirect(url_for("dashboard"))

    # var mengembalikan data file terdekripsi langsung ke browser pengguna dari RAM
    return send_file(
        io.BytesIO(plaintext_bytes),
        download_name=item["filename_enc"].decode("utf-8"),
        as_attachment=True,
    )


# Rute hapus berkas: Menghapus entri SQLite dan berkas blob fisik secara permanen
@app.route("/delete/<item_id>", methods=["POST"])
@auth.login_required
def delete_file(item_id):
    # var koneksi database
    db = get_db()

    # --- OWNERSHIP CHECK ---
    # pastikan item yang akan dihapus milik pengguna yang sedang terautentikasi
    item = db.execute(
        "SELECT * FROM items WHERE id = ? AND user_id = ?",
        (item_id, g.user_id),
    ).fetchone()

    if item is None:
        flash("Delete failed: file not found or access denied.")
        return redirect(url_for("dashboard"))

    # ambil seluruh jalur file blob fisik yang terkait dengan item ini
    copies = db.execute(
        "SELECT blob_path FROM copies WHERE item_id = ?", (item_id,)
    ).fetchall()

    # loop menghapus setiap file blob fisik dari disk
    for copy_rec in copies:
        delete_blob_file(copy_rec["blob_path"])

    # hapus metadata item dari SQLite (ON DELETE CASCADE akan membersihkan tabel copies & wrapped_keys)
    db.execute("DELETE FROM items WHERE id = ?", (item_id,))
    db.commit()

    flash("The file and all 3 of its encrypted copies were deleted.")
    return redirect(url_for("dashboard"))


# eksekusi server web Flask
if __name__ == "__main__":
    # flag Secure membuat browser tidak mengirim cookie lewat http://localhost;
    # matikan hanya untuk server pengembangan lokal
    app.config["SESSION_COOKIE_SECURE"] = False
    app.run(debug=True, port=5001)