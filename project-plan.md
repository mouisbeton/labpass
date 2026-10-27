# Project Plan: Secure Lab Access Enrollment Portal

## 1. Scenario

A web portal where students enroll for face-recognition door access to the campus Computer Science labs.

- **Users:** applicants (students) only.
- **Out of scope:** approval of applications and the door lock itself. Approval and face-template enrollment are handled by the lab's existing system; our app is the secure intake and storage portal.
- **Re-enrollment:** happens only when the student logs in and approves it (e.g. when the recognition model changes).
- **Retention:** all of a student's data is deleted when their lab access ends (`access_until`, set from the KRS semester).

## 2. Data and Classification

UU PDP (Law 27/2022) is the primary law; GDPR is the international reference.

| Data | UU PDP category | Notes |
|---|---|---|
| Face enrollment video | **Specific (biometric)** | Biometric because it is used for recognition (GDPR Art. 9, Recital 51). Kept only for re-enrollment; deleted when access ends. |
| KTM scan | General, high risk | Identity document. Proves student status. |
| Name, NRP, phone, email | General | Identifies the student. |
| KRS | General | Proves enrollment in a course that uses the lab. |
| Signed lab rules agreement | General | Contains the student's signature. |
| Applicant's age | Possibly **specific (child)** | Some first-year students are 17. The portal is for applicants aged 18+ (confirmed at registration); under-18 students use the lab's offline process, since children's data needs a parent's or guardian's consent under UU PDP. |
| Lab ID, access period, timestamps | Not personal on their own | Become personal once linked to a student. |

- **No KTP.** Data minimisation and purpose limitation: lab access needs proof of student status, not citizenship, religion or marital status. (Religion is general data under UU PDP but a special category under GDPR Art. 9.)
- **KTM** is not a bank card on our campus. If it were, students would cover the card number before scanning.
- **Consent:** recorded with what was agreed, when, and the consent text version. Withdrawing consent triggers the same deletion as access expiry.
- **Power imbalance:** students and the campus are not equals, so consent may not be freely given. The report names an alternative that needs no biometrics (access through the lab assistant); we don't build it.
- **Login username:** chosen by the student, stored in plaintext as a pseudonymous identifier. Usernames matching the NRP format are rejected, and a hint says not to use name or NRP. All personal data is encrypted.

## 3. Crypto Decisions

**Every item is stored three times, once under each cipher**, with independent keys. Limitation acknowledged: confidentiality is only as strong as the weakest copy; a real deployment would keep only the AES-GCM copy.

| | AES | DES | RC4 |
|---|---|---|---|
| Scheme | AES-256-GCM | DES-CBC + HMAC-SHA256 (encrypt-then-MAC) | RC4-drop3072 + HMAC-SHA256 |
| IV / nonce | Nonce = chunk counter (unique key per item) | Random 8-byte IV per chunk | None; fresh key per chunk |
| Integrity | GCM tag | HMAC, verified **before** decrypting | HMAC |
| Per-key limit | — | Subkey per chunk via HKDF (≤ 8 MB per key, 64-bit block) | Key per chunk via HKDF |

- **Every write gets a new random item secret**, including profile updates and re-enrollment. The AES nonce is the chunk counter, so re-encrypting under an old secret would reuse key + nonce and break GCM.
- GCM is only defined for 128-bit block ciphers, so DES cannot use it.
- **All three ciphers use 1 MB chunks**, so the benchmark compares ciphers, not file layouts.
- Every chunk's tag/HMAC covers: user ID, item ID, cipher, chunk index, last-chunk flag (detects tampering, reordering, truncation, swapping between students).
- Filename and MIME type are encrypted in a metadata record.
- Personal data is encrypted as **one JSON record per cipher**.
- **Benchmark only:** AES-CBC + HMAC as a control (separates cipher effect from mode effect).

## 4. Key Handling

```
password ─ Argon2id (t=3, m=64 MiB, p=4; RFC 9106) ─► master
master ─ HKDF "labaccess/login" ─► login_key (stored, compared with hmac.compare_digest)
master ─ HKDF "labaccess/kek"   ─► KEK (never stored)

per item × cipher:
  random 32-byte secret ─ wrapped with KEK using AES-GCM only ─► stored
  secret ─ HKDF with labels ─► enc key(s) + MAC key
```

- **One Argon2id run**, split into two independent keys with HKDF.
- Wrapped keys use **AES-GCM only**: a key must be protected by something at least as strong as what it protects.
- Password change re-wraps the item keys only; no re-encryption of files.
- Forgotten password means the data is lost; the student re-registers.
- **KEK cache (option B):** server memory, one worker with several threads, keyed by a random server-side session ID with a lock. The KEK is never put in the Flask session cookie.
  - New session ID at login; cookie `Secure`, `HttpOnly`, `SameSite=Lax`.
  - KEK wiped at logout, after 15 min idle, and after 2 h absolute.

## 5. Architecture

```
Browser ──HTTPS──► Flask (1 worker, threads)
                     ├─ auth     (Argon2id + HKDF, username rules, consent, CSRF)
                     ├─ routes   (upload / list / download / delete, ownership check on every route)
                     └─ crypto/  (AES, DES, RC4 behind one interface)
                           │
          ┌────────────────┴────────────────┐
     SQLite (metadata)                 Blob folder
     users, items, copies,             random-UUID filenames,
     wrapped keys                      ciphertext chunks only
```

- **Stack:** Python, Flask, PyCryptodome (all three ciphers), argon2-cffi, SQLite.
- **Uploads stay in memory** (custom `Request._get_file_stream` returning `BytesIO`) so plaintext never touches disk. `MAX_CONTENT_LENGTH` = 100 MB. No nginx request buffering.
- The benchmark imports the **same crypto module** as the app.
- **Daily cleanup script** deletes wrapped keys and blobs after `access_until` (crypto-shredding).
- **Download:** the student picks which copy (AES, DES or RC4) to decrypt; the page shows that its SHA-256 matches the original's. This is the visible proof of "comes back intact".

**Crypto interface (agreed on day 1):**
```python
derive_keys(password, salt)                 -> (login_key, kek)   # one Argon2id run + HKDF
new_item_secret()                           -> item_secret        # fresh for every write
wrap_secret(kek, item_secret, ctx)          -> wrapped            # AES-GCM
unwrap_secret(kek, wrapped, ctx)            -> item_secret        # raises on tampering
encrypt_item(cipher, plaintext, item_secret, ctx) -> blob
decrypt_item(cipher, blob, item_secret, ctx)      -> plaintext    # raises on tampering
# cipher = "aes-gcm" | "des-cbc" | "rc4"   (+ "aes-cbc" control, benchmark only)
# ctx = user ID, item ID, cipher
```

**Known limitations:** weakest-copy problem; a weak password weakens all three copies; RAM can reach disk through swap; Python cannot reliably wipe memory; root on the server can read cached KEKs of logged-in students.

## 6. Team Split

| Person | Code | Report section (word budget) |
|---|---|---|
| **1** | Crypto core: cipher modules, chunk format, HKDF, key wrapping, tamper tests | Crypto design + key handling (~300) |
| **2** | Auth, sessions, KEK cache, consent screen | Scenario and why the app is useful, data classification, consent (~250) |
| **3** | Routes, storage, DB, in-memory uploads, cleanup script, UI | Architecture, storage, deletion, limitations (~250) |
| **4** | Benchmark harness and analysis | Analysis (~300 + one chart/table); merges the report and checks for contradictions |

- **Tamper tests** (person 1), per cipher, must fail loudly on: one flipped byte, reordered chunks, deleted last chunk, blob swapped between two students.
- **Shared topics have one author:** key handling is written by person 1, checked by person 2; the session/KEK cache is written by person 2, checked by person 3.

## 7. Rules

1. **Everyone commits their own code and report section from their own account.** Marks depend on it; nobody commits on someone else's behalf.
2. The crypto interface is agreed on day 1; persons 2 and 3 work against a stub until person 1's module is ready.
3. Person 1 delivers the crypto module first so person 4 can benchmark the real code early.
4. Report sections are due 3–4 days before the real deadline so person 4 can merge.
5. Each person reviews one other person's code.
6. **Everyone saves the link and screenshots of every AI conversation they used** (the brief requires it). Person 4 collects them in the README.

**Still open:** benchmark details (file sizes, repetitions, what to plot).
