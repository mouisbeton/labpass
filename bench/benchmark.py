"""Cipher benchmark for the Lab Access Enrollment Portal.

Run from the repo root:
    python -m bench.benchmark            # full run (1 KiB .. 100 MiB, 10 runs)
    python -m bench.benchmark --quick    # fast smoke test (small sizes, 3 runs)
    python -m bench.benchmark --backend stub
    python -m bench.benchmark --ciphers aes-gcm des-cbc   # only some ciphers (results stay in raw/)

Backends:
    real  - labcrypto.encrypt_item / decrypt_item (person 1's module, same code as the app);
            stops if any cipher is not implemented there yet
    stub  - bench/stub_cipher.py, a temporary stand-in for every cipher
    auto  - per cipher: real if labcrypto supports it, otherwise stub (default)
Only an all-real full run writes to results/; anything else goes to results/raw/ (gitignored).

What it measures:
    1. encrypt / decrypt speed per cipher per size
    2. storage overhead (ciphertext size - plaintext size)
    3. key cost: derive_keys, wrap_secret, unwrap_secret
    4. upload cost: new secret + wrap + encrypt, for all three app ciphers
    5. HMAC-SHA256 alone over the same 1 MiB chunks, to split cipher time from MAC time
"""

from __future__ import annotations

import argparse
import csv
import gc
import hashlib
import hmac
import json
import math
import os
import platform
import statistics
import sys
import time
from datetime import datetime
from importlib import metadata
from pathlib import Path

from labcrypto import derive_keys, new_item_secret, new_salt, unwrap_secret, wrap_secret

KiB = 1024
MiB = 1024 * KiB

FULL_SIZES = [1 * KiB, 100 * KiB, 1 * MiB, 10 * MiB, 50 * MiB, 100 * MiB]
QUICK_SIZES = [1 * KiB, 100 * KiB, 1 * MiB]
APP_CIPHERS = ("aes-gcm", "des-cbc", "rc4")
BENCH_CIPHERS = APP_CIPHERS + ("aes-cbc",)  # aes-cbc = control, benchmark only

# A timed run that lasts only a few ms is easily disturbed by Windows (an
# interrupt or a core switch can double it). So each timed run repeats the
# operation until it lasts at least this long, then divides by the repeats.
# The repeat count is measured once per measurement, before the timed runs.
TARGET_RUN_SECONDS = 0.25

RESULTS_DIR = Path(__file__).parent / "results"


def size_label(n: int) -> str:
    return f"{n // MiB} MiB" if n >= MiB else f"{n // KiB} KiB"


def load_backend(name: str, ciphers=BENCH_CIPHERS):
    """Pick real or stub code per cipher.

    Person 1 adds ciphers one at a time, so in auto mode each cipher uses the
    real labcrypto code if it already supports that cipher, else the stub.
    Returns (overall, {cipher: source}, enc, dec) where overall is
    "real" only if every cipher is real.
    """
    from bench import stub_cipher

    real_enc = real_dec = None
    if name in ("real", "auto"):
        try:
            from labcrypto import decrypt_item as real_dec, encrypt_item as real_enc
        except ImportError:
            pass

    sources = {}
    for c in ciphers:
        sources[c] = "stub"
        if real_enc is None:
            continue
        try:  # probe: does the real module support this cipher yet?
            secret = new_item_secret()
            ctx = ("probe-user", "probe-item", c)
            if real_dec(c, real_enc(c, b"probe", secret, ctx), secret, ctx) == b"probe":
                sources[c] = "real"
        except (ValueError, NotImplementedError):
            pass

    if name == "real" and "stub" in sources.values():
        missing = [c for c, s in sources.items() if s == "stub"]
        sys.exit(f"labcrypto does not support {missing} yet. Use --backend auto or stub.")

    def enc(c, *args):
        return (real_enc if sources[c] == "real" else stub_cipher.encrypt_item)(c, *args)

    def dec(c, *args):
        return (real_dec if sources[c] == "real" else stub_cipher.decrypt_item)(c, *args)

    values = set(sources.values())
    overall = "real" if values == {"real"} else "stub" if values == {"stub"} else "mixed"
    print("Cipher code:", ", ".join(f"{c}={s}" for c, s in sources.items()))
    if overall != "real":
        print("!! Some ciphers use the STUB: numbers are for testing the harness only, not the report.\n")
    return overall, sources, enc, dec


def summarize(times: list[float]) -> dict:
    mean = statistics.fmean(times)
    return {
        "runs": len(times),
        "median_s": statistics.median(times),
        "min_s": min(times),
        "max_s": max(times),
        # coefficient of variation: how noisy the runs were (lower = more trustworthy)
        "cv_pct": (statistics.stdev(times) / mean * 100) if len(times) > 1 and mean else 0.0,
    }


def machine_info(backend: str) -> dict:
    def ver(pkg):
        try:
            return metadata.version(pkg)
        except metadata.PackageNotFoundError:
            return "?"

    return {
        "date": datetime.now().isoformat(timespec="seconds"),
        "backend": backend,
        "os": platform.platform(),
        "cpu": platform.processor() or platform.machine(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "pycryptodome": ver("pycryptodome"),
        "argon2-cffi": ver("argon2-cffi"),
    }


def timed(fn, inner: int = 1) -> float:
    """Seconds per call of fn(), averaged over `inner` back-to-back calls."""
    gc.collect()
    start = time.perf_counter()
    for _ in range(inner):
        fn()
    return (time.perf_counter() - start) / inner


def calibrate(fn) -> int:
    """How many back-to-back calls of fn() make one timed run last ~TARGET_RUN_SECONDS.
    Doubles the count until the batch takes >= 1/10 of the target, then scales up."""
    fn()  # warm up caches and imports
    n = 1
    while True:
        start = time.perf_counter()
        for _ in range(n):
            fn()
        elapsed = time.perf_counter() - start
        if elapsed >= TARGET_RUN_SECONDS / 10:
            return max(1, math.ceil(n * TARGET_RUN_SECONDS / elapsed))
        n *= 2


# ---------------------------------------------------------------- 3. key cost

def bench_keys(warmup: int, runs: int, raw_rows: list) -> list[dict]:
    print("Key cost")
    salt = new_salt()
    _, kek = derive_keys("benchmark password", salt)
    ctx = ("bench-user", "bench-item", "aes-gcm")
    secret = new_item_secret()
    wrapped = wrap_secret(kek, secret, ctx)

    ops = {
        "derive_keys": lambda: derive_keys("benchmark password", salt),
        "wrap_secret": lambda: wrap_secret(kek, secret, ctx),
        "unwrap_secret": lambda: unwrap_secret(kek, wrapped, ctx),
    }
    rows = []
    for op, fn in ops.items():
        inner = calibrate(fn)
        times = []
        for r in range(warmup + runs):
            t = timed(fn, inner)
            if r >= warmup:
                times.append(t)
                raw_rows.append({"test": "key", "op": op, "run": r - warmup, "seconds": t})
        s = summarize(times)
        rows.append({"op": op, **s})
        print(f"  {op:<14} median {s['median_s'] * 1000:10.3f} ms   cv {s['cv_pct']:5.1f}%")
    print()
    return rows


# ------------------------------------------------- 1+2. cipher speed, overhead

def bench_ciphers(sizes, warmup, runs, enc, dec, raw_rows, ciphers=BENCH_CIPHERS) -> list[dict]:
    print("Cipher speed (median MiB/s)")
    ciphers = list(ciphers)
    rows = []
    for size in sizes:
        data = os.urandom(size)  # generated outside the timer
        # repeat counts per cipher and direction, so every timed run lasts ~TARGET_RUN_SECONDS
        inner = {}
        for c in ciphers:
            ctx = ("bench-user", f"calibrate-{size}", c)
            secret = new_item_secret()
            blob = enc(c, data, secret, ctx)
            inner[(c, "encrypt")] = calibrate(lambda: enc(c, data, secret, ctx))
            inner[(c, "decrypt")] = calibrate(lambda: dec(c, blob, secret, ctx))
        times = {(c, op): [] for c in ciphers for op in ("encrypt", "decrypt")}
        overhead = {}
        for r in range(warmup + runs):
            # rotate cipher order each run so none is always first (cold) or last
            order = ciphers[r % len(ciphers):] + ciphers[:r % len(ciphers)]
            for c in order:
                ctx = ("bench-user", f"item-{size}-{r}", c)
                secret = new_item_secret()  # fresh secret per write, as in the app
                blob = enc(c, data, secret, ctx)
                t_enc = timed(lambda: enc(c, data, secret, ctx), inner[(c, "encrypt")])
                t_dec = timed(lambda: dec(c, blob, secret, ctx), inner[(c, "decrypt")])
                # a fast wrong answer doesn't count: check the round trip
                if dec(c, blob, secret, ctx) != data:
                    sys.exit(f"ROUND TRIP FAILED: {c} at {size_label(size)}")
                overhead[c] = len(blob) - size
                if r >= warmup:
                    for op, t in (("encrypt", t_enc), ("decrypt", t_dec)):
                        times[(c, op)].append(t)
                        raw_rows.append({"test": "cipher", "size_bytes": size, "cipher": c,
                                         "op": op, "run": r - warmup, "seconds": t})
            del blob
        line = []
        for c in ciphers:
            for op in ("encrypt", "decrypt"):
                s = summarize(times[(c, op)])
                mib_s = size / MiB / s["median_s"]
                rows.append({
                    "size_bytes": size, "size": size_label(size), "cipher": c, "op": op,
                    "inner_reps": inner[(c, op)], **s, "median_mib_s": mib_s,
                    "overhead_bytes": overhead[c],
                    "overhead_pct": overhead[c] / size * 100,
                })
                if op == "encrypt":
                    line.append(f"{c} {mib_s:8.1f}")
        print(f"  {size_label(size):>8}  " + "  ".join(line))
        del data
    print()
    return rows


# ------------------------------------------------------------ 4. upload cost

def bench_upload(sizes, warmup, runs, enc, raw_rows) -> list[dict]:
    print("Upload cost (secret + wrap + encrypt, x3 app ciphers)")
    _, kek = derive_keys("benchmark password", new_salt())
    rows = []
    for size in sizes:
        data = os.urandom(size)

        def upload():
            for c in APP_CIPHERS:
                ctx = ("bench-user", "upload-item", c)
                secret = new_item_secret()
                wrap_secret(kek, secret, ctx)
                enc(c, data, secret, ctx)

        inner = calibrate(upload)
        times = []
        for r in range(warmup + runs):
            t = timed(upload, inner)
            if r >= warmup:
                times.append(t)
                raw_rows.append({"test": "upload", "size_bytes": size, "run": r - warmup, "seconds": t})
        s = summarize(times)
        rows.append({"size_bytes": size, "size": size_label(size), "inner_reps": inner, **s})
        print(f"  {size_label(size):>8}  median {s['median_s'] * 1000:10.2f} ms   cv {s['cv_pct']:5.1f}%")
        del data
    print()
    return rows


# ------------------------------------------------------- 5. HMAC alone

CHUNK_SIZE = 1 * MiB  # same chunk size as labcrypto
AAD_BYTES = 64        # roughly the size of context + chunk header labcrypto MACs


def mac_only(key: bytes, data: bytes) -> None:
    """HMAC-SHA256 over every 1 MiB chunk, the way labcrypto does it for DES and RC4
    (hmac.new(mac_key, aad + body, sha256) per chunk, including the aad + body copy)."""
    aad = b"\x00" * AAD_BYTES
    for start in range(0, max(len(data), 1), CHUNK_SIZE):
        hmac.new(key, aad + data[start:start + CHUNK_SIZE], hashlib.sha256).digest()


def bench_mac(sizes, warmup, runs, raw_rows) -> list[dict]:
    """Time the MAC on its own, so the analysis can split DES/RC4/AES-CBC time
    into 'cipher' and 'HMAC' parts (both CBC ciphers pay the same HMAC cost)."""
    print("HMAC-SHA256 alone (median MiB/s)")
    key = os.urandom(32)
    rows = []
    for size in sizes:
        data = os.urandom(size)
        inner = calibrate(lambda: mac_only(key, data))
        times = []
        for r in range(warmup + runs):
            t = timed(lambda: mac_only(key, data), inner)
            if r >= warmup:
                times.append(t)
                raw_rows.append({"test": "mac", "size_bytes": size, "run": r - warmup, "seconds": t})
        s = summarize(times)
        mib_s = size / MiB / s["median_s"]
        rows.append({"size_bytes": size, "size": size_label(size), "inner_reps": inner, **s,
                     "median_mib_s": mib_s})
        print(f"  {size_label(size):>8}  {mib_s:8.1f} MiB/s   cv {s['cv_pct']:5.1f}%")
        del data
    print()
    return rows


# ----------------------------------------------------------------- output

def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = []
    for row in rows:
        fields += [k for k in row if k not in fields]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--backend", choices=("auto", "real", "stub"), default="auto")
    p.add_argument("--quick", action="store_true", help="small sizes, 3 runs (smoke test)")
    p.add_argument("--runs", type=int, help="timed runs per measurement (default 10, quick 3)")
    p.add_argument("--warmup", type=int, default=1, help="discarded warm-up runs (default 1)")
    p.add_argument("--skip", nargs="*", default=[], choices=("keys", "ciphers", "upload", "mac"))
    p.add_argument("--ciphers", nargs="+", choices=BENCH_CIPHERS, default=list(BENCH_CIPHERS),
                   help="only these ciphers (default: all four)")
    args = p.parse_args()

    ciphers = [c for c in BENCH_CIPHERS if c in args.ciphers]  # keep the fixed order
    subset = len(ciphers) < len(BENCH_CIPHERS)
    if subset and "upload" not in args.skip and not set(APP_CIPHERS) <= set(ciphers):
        print("Upload cost needs all three app ciphers -> skipped for this run.\n")
        args.skip.append("upload")

    backend, sources, enc, dec = load_backend(args.backend, ciphers)
    sizes = QUICK_SIZES if args.quick else FULL_SIZES
    runs = args.runs or (3 if args.quick else 10)
    info = machine_info(backend)
    info["cipher_code"] = sources
    info.update(sizes=[size_label(s) for s in sizes], runs=runs, warmup=args.warmup, quick=args.quick,
                subset=subset)
    print(json.dumps(info, indent=2), "\n")

    raw_rows: list[dict] = []
    results = {}
    if "keys" not in args.skip:
        results["key_cost"] = bench_keys(args.warmup, runs, raw_rows)
    if "ciphers" not in args.skip:
        results["cipher_speed"] = bench_ciphers(sizes, args.warmup, runs, enc, dec, raw_rows, ciphers)
    if "upload" not in args.skip:
        results["upload_cost"] = bench_upload(sizes, args.warmup, runs, enc, raw_rows)
    if "mac" not in args.skip:
        results["mac_cost"] = bench_mac(sizes, args.warmup, runs, raw_rows)

    # Summaries for the report go in results/ (committable) only for an all-real,
    # full run of every cipher. Stub, quick and subset runs stay in raw/ (gitignored).
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    raw_dir = RESULTS_DIR / "raw"
    if backend == "real" and not args.quick and not subset:
        out_dir = RESULTS_DIR
    else:
        tag = "-".join(ciphers) if subset else ""
        out_dir = raw_dir / "-".join(x for x in (backend, tag, "quick" if args.quick else "") if x)
    for name, rows in results.items():
        write_csv(out_dir / f"{name}.csv", rows)
    (out_dir / "machine.json").parent.mkdir(parents=True, exist_ok=True)
    (out_dir / "machine.json").write_text(json.dumps(info, indent=2) + "\n")
    write_csv(raw_dir / f"{stamp}_{backend}_runs.csv", raw_rows)
    print(f"Summaries written to {out_dir}")
    print(f"Every single run written to {raw_dir / f'{stamp}_{backend}_runs.csv'}")


if __name__ == "__main__":
    main()
