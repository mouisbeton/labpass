"""Chart + tables from the benchmark CSVs.

Run from the repo root:
    python -m bench.plot                                   # reads bench/results/
    python -m bench.plot --dir bench/results/raw/stub-quick   # test on stub output

Writes into the same folder:
    cipher_speed.png  - MiB/s vs file size, encrypt and decrypt side by side
    tables.md         - storage overhead, key cost, upload cost (markdown, paste into report)
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # no window, just files
import matplotlib.pyplot as plt  # noqa: E402

RESULTS_DIR = Path(__file__).parent / "results"

# Fixed order and look per cipher. Color + marker + line style, so the chart
# still reads in grayscale print and for colour-blind readers.
STYLE = {
    "aes-gcm": {"label": "AES-256-GCM", "color": "#2a78d6", "marker": "o", "ls": "-"},
    "des-cbc": {"label": "DES-CBC + HMAC", "color": "#eb6834", "marker": "s", "ls": "-"},
    "rc4": {"label": "RC4-drop3072 + HMAC", "color": "#1baf7a", "marker": "^", "ls": "-"},
    "aes-cbc": {"label": "AES-256-CBC + HMAC (control)", "color": "#eda100", "marker": "D", "ls": "--"},
}
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e4e3df"


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def plot_speed(rows: list[dict], info: dict, out: Path) -> None:
    ciphers = [c for c in STYLE if any(r["cipher"] == c for r in rows)]
    sizes = sorted({int(r["size_bytes"]) for r in rows})
    labels = {int(r["size_bytes"]): r["size"] for r in rows}
    xs = range(len(sizes))  # evenly spaced: sizes are roughly x10 steps

    fig, axes = plt.subplots(1, 2, figsize=(10, 4.4), sharey=True)
    # top of the axis = fastest single run anywhere, so no whisker is cut off
    ymax = max(int(r["size_bytes"]) / 2**20 / float(r["min_s"]) for r in rows) * 1.05

    for ax, op in zip(axes, ("encrypt", "decrypt")):
        ends = []
        for c in ciphers:
            by_size = {int(r["size_bytes"]): r for r in rows if r["cipher"] == c and r["op"] == op}
            med = [float(by_size[s]["median_mib_s"]) for s in sizes]
            # whiskers: fastest and slowest run (speed = size / time, so min time = max speed)
            lo = [m - s / 2**20 / float(by_size[s]["max_s"]) for m, s in zip(med, sizes)]
            hi = [s / 2**20 / float(by_size[s]["min_s"]) - m for m, s in zip(med, sizes)]
            st = STYLE[c]
            label = st["label"]
            if info.get("cipher_code", {}).get(c) == "stub":
                label += " [stub]"
            ax.errorbar(xs, med, yerr=[lo, hi], color=st["color"], marker=st["marker"],
                        ls=st["ls"], lw=2, ms=6, capsize=3, elinewidth=1, label=label)
            ends.append([med[-1], st["label"].split(" (")[0].split(" +")[0]])

        # direct label at each line end so identity never relies on colour alone;
        # push labels apart when lines finish at almost the same speed
        gap = ymax * 0.06
        ends.sort()
        for i in range(1, len(ends)):
            ends[i][0] = max(ends[i][0], ends[i - 1][0] + gap)
        for y, text in ends:
            ax.annotate(text, (xs[-1], y), xytext=(10, 0), textcoords="offset points",
                        va="center", fontsize=8, color=INK_2, annotation_clip=False)

        ax.set_title(op.capitalize(), fontsize=11, color=INK, loc="left")
        ax.set_xticks(list(xs), [labels[s] for s in sizes])
        ax.set_xlabel("File size", color=INK_2)
        ax.set_ylim(0, ymax)
        ax.set_xlim(-0.3, len(sizes) - 1 + 0.9)  # room for end labels
        ax.grid(axis="y", color=GRID, lw=0.8)
        ax.set_axisbelow(True)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            ax.spines[side].set_color(GRID)
        ax.tick_params(colors=INK_2, labelsize=9)

    axes[0].set_ylabel("Throughput (MiB/s, higher is faster)", color=INK_2)
    title = "Cipher throughput by file size (median of %s runs; bars = fastest/slowest run)" % info.get("runs", "?")
    test_data = info.get("backend") != "real" or info.get("quick")
    if test_data:
        title = "TEST DATA ONLY - NOT FOR REPORT\n" + title
    fig.suptitle(title, fontsize=11, color="#c0392b" if test_data else INK, x=0.01, ha="left")
    # one legend for both panels, in its own row above the plots
    handles, names = axes[0].get_legend_handles_labels()
    fig.legend(handles, names, loc="upper left", bbox_to_anchor=(0.01, 0.9 if test_data else 0.94),
               ncol=len(names), frameon=False, fontsize=8, handlelength=2.5)
    fig.text(0.01, 0.005, f"{info.get('cpu', '?')} | {info.get('os', '?')} | Python {info.get('python', '?')} | "
             f"PyCryptodome {info.get('pycryptodome', '?')}", fontsize=7, color=INK_2)
    fig.subplots_adjust(top=0.76 if test_data else 0.8, bottom=0.15, left=0.07, right=0.9, wspace=0.22)
    fig.savefig(out, dpi=200)
    plt.close(fig)


def fmt_ms(seconds: str) -> str:
    ms = float(seconds) * 1000
    return f"{ms:.3f}" if ms < 1 else f"{ms:.1f}"


def write_tables(speed: list[dict], keys: list[dict], upload: list[dict], info: dict, out: Path,
                 mac: list[dict] | None = None) -> None:
    lines = []
    if info.get("backend") != "real" or info.get("quick"):
        lines += ["> **TEST DATA ONLY - NOT FOR REPORT**", ""]
    lines += [f"Machine: {info.get('cpu')} | {info.get('os')} | Python {info.get('python')} | "
              f"PyCryptodome {info.get('pycryptodome')} | {info.get('runs')} runs, median", ""]

    if speed:
        ciphers = [c for c in STYLE if any(r["cipher"] == c for r in speed)]
        enc = [r for r in speed if r["op"] == "encrypt"]
        sizes = sorted({int(r["size_bytes"]) for r in enc})
        names = {int(r["size_bytes"]): r["size"] for r in enc}
        get = {(int(r["size_bytes"]), r["cipher"]): r for r in enc}

        lines += ["### Encrypt throughput (MiB/s)", "",
                  "| Size | " + " | ".join(STYLE[c]["label"] for c in ciphers) + " |",
                  "|---" * (len(ciphers) + 1) + "|"]
        for s in sizes:
            lines.append(f"| {names[s]} | " + " | ".join(
                f"{float(get[(s, c)]['median_mib_s']):.1f}" for c in ciphers) + " |")

        lines += ["", "### Storage overhead (extra bytes per stored copy)", "",
                  "| Size | " + " | ".join(STYLE[c]["label"] for c in ciphers) + " |",
                  "|---" * (len(ciphers) + 1) + "|"]
        for s in sizes:
            lines.append(f"| {names[s]} | " + " | ".join(
                f"{int(get[(s, c)]['overhead_bytes'])} B ({float(get[(s, c)]['overhead_pct']):.2f}%)"
                for c in ciphers) + " |")

    if keys:
        lines += ["", "### Key cost", "", "| Operation | Median (ms) | Min | Max | CV |", "|---|---|---|---|---|"]
        for r in keys:
            lines.append(f"| `{r['op']}` | {fmt_ms(r['median_s'])} | {fmt_ms(r['min_s'])} | "
                         f"{fmt_ms(r['max_s'])} | {float(r['cv_pct']):.1f}% |")

    if upload:
        lines += ["", "### Upload cost (new secret + wrap + encrypt, x3 app ciphers)", "",
                  "| Size | Median (ms) | Min | Max | CV |", "|---|---|---|---|---|"]
        for r in upload:
            lines.append(f"| {r['size']} | {fmt_ms(r['median_s'])} | {fmt_ms(r['min_s'])} | "
                         f"{fmt_ms(r['max_s'])} | {float(r['cv_pct']):.1f}% |")

    if mac:
        lines += ["", "### HMAC-SHA256 alone (same 1 MiB chunks as the app)", "",
                  "| Size | Median (ms) | MiB/s | CV |", "|---|---|---|---|"]
        for r in mac:
            lines.append(f"| {r['size']} | {fmt_ms(r['median_s'])} | {float(r['median_mib_s']):.1f} | "
                         f"{float(r['cv_pct']):.1f}% |")

        # Split encrypt time of the HMAC'd ciphers into HMAC part and the rest (cipher + overhead).
        mac_s = {int(r["size_bytes"]): float(r["median_s"]) for r in mac}
        macd = [c for c in ("des-cbc", "rc4", "aes-cbc") if any(r["cipher"] == c for r in speed)]
        if speed and macd:
            enc = {(int(r["size_bytes"]), r["cipher"]): r for r in speed if r["op"] == "encrypt"}
            sizes = sorted(s for s in mac_s if all((s, c) in enc for c in macd))
            lines += ["", "### HMAC share of encrypt time (rest = cipher + per-item setup)", "",
                      "| Size | " + " | ".join(f"{STYLE[c]['label']}: HMAC share / rest MiB/s" for c in macd) + " |",
                      "|---" * (len(macd) + 1) + "|"]
            for s in sizes:
                cells = []
                for c in macd:
                    total = float(enc[(s, c)]["median_s"])
                    rest = total - mac_s[s]
                    rest_speed = f"{s / 2**20 / rest:.1f}" if rest > 0 else "n/a"
                    cells.append(f"{mac_s[s] / total * 100:.0f}% / {rest_speed}")
                lines.append(f"| {enc[(s, macd[0])]['size']} | " + " | ".join(cells) + " |")
            lines += ["", "_HMAC and cipher medians come from separate runs, so shares are estimates. "
                      "'n/a' = HMAC median was longer than the whole encrypt median (noise)._"]

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dir", type=Path, default=RESULTS_DIR, help="folder with the benchmark CSVs")
    args = p.parse_args()

    d = args.dir
    if not (d / "machine.json").exists():
        raise SystemExit(f"No benchmark results in {d}. Run: python -m bench.benchmark")
    info = json.loads((d / "machine.json").read_text())
    speed = read_csv(d / "cipher_speed.csv") if (d / "cipher_speed.csv").exists() else []
    keys = read_csv(d / "key_cost.csv") if (d / "key_cost.csv").exists() else []
    upload = read_csv(d / "upload_cost.csv") if (d / "upload_cost.csv").exists() else []
    mac = read_csv(d / "mac_cost.csv") if (d / "mac_cost.csv").exists() else []

    if speed:
        plot_speed(speed, info, d / "cipher_speed.png")
        print(f"Chart:  {d / 'cipher_speed.png'}")
    write_tables(speed, keys, upload, info, d / "tables.md", mac)
    print(f"Tables: {d / 'tables.md'}")


if __name__ == "__main__":
    main()
