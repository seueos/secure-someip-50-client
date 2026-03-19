#!/usr/bin/env python3
import sys
import re
from pathlib import Path
import argparse
import matplotlib.pyplot as plt

LINE_RE = re.compile(
    r"size_kb=(?P<size>\d+)\s+clients=(?P<clients>\d+)\s+rtt_avg_ns=(?P<rtt>\d+)\s+srv_proc_avg_ns=(?P<srvp>\d+)\s+srv_queue_est_ns=(?P<srvq>\d+)\s+cpu_pct=(?P<cpu>[0-9.]+)\s+mem_pct=(?P<mem>[0-9.]+)"
)

def parse_file(path: Path):
    rows = []
    for line in path.read_text().splitlines():
        m = LINE_RE.search(line)
        if not m:
            continue
        d = m.groupdict()
        rows.append({
            "size_kb": int(d["size"]),
            "clients": int(d["clients"]),
            "rtt_avg_ns": int(d["rtt"]),
            "cpu_pct": float(d["cpu"]),
            "mem_pct": float(d["mem"]),
        })
    rows.sort(key=lambda r: r["size_kb"])
    return rows

def plot_overlay(rows_a, label_a, rows_b, label_b, metric, ylabel, out_png, convert_ms=False):
    xs = [r["size_kb"] for r in rows_a]
    ya = [r[metric] for r in rows_a]
    yb = [r[metric] for r in rows_b]
    if convert_ms:
        # for RTT: ns -> ms
        ya = [v / 1e6 for v in ya]
        yb = [v / 1e6 for v in yb]
    plt.figure(figsize=(8,5))
    plt.plot(xs, ya, 'o-', label=label_a)
    plt.plot(xs, yb, 's-', label=label_b)
    plt.xlabel('Message size (KB)')
    plt.ylabel(ylabel)
    plt.grid(True, linestyle='--', alpha=0.4)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_png)
    print(f"Wrote {out_png}")

def main():
    ap = argparse.ArgumentParser(description="Overlay compare two profiles (RTT/CPU/Mem)")
    ap.add_argument("--label-a", required=True)
    ap.add_argument("--file-a", required=True)
    ap.add_argument("--label-b", required=True)
    ap.add_argument("--file-b", required=True)
    ap.add_argument("--prefix", required=True, help="Output file prefix")
    args = ap.parse_args()

    rows_a = parse_file(Path(args.file_a))
    rows_b = parse_file(Path(args.file_b))
    if not rows_a or not rows_b:
        print("No rows to plot.")
        sys.exit(1)
    if len(rows_a) != len(rows_b):
        print("Warning: row counts differ; proceeding by index order.")

    plot_overlay(rows_a, args.label_a, rows_b, args.label_b, "rtt_avg_ns", "RTT (ms)", f"{args.prefix}_overlay_rtt.png", convert_ms=True)
    plot_overlay(rows_a, args.label_a, rows_b, args.label_b, "cpu_pct", "CPU (%)", f"{args.prefix}_overlay_cpu.png", convert_ms=False)
    plot_overlay(rows_a, args.label_a, rows_b, args.label_b, "mem_pct", "Memory (%)", f"{args.prefix}_overlay_mem.png", convert_ms=False)

if __name__ == "__main__":
    main()


