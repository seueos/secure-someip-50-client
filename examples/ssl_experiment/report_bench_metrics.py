#!/usr/bin/env python3
import sys
import re
from pathlib import Path
import argparse
import json
import matplotlib.pyplot as plt

LINE_RE = re.compile(
    r"size_kb=(?P<size>\d+)\s+clients=(?P<clients>\d+)\s+rtt_avg_ns=(?P<rtt>\d+)\s+srv_proc_avg_ns=(?P<srvp>\d+)\s+srv_queue_est_ns=(?P<srvq>\d+)\s+cpu_pct=(?P<cpu>[0-9.]+)\s+mem_pct=(?P<mem>[0-9.]+)"
)

def parse_file(p: Path):
    rows = []
    with p.open() as f:
        for line in f:
            m = LINE_RE.search(line)
            if not m:
                continue
            d = m.groupdict()
            rows.append({
                "size_kb": int(d["size"]),
                "clients": int(d["clients"]),
                "rtt_avg_ns": int(d["rtt"]),
                "srv_proc_avg_ns": int(d["srvp"]),
                "srv_queue_est_ns": int(d["srvq"]),
                "cpu_pct": float(d["cpu"]),
                "mem_pct": float(d["mem"]),
            })
    return rows

def group_by_clients(rows):
    groups = {}
    for r in rows:
        groups.setdefault(r["clients"], []).append(r)
    # sort by size
    for k in groups:
        groups[k] = sorted(groups[k], key=lambda x: x["size_kb"])
    return groups

def plot_metric(groups, metric, out_png, title, ylabel):
    plt.figure(figsize=(8,5))
    for clients, rows in sorted(groups.items()):
        x = [r["size_kb"] for r in rows]
        y = [r[metric] for r in rows]
        plt.plot(x, y, marker='o', label=f'clients={clients}')
    plt.title(title)
    plt.xlabel('Message size (KB)')
    plt.ylabel(ylabel)
    plt.grid(True, linestyle='--', alpha=0.4)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_png)
    print(f"Wrote {out_png}")

def main():
    ap = argparse.ArgumentParser(description="Plot bench metrics from bench_client output")
    ap.add_argument("inputs", nargs="+", help="Input result files (/tmp/*.txt)")
    ap.add_argument("--prefix", default="bench", help="Output filename prefix")
    args = ap.parse_args()

    all_rows = []
    for fp in args.inputs:
        rows = parse_file(Path(fp))
        all_rows.extend(rows)
    if not all_rows:
        print("No rows parsed.")
        return
    groups = group_by_clients(all_rows)
    plot_metric(groups, "rtt_avg_ns", f"{args.prefix}_rtt.png", "RTT 평균(ns)", "RTT (ns)")
    plot_metric(groups, "cpu_pct", f"{args.prefix}_cpu.png", "CPU 사용률(%)", "CPU (%)")
    plot_metric(groups, "mem_pct", f"{args.prefix}_mem.png", "메모리 사용률(%)", "메모리 (%)")

if __name__ == "__main__":
    main()


