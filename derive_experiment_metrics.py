#!/usr/bin/env python3
"""Derive network cost and CPU metrics from experiment logs into CSV.

Reliable-source policy (see project notes on metric trustworthiness):
  - NETWORK COST  -> taken from the [METRIC] line (total_consensus_*_bytes).
                     These are application-layer, per-connection byte counts
                     isolated to base_meter's consensus traffic. We deliberately
                     do NOT use the [MONITOR] net_* bytes: those count the whole
                     wlan0 interface (SSH + OS traffic) and are contaminated.
  - AVERAGE CPU   -> taken from the [MONITOR] line (avg_cpu_pct), which is read
                     from /proc/<PID>/stat and is isolated to the base_meter
                     process. The [METRIC] line carries no CPU figure.

Each run's pi_meter.log is the primary source. Runs that never reached the
final [METRIC] line (e.g. startup "Base Meter already active" failures) are
flagged complete=0 and excluded from the aggregate.

Outputs (written to this script's directory, i.e. the repo root):
  - experiment_metrics.csv : one row per run
  - experiment_summary.csv : aggregated per quorum meter_count (mean / stdev)
"""
import os
import re
import csv
import glob
import argparse
import statistics

ROOT = os.path.dirname(os.path.abspath(__file__))

PER_RUN_HEADER = [
    "experiment", "run", "log_path", "meter_count", "utility_count", "peer_size",
    "block_height", "consensus_pct",
    "consensus_tx_bytes", "consensus_rx_bytes", "consensus_total_bytes",
    "avg_round_latency_s", "avg_successful_node_latency_s",
    "avg_cpu_pct", "peak_cpu_pct", "peak_mem_kb", "monitor_duration_ms",
    "complete",
]

SUMMARY_HEADER = [
    "meter_count", "utility_count", "peer_size", "quorum_slice_size", "runs_complete",
    "consensus_pct_mean",
    "consensus_total_bytes_mean", "consensus_total_bytes_std",
    "consensus_total_kb_mean",        # bytes/1000, ready to plot directly on a kB axis
    "bytes_per_node_mean",            # total / (meter_count + utility_count)
    "avg_node_latency_s_mean", "avg_node_latency_s_std", "avg_node_latency_s_median",
    "avg_cpu_pct_mean", "avg_cpu_pct_std", "avg_cpu_pct_median",
    "peak_mem_kb_mean",
]


def _f(pattern, text, cast=float):
    m = re.search(pattern, text)
    return cast(m.group(1)) if m else None


def _read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def parse_run(run_dir):
    """Return a dict of metrics for one run directory, or None if unreadable.

    [METRIC]  is read from pi_meter.log (network cost + quorum config).
    [MONITOR] is read from the sibling monitor.log (per-process CPU / mem).
    """
    meter_text = _read(os.path.join(run_dir, "pi_meter.log"))
    monitor_text = _read(os.path.join(run_dir, "monitor.log"))
    if not meter_text and not monitor_text:
        return None

    metric = re.search(r"\[METRIC\].*", meter_text)
    monitor = re.search(r"\[MONITOR\].*", monitor_text)
    metric = metric.group(0) if metric else ""
    monitor = monitor.group(0) if monitor else ""

    row = {
        # network cost + quorum config: reliable source = [METRIC]
        "meter_count":           _f(r"quorum_meter_count=(\d+)", metric, int),
        "utility_count":         _f(r"quorum_utility_count=(\d+)", metric, int),
        "peer_size":             _f(r"peer_size=(\d+)", metric, int),
        "block_height":          _f(r"BlockHeight=(\d+)", metric, int),
        "consensus_pct":         _f(r"consensus_pct=([\d.]+)", metric),
        "consensus_tx_bytes":    _f(r"total_consensus_tx_bytes=(\d+)", metric, int),
        "consensus_rx_bytes":    _f(r"total_consensus_rx_bytes=(\d+)", metric, int),
        "consensus_total_bytes": _f(r"total_consensus_bytes=(\d+)", metric, int),
        "avg_round_latency_s":            _f(r"avg_round_latency_s=([\d.]+)", metric),
        "avg_successful_node_latency_s":  _f(r"avg_successful_node_latency_s=([\d.]+)", metric),
        # cpu / mem: reliable source = [MONITOR] (per-process /proc/<PID>)
        "avg_cpu_pct":           _f(r"avg_cpu_pct=(-?[\d.]+)", monitor),
        "peak_cpu_pct":          _f(r"peak_cpu_pct=([\d.]+)", monitor),
        "peak_mem_kb":           _f(r"peak_mem_kb=(\d+)", monitor, int),
        "monitor_duration_ms":   _f(r"duration_ms=(\d+)", monitor, int),
    }
    # A run is "complete" only if it emitted the final [METRIC] line.
    row["complete"] = 1 if metric and row["consensus_total_bytes"] is not None else 0
    return row


def collect(logs_dir):
    rows = []
    # Scan exactly the <logs_dir>/<experiment>/<run>/pi_meter.log layer. This is a
    # fixed two-level glob (not recursive) on purpose: it keeps archived runs in
    # nested folders like logs/run_with_RSA/<experiment>/<run>/ or logs/old_logs/...
    # from being merged in by basename. To analyse an archive, point logs_dir at it
    # directly, e.g. `derive_experiment_metrics.py logs/run_with_RSA`.
    for log_path in glob.glob(os.path.join(logs_dir, "*", "*", "pi_meter.log")):
        run_dir = os.path.dirname(log_path)
        exp = os.path.basename(os.path.dirname(run_dir))
        run = os.path.basename(run_dir)
        parsed = parse_run(run_dir)
        if parsed is None:
            continue
        parsed["experiment"] = exp
        parsed["run"] = run
        # Path to the exact source file this row's data was extracted from,
        # relative to the repo root — so any row can be traced back by hand.
        parsed["log_path"] = os.path.relpath(log_path, ROOT)
        # Fall back to the directory name for meter_count if the run never
        # produced a [METRIC] line (failed runs still carry the size in the path).
        if parsed["meter_count"] is None:
            m = re.search(r"for_meter_(\d+)_", exp)
            if m:
                parsed["meter_count"] = int(m.group(1))
        rows.append(parsed)
    # Sort by quorum size then run for stable, readable output.
    rows.sort(key=lambda r: (r["meter_count"] or 0, r["experiment"], r["run"]))
    return rows


def write_per_run(rows, out_path):
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=PER_RUN_HEADER, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return statistics.mean(xs) if xs else None


def _std(xs):
    xs = [x for x in xs if x is not None]
    return statistics.pstdev(xs) if len(xs) > 1 else 0.0


def _median(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def _round(x, n):
    return round(x, n) if x is not None else None


def write_summary(rows, out_path):
    # Aggregate only complete runs, grouped by experiment (directory name) — NOT
    # by meter_count alone. Multiple experiment folders can share the same
    # meter_count (e.g. all baseline runs are meter_count=0), so grouping by
    # meter_count would silently merge unrelated sweeps (e.g. a "baseline" and a
    # "baseline_backup" archive) into one row.
    groups = {}
    for r in rows:
        if not r["complete"]:
            continue
        groups.setdefault(r["experiment"], []).append(r)

    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(SUMMARY_HEADER)
        for exp in sorted(groups, key=lambda e: (groups[e][0]["meter_count"] or 0, e)):
            g = groups[exp]
            n = g[0]["meter_count"]
            util = _mean([r["utility_count"] for r in g]) or 0
            total_nodes = n + util
            tot_bytes = [r["consensus_total_bytes"] for r in g]
            bytes_per_node = [
                r["consensus_total_bytes"] / total_nodes
                for r in g if r["consensus_total_bytes"] is not None and total_nodes
            ]
            w.writerow([
                n,
                int(util),
                _mean([r["peer_size"] for r in g]),
                n + int(util),                    # quorum_slice_size = meters + utilities
                len(g),
                _round(_mean([r["consensus_pct"] for r in g]), 2),
                _round(_mean(tot_bytes), 1),
                _round(_std(tot_bytes), 1),
                _round((_mean(tot_bytes) or 0) / 1000, 2),   # consensus_total_kb_mean
                _round(_mean(bytes_per_node), 1),
                _round(_mean([r["avg_successful_node_latency_s"] for r in g]), 3),
                _round(_std([r["avg_successful_node_latency_s"] for r in g]), 3),
                _round(_median([r["avg_successful_node_latency_s"] for r in g]), 3),
                _round(_mean([r["avg_cpu_pct"] for r in g]), 2),
                _round(_std([r["avg_cpu_pct"] for r in g]), 2),
                _round(_median([r["avg_cpu_pct"] for r in g]), 2),
                _round(_mean([r["peak_mem_kb"] for r in g]), 0),
            ])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs_dir", nargs="?", default=os.path.join(ROOT, "logs"),
                    help="root logs directory to scan (default: ./logs)")
    args = ap.parse_args()

    rows = collect(args.logs_dir)
    if not rows:
        print(f"No pi_meter.log files found under {args.logs_dir}")
        return

    per_run = os.path.join(ROOT, "experiment_metrics.csv")
    summary = os.path.join(ROOT, "experiment_summary.csv")
    write_per_run(rows, per_run)
    write_summary(rows, summary)

    complete = sum(r["complete"] for r in rows)
    print(f"Parsed {len(rows)} runs ({complete} complete, {len(rows) - complete} incomplete).")
    print(f"  per-run  -> {per_run}")
    print(f"  summary  -> {summary}")


if __name__ == "__main__":
    main()
