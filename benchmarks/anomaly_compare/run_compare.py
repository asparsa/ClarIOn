"""Orchestrate the ClarIOn-vs-Chimbuko comparison.

For each workload family it runs:
  - ClarIOn  : the real `clarion_calltree --detect-anomaly` binary, swept over
               --anomaly-threshold; flagged functions parsed from the
               <out>.anomalies.txt Performance Anomalies table.
  - SSTD     : reimplemented mu +/- alpha*sigma, swept over alpha.
  - HBOS     : reimplemented histogram score, swept over an absolute score
               threshold.

Everything is scored per function against ground truth (precision / recall /
F1 / FP-rate), averaged over seeds. A separate scalability pass times ClarIOn's
detection step (binary detect-vs-aggregate delta, best-of-N) and the Python
scorers across event counts up to ~1e6.

Outputs CSVs under results/ and a results.json consumed by make_report.py.

Usage:
  python run_compare.py [--funcs 100] [--k 60] [--seeds 5]
                        [--scal-sizes 1000,10000,100000,1000000]
                        [--out results] [--quick]
"""
import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile
import time

import chimbuko_ad as ch
import gen_workload as gw

CLARION_THRESHOLDS = [10, 20, 30, 40, 50, 60, 75, 100, 125, 150, 175, 200]
SSTD_ALPHAS = [0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0]
HBOS_THRESHS = [round(0.5 * i, 2) for i in range(0, 15)]  # 0.0 .. 7.0

CLARION_DEFAULT_THR = 50.0
SSTD_DEFAULT_ALPHA = 6.0
HBOS_DEFAULT_FRACTION = 0.01  # Chimbuko's documented top-1%

MIN_SAMPLES = 3
MIN_DUR = 100


# --- ClarIOn binary plumbing -------------------------------------------------


def find_binary():
    env = os.environ.get("CLARION_CALLTREE_PATH")
    cands = [env] if env else []
    cands += [
        "/home/cc/ClarIOn/build/bin/clarion_calltree",
        "./clarion_calltree", "../bin/clarion_calltree",
    ]
    for c in cands:
        if c and os.access(c, os.X_OK):
            return c
    sys.exit("clarion_calltree binary not found (set CLARION_CALLTREE_PATH)")


def _split_columns(line):
    out, i, n = [], 0, len(line)
    while i < n:
        while i < n and line[i] == " ":
            i += 1
        if i >= n:
            break
        start = i
        while i < n:
            if line[i] == " " and i + 1 < n and line[i + 1] == " ":
                break
            i += 1
        out.append(line[start:i])
        while i < n and line[i] == " ":
            i += 1
    return out


def parse_perf_functions(report_path):
    """Set of function names in the Performance Anomalies table."""
    try:
        with open(report_path) as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return set()
    i = 0
    while i < len(lines) and not lines[i].startswith("=== Performance Anomalies"):
        i += 1
    if i >= len(lines):
        return set()
    i += 1
    if i >= len(lines) or lines[i].strip() == "(none)":
        return set()
    headers = _split_columns(lines[i])
    i += 1
    if i < len(lines) and "---" in lines[i]:
        i += 1
    fidx = headers.index("function") if "function" in headers else 0
    funcs = set()
    while i < len(lines):
        if lines[i].strip() == "" or lines[i].startswith("==="):
            break
        cols = _split_columns(lines[i])
        if fidx < len(cols):
            funcs.add(cols[fidx])
        i += 1
    return funcs


def run_clarion(binary, trace, workdir, threshold):
    out = os.path.join(workdir, "ct.txt")
    subprocess.run(
        [binary, trace, "-a", "--detect-anomaly",
         "--anomaly-threshold", str(threshold),
         "--anomaly-min-samples", str(MIN_SAMPLES),
         "--anomaly-min-dur", str(MIN_DUR), "-o", out],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return parse_perf_functions(os.path.join(workdir, "ct.anomalies.txt"))


# --- scoring -----------------------------------------------------------------


def score(flagged, funcs):
    tp = fp = fn = n_pos = n_neg = 0
    for name, info in funcs.items():
        pos = info["label"] == 1
        if pos:
            n_pos += 1
        else:
            n_neg += 1
        if name in flagged:
            if pos:
                tp += 1
            else:
                fp += 1
        elif pos:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = (tp / (tp + fn)) if (tp + fn) else None
    if recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    fp_rate = fp / n_neg if n_neg else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision,
            "recall": recall, "f1": f1, "fp_rate": fp_rate,
            "n_pos": n_pos, "n_neg": n_neg}


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def _std(xs):
    xs = [x for x in xs if x is not None]
    if len(xs) < 2:
        return 0.0
    m = sum(xs) / len(xs)
    return (sum((x - m) ** 2 for x in xs) / (len(xs) - 1)) ** 0.5


# --- precision/recall experiment --------------------------------------------


def pr_experiment(binary, n_funcs, k, seeds, workdir):
    """Return raw per-(family,detector,param,seed) rows."""
    rows = []
    for family in gw.FAMILIES:
        for seed in range(seeds):
            funcs = gw.generate(family, n_funcs, k, seed)
            trace = os.path.join(workdir, "trace.pfw")
            gw.write_pfw(funcs, trace)

            # ClarIOn (one binary run per threshold)
            for thr in CLARION_THRESHOLDS:
                s = score(run_clarion(binary, trace, workdir, thr), funcs)
                rows.append(("ClarIOn", family, seed, thr, s))

            # SSTD
            for a in SSTD_ALPHAS:
                s = score(ch.sstd_flag(funcs, a), funcs)
                rows.append(("SSTD", family, seed, a, s))

            # HBOS (scores once, swept over score threshold)
            scores = ch.hbos_scores(funcs)
            for t in HBOS_THRESHS:
                s = score(ch.hbos_threshold_flag(scores, t), funcs)
                rows.append(("HBOS", family, seed, t, s))
        print("  [pr] %-14s done" % family, flush=True)
    return rows


def aggregate_pr(rows):
    """Average metrics over seeds, keyed by (detector, family, param)."""
    buckets = {}
    for det, family, seed, param, s in rows:
        buckets.setdefault((det, family, param), []).append(s)
    agg = []
    for (det, family, param), ss in buckets.items():
        agg.append({
            "detector": det, "family": family, "param": param,
            "precision": _mean([x["precision"] for x in ss]),
            "recall": _mean([x["recall"] for x in ss]),
            "f1": _mean([x["f1"] for x in ss]),
            "fp_rate": _mean([x["fp_rate"] for x in ss]),
            "tp": _mean([x["tp"] for x in ss]),
            "fp": _mean([x["fp"] for x in ss]),
            "fn": _mean([x["fn"] for x in ss]),
        })
    return agg


def operating_points(binary, rows, n_funcs, k, seeds, workdir):
    """Default-setting and F1-optimal operating points per (family, detector)."""
    # defaults
    out = []
    by = {}
    for det, family, seed, param, s in rows:
        by.setdefault((det, family), []).append((seed, param, s))

    def default_param(det):
        return {"ClarIOn": CLARION_DEFAULT_THR, "SSTD": SSTD_DEFAULT_ALPHA}.get(det)

    # ClarIOn + SSTD defaults come straight from the swept grid
    for (det, family), items in by.items():
        if det == "HBOS":
            continue
        dp = default_param(det)
        sel = [s for (_, p, s) in items if abs(p - dp) < 1e-9]
        if sel:
            out.append(_op_row(family, det, "default", dp, sel))

    # HBOS default = top-1% (recompute, since the sweep uses an absolute
    # threshold, not a fraction)
    for family in gw.FAMILIES:
        sel = []
        for seed in range(seeds):
            funcs = gw.generate(family, n_funcs, k, seed)
            scores = ch.hbos_scores(funcs)
            sel.append(score(ch.hbos_topfraction_flag(scores, HBOS_DEFAULT_FRACTION), funcs))
        out.append(_op_row(family, "HBOS", "default", HBOS_DEFAULT_FRACTION, sel))

    # F1-optimal (skip neg_control: no positives -> F1 undefined)
    agg = aggregate_pr(rows)
    best = {}
    for a in agg:
        if a["family"] == "neg_control" or a["f1"] is None:
            continue
        key = (a["detector"], a["family"])
        if key not in best or a["f1"] > best[key]["f1"]:
            best[key] = a
    for (det, family), a in best.items():
        sel = [s for (d, f, seed, p, s) in rows
               if d == det and f == family and abs(p - a["param"]) < 1e-9]
        out.append(_op_row(family, det, "f1_opt", a["param"], sel))
    return out


def _op_row(family, det, setting, param, score_list):
    return {
        "family": family, "detector": det, "setting": setting, "param": param,
        "precision_mean": _mean([s["precision"] for s in score_list]),
        "precision_std": _std([s["precision"] for s in score_list]),
        "recall_mean": _mean([s["recall"] for s in score_list]),
        "recall_std": _std([s["recall"] for s in score_list]),
        "f1_mean": _mean([s["f1"] for s in score_list]),
        "fp_rate_mean": _mean([s["fp_rate"] for s in score_list]),
    }


# --- scalability experiment --------------------------------------------------


def _best_time(fn, reps=3):
    best = float("inf")
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def scalability(binary, sizes, k, workdir, reps=3):
    rows = []
    for events_target in sizes:
        n_funcs = max(1, int(round(events_target / (k + 1))))
        funcs = gw.generate("clean_spike", n_funcs, k, seed=0)
        trace = os.path.join(workdir, "scal.pfw")
        n_events = gw.write_pfw(funcs, trace)
        out = os.path.join(workdir, "scal_out.txt")

        def run_detect():
            subprocess.run([binary, trace, "-a", "--detect-anomaly",
                            "--anomaly-threshold", "50", "-o", out],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def run_agg():
            subprocess.run([binary, trace, "-a", "-o", out],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        t_detect = _best_time(run_detect, reps)
        t_agg = _best_time(run_agg, reps)
        clarion_ms = max(0.0, (t_detect - t_agg)) * 1000.0

        t_sstd = _best_time(lambda: ch.sstd_flag(funcs, 6.0), reps) * 1000.0
        t_hbos = _best_time(lambda: ch.hbos_scores(funcs), reps) * 1000.0

        for det, ms in (("ClarIOn", clarion_ms), ("SSTD", t_sstd), ("HBOS", t_hbos)):
            eps = (n_events / (ms / 1000.0)) if ms > 0 else None
            rows.append({"detector": det, "events": n_events, "time_ms": ms,
                         "throughput_eps": eps})
        print("  [scal] events=%d clarion=%.1fms sstd=%.2fms hbos=%.2fms"
              % (n_events, clarion_ms, t_sstd, t_hbos), flush=True)
    return rows


# --- CSV / JSON writers ------------------------------------------------------


def write_csv(path, fieldnames, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--funcs", type=int, default=100)
    ap.add_argument("--k", type=int, default=60)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--scal-sizes", default="1000,10000,100000,1000000")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "results"))
    ap.add_argument("--quick", action="store_true",
                    help="small/fast run for smoke-testing")
    args = ap.parse_args()

    if args.quick:
        args.funcs, args.seeds = 30, 2
        args.scal_sizes = "1000,10000"

    binary = find_binary()
    os.makedirs(args.out, exist_ok=True)
    sizes = [int(x) for x in args.scal_sizes.split(",") if x]

    with tempfile.TemporaryDirectory() as workdir:
        print("Precision/recall experiment (funcs=%d k=%d seeds=%d)..."
              % (args.funcs, args.k, args.seeds), flush=True)
        raw = pr_experiment(binary, args.funcs, args.k, args.seeds, workdir)
        agg = aggregate_pr(raw)
        ops = operating_points(binary, raw, args.funcs, args.k, args.seeds, workdir)

        print("Scalability experiment (sizes=%s)..." % sizes, flush=True)
        scal = scalability(binary, sizes, args.k, workdir)

    # raw CSV
    write_csv(os.path.join(args.out, "pr_raw.csv"),
              ["detector", "family", "seed", "param", "tp", "fp", "fn",
               "precision", "recall", "f1", "fp_rate"],
              [{"detector": d, "family": f, "seed": seed, "param": p,
                **{kk: s[kk] for kk in ("tp", "fp", "fn", "precision",
                                        "recall", "f1", "fp_rate")}}
               for (d, f, seed, p, s) in raw])
    write_csv(os.path.join(args.out, "pr_agg.csv"),
              ["detector", "family", "param", "precision", "recall", "f1",
               "fp_rate", "tp", "fp", "fn"], agg)
    write_csv(os.path.join(args.out, "operating_points.csv"),
              ["family", "detector", "setting", "param", "precision_mean",
               "precision_std", "recall_mean", "recall_std", "f1_mean",
               "fp_rate_mean"], ops)
    write_csv(os.path.join(args.out, "scalability.csv"),
              ["detector", "events", "time_ms", "throughput_eps"], scal)

    with open(os.path.join(args.out, "results.json"), "w") as f:
        json.dump({"config": vars(args), "pr_agg": agg,
                   "operating_points": ops, "scalability": scal,
                   "family_labels": gw.FAMILY_LABELS}, f, indent=2)

    print("Wrote CSVs + results.json to", args.out, flush=True)


if __name__ == "__main__":
    main()
