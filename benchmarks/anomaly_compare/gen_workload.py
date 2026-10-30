"""Synthetic performance-anomaly workloads with ground truth.

Each "function" is emitted as its own root containing K *leaf* occurrences
(same name, repeated siblings). ClarIOn's --aggregate folds those leaves into
one call-tree node whose per-occurrence samples equal the generated durations
exactly (leaves have no children, so ClarIOn's inclusive `dur` == the generated
value == what the Chimbuko scorers see). That makes the sample set fed to every
detector byte-identical, so the comparison is apples-to-apples.

Ground truth is per function: label == 1 iff the function had an anomaly
injected. The evaluation unit throughout the benchmark is "is function f
flagged or not".

The .pfw format matches clarion_calltree's reader (Chrome-tracing complete "X"
events): {"name","cat":"X","pid","tid","ts","dur","ph":"X","args":{}} inside a
top-level JSON array. Nesting is inferred from [ts, ts+dur] containment.
"""
import json
import math
import random

# --- distribution helpers ---------------------------------------------------


def _lognormal(rng, median, cv):
    """Draw one lognormal value with the given median and coefficient of
    variation (std/mean). sigma is derived so exp(mu) == median."""
    sigma = math.sqrt(math.log(1.0 + cv * cv))
    mu = math.log(median)
    return max(1, int(round(math.exp(rng.gauss(mu, sigma)))))


def _normals(rng, k, median, cv):
    return [_lognormal(rng, median, cv) for _ in range(k)]


# --- per-family anomaly injection -------------------------------------------
# Each injector mutates `durs` in place and returns nothing; the function is
# labelled anomalous by the caller.

def _inject(family, rng, durs, median, spike_factor, shift_factor, ramp_factor):
    k = len(durs)
    if family == "clean_spike":
        # one large, unambiguous spike among otherwise-normal occurrences
        durs[rng.randrange(k)] = int(round(median * spike_factor))
    elif family == "multi_outlier":
        # several spikes -> drags a mean/std baseline, but not a median one
        n = rng.randint(3, 5)
        for idx in rng.sample(range(k), min(n, k)):
            durs[idx] = int(round(median * spike_factor * rng.uniform(0.8, 1.2)))
    elif family == "subtle_shift":
        # a modest elevation (~just past the 50% band) on a fraction of calls:
        # near the detection boundary, so it separates the detectors' curves
        n = max(1, int(round(0.2 * k)))
        for idx in rng.sample(range(k), n):
            durs[idx] = int(round(median * shift_factor * rng.uniform(0.95, 1.05)))
    elif family == "drift":
        # monotonic boiling-frog ramp across the whole series; no single call
        # stands far from the middle of the distribution (known blind spot)
        for j in range(k):
            frac = j / (k - 1) if k > 1 else 0.0
            durs[j] = int(round(median * (1.0 + (ramp_factor - 1.0) * frac)))
    else:
        raise ValueError("unknown family: " + family)


# --- workload assembly -------------------------------------------------------


def generate(family, n_funcs, k, seed,
             anom_frac=0.3, median=2000.0, cv=0.12,
             spike_factor=20.0, shift_factor=1.7, ramp_factor=3.0):
    """Return {func_name: {"label": 0/1, "durations": [...]}}.

    For `neg_control`, no anomalies are injected (anom_frac forced to 0): the
    workload exists purely to measure false positives / precision under noise.
    """
    rng = random.Random(seed)
    neg = family == "neg_control"
    base_family = "clean_spike" if neg else family

    n_anom = 0 if neg else int(round(anom_frac * n_funcs))
    anom_ids = set(rng.sample(range(n_funcs), n_anom)) if n_anom else set()

    funcs = {}
    for i in range(n_funcs):
        name = "func_%05d" % i
        durs = _normals(rng, k, median, cv)
        is_anom = i in anom_ids
        if is_anom:
            _inject(base_family, rng, durs, median,
                    spike_factor, shift_factor, ramp_factor)
        funcs[name] = {"label": 1 if is_anom else 0, "durations": durs}
    return funcs


def write_pfw(funcs, path, margin=1000, gap=100):
    """Serialize `funcs` to a .pfw trace: one root per function, K leaf
    occurrences nested inside it."""
    events = []
    base = 0
    for name, info in funcs.items():
        durs = info["durations"]
        total = sum(durs) + gap * len(durs) + 2 * margin
        events.append({"name": "root_" + name, "cat": "X", "pid": 1, "tid": 1,
                       "ts": base, "dur": total, "ph": "X", "args": {}})
        cur = base + margin
        for d in durs:
            events.append({"name": name, "cat": "X", "pid": 1, "tid": 1,
                           "ts": cur, "dur": d, "ph": "X", "args": {}})
            cur += d + gap
        base += total + margin
    with open(path, "w") as f:
        f.write("[\n")
        f.write(",\n".join(json.dumps(e, separators=(",", ":")) for e in events))
        f.write("\n]\n")
    return len(events)


FAMILIES = ["clean_spike", "multi_outlier", "subtle_shift", "drift", "neg_control"]

FAMILY_LABELS = {
    "clean_spike": "Clean spike (1 large outlier)",
    "multi_outlier": "Multi-outlier (3-5 spikes)",
    "subtle_shift": "Subtle shift (~1.7x, near band)",
    "drift": "Gradual drift (boiling frog)",
    "neg_control": "Negative control (noise only)",
}
