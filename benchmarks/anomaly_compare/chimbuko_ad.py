"""Offline reimplementation of Chimbuko's documented anomaly-detection
algorithms, operating per function on the same duration samples ClarIOn sees.

This is faithful to the published algorithms (Chimbuko performance-analysis
docs), not a wrapper around the Chimbuko binary:

  SSTD  - per-function mean +/- alpha*sigma threshold. A call is anomalous if
          its time lies outside [mu - alpha*sigma, mu + alpha*sigma]. The
          model (mu, sigma) is built from *all* occurrences, including the
          anomalous ones, exactly as Chimbuko's online accumulator does -- so
          a cluster of outliers inflates the baseline (mean-dragging). Default
          alpha is 6 sigma.

  HBOS  - per-function normalized histogram; score of a sample is
          log2(1 / density) where density is the (normalized) height of the
          bin the sample falls in. Rare bins -> high score. Classified by an
          absolute score threshold (swept for the PR curve); Chimbuko's
          documented default instead filters the top ~1% of scores, provided
          here as hbos_topfraction_flag().

Both model per-function execution time (Chimbuko uses exclusive time by
default; our occurrences are leaves, so inclusive == exclusive).
"""
import math
import statistics

EPS = 1e-12


# --- SSTD -------------------------------------------------------------------


def sstd_flag(funcs, alpha):
    """Return the set of function names with >=1 occurrence outside mu +/-
    alpha*sigma. sigma is the population standard deviation of the function's
    occurrences."""
    flagged = set()
    for name, info in funcs.items():
        d = info["durations"]
        if len(d) < 2:
            continue
        mu = statistics.fmean(d)
        sigma = statistics.pstdev(d)
        hi = mu + alpha * sigma
        lo = mu - alpha * sigma
        for x in d:
            if x > hi or x < lo:
                flagged.add(name)
                break
    return flagged


# --- HBOS -------------------------------------------------------------------


def hbos_scores(funcs, max_bins=50):
    """Per function, fixed-width normalized histogram; return {name: [score per
    occurrence]}. Score = log2(1/(density+eps)).

    The effective bin count is ~sqrt(N) (capped at max_bins): HBOS only
    separates outliers when bins << samples, otherwise well-spread normal data
    lands one-per-bin and scores as 'rare everywhere'. sqrt(N) is the standard
    HBOS/Sturges-style rule."""
    scores = {}
    for name, info in funcs.items():
        d = info["durations"]
        lo, hi = min(d), max(d)
        if hi == lo:
            scores[name] = [0.0] * len(d)
            continue
        nb = max(5, int(round(len(d) ** 0.5)))
        nb = min(nb, max_bins, len(set(d)))
        nb = max(nb, 1)
        width = (hi - lo) / nb
        counts = [0] * nb

        def binof(x, lo=lo, width=width, nb=nb):
            b = int((x - lo) / width)
            return min(b, nb - 1)

        for x in d:
            counts[binof(x)] += 1
        n = len(d)
        heights = [c / n for c in counts]
        scores[name] = [math.log2(1.0 / (heights[binof(x)] + EPS)) for x in d]
    return scores


def hbos_threshold_flag(scores, thresh):
    """Flag any function with an occurrence whose HBOS score exceeds `thresh`."""
    flagged = set()
    for name, sc in scores.items():
        if any(s > thresh for s in sc):
            flagged.add(name)
    return flagged


def hbos_topfraction_flag(scores, fraction):
    """Chimbuko's documented default: flag the globally top-`fraction` scores.
    Rank-based with a tie-inclusive cutoff (flag every sample whose score is
    >= the m-th highest), so a tie at the cutoff doesn't collapse the filter to
    flagging nothing. Note a fixed-fraction filter always flags *something*,
    even on clean data -- itself an informative property of the method."""
    allsc = sorted((s for sc in scores.values() for s in sc), reverse=True)
    if not allsc:
        return set()
    m = max(1, int(math.ceil(fraction * len(allsc))))
    cutoff = allsc[m - 1]
    flagged = set()
    for name, sc in scores.items():
        if any(s >= cutoff for s in sc):
            flagged.add(name)
    return flagged
