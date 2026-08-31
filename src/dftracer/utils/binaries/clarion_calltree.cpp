// ClarIOn call tree analysis on the dftracer_call_tree pipeline.
// DAG:
//   scan -> build -> merge -> analyze -> reduce -> write
//
// scan      : enumerate inputs
// build     : per-file CoroScope fan-out; each file ingests into its own
//             local bucket map (no shared mutation). Events are bucketed
//             by (pid, tid, node_id); tid falls back to the event's
//             top-level tid when args["tid"] is absent (e.g. HDF5 traces).
// merge     : concatenate per-file bucket maps
// analyze   : per-bucket CoroScope fan-out; nest each bucket's events by
//             time-span containment (ClarIOn semantics; no dependence on
//             args["level"], which many traces lack) into a lightweight
//             AggNode forest, compute structural hashes, then optionally
//             dedup paths with equal hashes (--aggregate) and prune
//             (--hotpath, --threshold). Buckets are independent, so this
//             is fully parallel and events from different pids never mix.
//             --detect-anomaly (implies --aggregate) flags two kinds of
//             anomaly. A System Anomaly is found *during* this merge, at
//             each same-name sibling merge candidate: two same-named
//             siblings with different child sets (different execution
//             paths) are left un-merged and flagged. A Performance Anomaly
//             is found only *after* merging is fully done for a node: every
//             individual occurrence's duration is collected onto the node
//             as it merges (AggNode::perf_samples), and once a node has
//             absorbed everything it ever will, each of its samples is
//             compared against the mean of every *other* sample of that
//             same call site (leave-one-out) and flagged if it deviates by
//             more than --anomaly-threshold %% -- skipped when the baseline
//             or the sample itself is below --anomaly-min-dur (trace
//             timestamps are microsecond-resolution, so very short calls
//             are mostly measurement noise). Once a node is itself flagged
//             (either kind), anomalies already recorded for its descendants
//             are removed -- a flagged ancestor suppresses the
//             (now-redundant) nested findings, regardless of which kind
//             either one is.
// reduce    : (--global only) merge all per-bucket forests into one
//             cross-process profile; also runs anomaly detection on the
//             cross-bucket root merge when --detect-anomaly is set
// write     : --format text   -> ClarIOn print_tree output
//                                (dur/depth/count/min/max/mean, %% of
//                                total/parent)
//             --format json   -> Chrome Tracing JSON with agg stats in args
//             --detect-anomaly -> also writes <output_stem>.anomalies.txt
//                                with Performance Anomaly / System Anomaly
//                                tables (function, ancestor, count, plus
//                                expected_range/observed or the diverging
//                                children and duration comparison)

#include <dftracer/utils/call_tree/internal/process_key.h>
#include <dftracer/utils/core/common/byte_view.h>
#include <dftracer/utils/core/common/config.h>
#include <dftracer/utils/core/common/filesystem.h>
#include <dftracer/utils/core/common/logging.h>
#include <dftracer/utils/core/common/string_intern.h>
#include <dftracer/utils/core/coro/task.h>
#include <dftracer/utils/core/pipeline/pipeline.h>
#include <dftracer/utils/core/tasks/coro_scope.h>
#include <dftracer/utils/core/tasks/task.h>
#include <dftracer/utils/utilities/composites/dft/event.h>
#include <dftracer/utils/utilities/fileio/parallel/merge.h>
#include <dftracer/utils/utilities/fileio/parallel/parallel_writer.h>
#include <dftracer/utils/utilities/reader/trace_reader.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "common_cli.h"

using namespace dftracer::utils;
using namespace dftracer::utils::utilities;
using dftracer::utils::call_tree::internal::ProcessKey;

namespace {

enum class OutputFormat { TEXT, JSON };


// ── Raw event storage ───────────────────────────────────────────────────────
// Names are interned once so RawEvent/AggNode carry cheap non-owning views
// with program lifetime.

StringIntern& name_intern() {
    static StringIntern instance;
    return instance;
}

struct RawEvent {
    std::string_view name;
    std::uint64_t ts = 0;
    std::uint64_t dur = 0;
};

using Bucket = std::vector<RawEvent>;
using BucketMap = std::unordered_map<ProcessKey, Bucket>;

// ────────────────────────────────────────────────────────────────────────────
// Aggregation model (ported from ClarIOn's Node, minus pid-blindness).
// ────────────────────────────────────────────────────────────────────────────

struct AggNode {
    std::string_view name;
    std::uint64_t first_ts = 0;
    long long dur = 0;           // inclusive, summed across merged occurrences
    long long count = 1;
    long long min = std::numeric_limits<long long>::max();
    long long max = std::numeric_limits<long long>::min();
    std::size_t hash = 0;
    std::vector<AggNode*> children;

    // Every individual occurrence's own duration that has been folded into
    // this node so far (always perf_samples.size() == count once merging is
    // done). Only populated when --detect-anomaly is set (see
    // project_bucket's track_perf_samples parameter) -- otherwise this stays
    // empty and costs nothing. Kept so Performance Anomaly detection can run
    // once, after a node has absorbed every occurrence it ever will, using
    // the complete distribution rather than a running mean seen one
    // occurrence at a time.
    std::vector<long long> perf_samples;
};

struct AggForest {
    ProcessKey key;
    // real trace time span of this bucket (before any aggregation)
    std::uint64_t span_start = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t span_end = 0;
    std::vector<std::unique_ptr<AggNode>> pool;
    std::vector<AggNode*> roots;

    AggNode* make() {
        pool.push_back(std::make_unique<AggNode>());
        return pool.back().get();
    }

    long long total_run_time() const {
        return span_end > span_start
                   ? static_cast<long long>(span_end - span_start)
                   : 0;
    }
};

// ── Anomaly detection model ─────────────────────────────────────────────────
// Populated (opt-in, --detect-anomaly) at the exact point dedup_list
// considers two same-named siblings for aggregation.

struct PerfAnomaly {
    std::string_view name;
    std::string_view ancestor;      // root name of the tree this occurred in
    int depth = 0;                  // depth of the node (root == 0)
    long long count = 0;            // total occurrences of this node (i.e.
                                     // node->perf_samples.size())
    long long expected_low = 0;
    long long expected_high = 0;
    long long observed = 0;         // the one flagged occurrence's own dur
    const AggNode* node = nullptr;  // identity of the flagged node, for
                                     // descendant-suppression bookkeeping only
                                     // (not rendered)
};

struct SysAnomaly {
    std::string_view name;
    std::string_view ancestor;
    int depth = 0;                  // depth of the compared siblings (root == 0)
    long long count = 0;
    std::vector<std::string_view> only_in_existing;  // children only in dst
    std::vector<std::string_view> only_in_incoming;  // children only in src
    long long existing_dur = 0;
    long long existing_count = 0;
    long long incoming_dur = 0;
    long long incoming_count = 0;
    const AggNode* node = nullptr;  // identity of the flagged node, for
                                     // descendant-suppression bookkeeping only
                                     // (not rendered)
    bool suppressed = false;        // see PerfAnomaly::suppressed
};

struct AnomalySink {
    std::vector<PerfAnomaly> perf;
    std::vector<SysAnomaly> sys;
    double threshold_pct = 50.0;    // % deviation from mean; from CLI
    long long min_samples = 3;      // don't flag a Performance Anomaly for a
                                     // node until it has at least this many
                                     // OTHER occurrences to compare against;
                                     // from CLI
    long long min_dur = 100;        // ignore Performance Anomaly comparisons
                                     // where the leave-one-out mean or the
                                     // observed duration is below this (raw
                                     // trace time units, e.g. microseconds
                                     // -- too short to be anything but
                                     // timer/measurement noise); from CLI

    // node -> indices of the (not-yet-necessarily-suppressed) entries in sys
    // recorded with that exact node as `.node`. A node can appear more than
    // once (e.g. it keeps diverging from different same-named siblings).
    // Populated alongside sys, purely so suppress_descendant_anomalies can
    // find "any System Anomaly already recorded under this specific
    // subtree" in O(1) per node visited instead of rescanning the whole
    // sink on every flag.
    std::unordered_map<const AggNode*, std::vector<std::size_t>> sys_by_node;
};

// Order/multiplicity-independent structural hash (ClarIOn semantics),
// computed bottom-up once and snapshotted; merging equal subtrees does not
// change it.
std::size_t compute_hash(AggNode* n) {
    std::size_t h = std::hash<std::string_view>{}(n->name);
    std::unordered_set<std::size_t> uniq;
    uniq.reserve(n->children.size());
    for (AggNode* c : n->children) uniq.insert(compute_hash(c));
    for (std::size_t ch : uniq) h ^= ch + 0x9e3779b9 + (h << 6) + (h >> 2);
    n->hash = h;
    return h;
}

bool subtrees_equal(const AggNode* a, const AggNode* b) {
    if (a->name != b->name) return false;
    std::unordered_set<std::size_t> ha, hb;
    for (const AggNode* c : a->children) ha.insert(c->hash);
    for (const AggNode* c : b->children) hb.insert(c->hash);
    return ha == hb;
}

// Recursively fold `src` into `dst` (same-pool pointer adoption; unlike
// ClarIOn's deduplicate_tree this also accumulates descendant stats instead
// of dropping them).
void merge_subtree(AggNode* dst, AggNode* src) {
    dst->dur += src->dur;
    dst->count += src->count;
    dst->min = std::min(dst->min, src->min);
    dst->max = std::max(dst->max, src->max);
    dst->first_ts = std::min(dst->first_ts, src->first_ts);
    dst->perf_samples.insert(dst->perf_samples.end(),
                             src->perf_samples.begin(), src->perf_samples.end());
    for (AggNode* sc : src->children) {
        AggNode* match = nullptr;
        for (AggNode* dc : dst->children) {
            if (dc->hash == sc->hash && subtrees_equal(dc, sc)) {
                match = dc;
                break;
            }
        }
        if (match) {
            merge_subtree(match, sc);
        } else {
            dst->children.push_back(sc);  // adopt; hash snapshot unchanged
        }
    }
    src->children.clear();
}

// Same name, different child-hash set: same function took a different
// execution path. Reports the child-name set difference; does NOT merge.
// Returns whether an anomaly was recorded (always true today -- callers
// only invoke this once they've already decided the two sides diverge --
// kept as a return value for symmetry with check_perf_anomaly).
bool record_sys_anomaly(AnomalySink* sink, const AggNode* existing,
                        const AggNode* incoming, std::string_view root_name,
                        int depth) {
    std::unordered_set<std::string_view> ex_children, in_children;
    for (const AggNode* c : existing->children) ex_children.insert(c->name);
    for (const AggNode* c : incoming->children) in_children.insert(c->name);
    SysAnomaly a;
    a.name = existing->name;
    a.ancestor = root_name;
    a.depth = depth;
    a.count = existing->count;
    for (const AggNode* c : existing->children)
        if (!in_children.count(c->name)) a.only_in_existing.push_back(c->name);
    for (const AggNode* c : incoming->children)
        if (!ex_children.count(c->name)) a.only_in_incoming.push_back(c->name);
    a.existing_dur = existing->dur;
    a.existing_count = existing->count;
    a.incoming_dur = incoming->dur;
    a.incoming_count = incoming->count;
    a.node = existing;
    sink->sys.push_back(std::move(a));
    sink->sys_by_node[existing].push_back(sink->sys.size() - 1);
    return true;
}

// Once a node is itself flagged with a System Anomaly, any System Anomaly
// already recorded for one of its descendants is redundant noise -- the
// ancestor's flag already explains it -- so mark it suppressed (dropped at
// report time). This must run *before* `n` is folded into anything else via
// merge_subtree: a merge can fold a flagged descendant's specific node
// object into a sibling's, orphaning it from the live tree, so identifying
// descendants has to happen against `n`'s current (not-yet-merged)
// structure. Detection itself runs bottom-up (a node's descendants are
// fully processed, and may already have been flagged, before the node is
// compared to its own siblings), so this is necessarily a retroactive walk
// rather than a check performed in advance -- but sink->sys_by_node turns
// "was a System Anomaly already recorded against this specific node" into
// an O(1) lookup, so the walk costs O(nodes visited) rather than O(sink
// size) per flag. Performance Anomalies use a separate, later pass (see
// detect_perf_anomalies) that runs once the tree is fully settled, so they
// don't need this retroactive treatment -- but a Performance Anomaly found
// there can still retroactively suppress a System Anomaly nested beneath
// it, which is why this is reused from there too.
void suppress_descendant_anomalies(AnomalySink* sink, const AggNode* n) {
    for (const AggNode* c : n->children) {
        auto sit = sink->sys_by_node.find(c);
        if (sit != sink->sys_by_node.end())
            for (std::size_t idx : sit->second) sink->sys[idx].suppressed = true;
        suppress_descendant_anomalies(sink, c);
    }
}

// `sink` is nullable: null means anomaly detection is off (no extra work
// beyond the null checks below). `root_name` is the ancestor reported for
// any anomaly found in this list (the enclosing tree's root name, or
// "(top-level)" for a forest's own roots list); `depth` is the depth of the
// siblings in `list` (root's own children are depth 1, forest roots are
// depth 0). Only handles System Anomalies and the structural merge itself;
// Performance Anomalies are detected in a separate later pass (see
// detect_perf_anomalies) once every occurrence a node will ever absorb has
// been merged into it.
void dedup_list(std::vector<AggNode*>& list, AnomalySink* sink,
                std::string_view root_name, int depth) {
    std::unordered_map<std::size_t, AggNode*> seen;
    std::unordered_map<std::string_view, AggNode*> seen_by_name;
    std::vector<AggNode*> out;
    out.reserve(list.size());
    for (AggNode* n : list) {
        auto it = seen.find(n->hash);
        if (it != seen.end() && subtrees_equal(it->second, n)) {
            merge_subtree(it->second, n);
        } else {
            if (sink) {
                auto nit = seen_by_name.find(n->name);
                if (nit != seen_by_name.end() && nit->second->hash != n->hash &&
                    record_sys_anomaly(sink, nit->second, n, root_name, depth)) {
                    suppress_descendant_anomalies(sink, nit->second);
                    suppress_descendant_anomalies(sink, n);
                }
                seen_by_name.emplace(n->name, n);
            }
            seen.emplace(n->hash, n);
            out.push_back(n);
        }
    }
    list = std::move(out);
}

void dedup_tree(AggNode* n, AnomalySink* sink, std::string_view root_name,
               int depth) {
    for (AggNode* c : n->children) dedup_tree(c, sink, root_name, depth + 1);
    dedup_list(n->children, sink, root_name, depth + 1);
}

void dedup_forest(std::vector<AggNode*>& roots, AnomalySink* sink) {
    for (AggNode* r : roots) {
        compute_hash(r);
        dedup_tree(r, sink, r->name, /*depth=*/0);
    }
    dedup_list(roots, sink, "(top-level)", /*depth=*/0);
}

// Performance Anomaly detection, run once per node *after* it has absorbed
// every occurrence it's ever going to (i.e. after dedup_forest/dedup_list
// has fully settled the tree this node lives in) -- unlike the old design,
// which compared each incoming occurrence against a running mean built from
// only the occurrences merged so far, this uses the complete distribution:
// checks `n`'s own perf_samples only (no recursion into children; the
// recursive walk over the whole tree lives in detect_perf_anomalies_node
// below). Skipped per-node while there are fewer than sink->min_samples
// samples total (a baseline built from 1-2 points has no real variance
// behind it), and skipped per-sample when either the baseline or the
// sample itself is below sink->min_dur (trace timestamps are
// microsecond-resolution, so very short calls are mostly measurement
// noise). Returns whether `n` itself was flagged, and -- since it was --
// has already suppressed any System Anomaly nested beneath it (cross-kind
// suppression against System Anomalies detected earlier, during
// dedup_forest, is finalized in detect_perf_anomalies_node below).
//
// The baseline is the *median* of all of `n`'s samples, not the mean: a
// leave-one-out mean was tried first and doesn't work here -- with a single
// dominant outlier, every *other* sample's own baseline still includes that
// outlier in its sum, dragging their expected mean upward and making the
// perfectly normal samples look anomalously *low* by comparison (one real
// spike turns into a cascade of spurious "too low" findings alongside it).
// The median barely moves in the presence of one (or a few) extreme values,
// so it stays representative of "what this call site normally costs" and
// doesn't fall into that trap; every sample is compared against that same
// single median-based band.
bool detect_perf_anomaly_self(AnomalySink* sink, AggNode* n,
                              std::string_view ancestor_label, int depth) {
    const long long count = static_cast<long long>(n->perf_samples.size());
    if (count < sink->min_samples) return false;
    std::vector<long long> sorted = n->perf_samples;
    std::sort(sorted.begin(), sorted.end());
    const double median =
        (count % 2 == 0)
            ? (static_cast<double>(sorted[count / 2 - 1]) +
              static_cast<double>(sorted[count / 2])) / 2.0
            : static_cast<double>(sorted[count / 2]);
    if (median < static_cast<double>(sink->min_dur)) return false;
    const double low = median * (1.0 - sink->threshold_pct / 100.0);
    const double high = median * (1.0 + sink->threshold_pct / 100.0);
    bool flagged = false;
    for (long long d : n->perf_samples) {
        if (static_cast<double>(d) < static_cast<double>(sink->min_dur))
            continue;
        if (static_cast<double>(d) < low || static_cast<double>(d) > high) {
            sink->perf.push_back(PerfAnomaly{n->name, ancestor_label, depth,
                count, static_cast<long long>(low),
                static_cast<long long>(high), d, n});
            flagged = true;
        }
    }
    if (flagged) suppress_descendant_anomalies(sink, n);
    return flagged;
}

void detect_perf_anomalies_node(AnomalySink* sink, AggNode* n,
                                std::string_view own_root_name, int depth,
                                bool ancestor_flagged) {
    // The node's own comparison uses "(top-level)" as its ancestor label at
    // depth 0 (matching System Anomaly's root-vs-root convention); every
    // deeper node is anchored to the root's own name.
    const std::string_view ancestor_label =
        depth == 0 ? std::string_view("(top-level)") : own_root_name;

    const bool self_flagged =
        !ancestor_flagged &&
        detect_perf_anomaly_self(sink, n, ancestor_label, depth);

    bool has_live_sys = false;
    if (!ancestor_flagged && !self_flagged) {
        auto sit = sink->sys_by_node.find(n);
        if (sit != sink->sys_by_node.end())
            for (std::size_t idx : sit->second)
                if (!sink->sys[idx].suppressed) { has_live_sys = true; break; }
    }
    const bool next_ancestor_flagged =
        ancestor_flagged || self_flagged || has_live_sys;
    for (AggNode* c : n->children)
        detect_perf_anomalies_node(sink, c, own_root_name, depth + 1,
                                   next_ancestor_flagged);
}

void detect_perf_anomalies(AnomalySink* sink, const std::vector<AggNode*>& roots) {
    for (AggNode* r : roots)
        detect_perf_anomalies_node(sink, r, r->name, /*depth=*/0,
                                   /*ancestor_flagged=*/false);
}

// For the --global cross-bucket reduce step: only the roots themselves can
// have picked up additional occurrences there (deeper nodes are untouched
// by the cross-bucket merge, and were already fully detected per-bucket via
// detect_perf_anomalies above), so only their own samples need re-checking
// -- recursing into children would re-detect, and duplicate, findings
// already recorded at the bucket level.
void detect_perf_anomalies_roots_only(AnomalySink* sink,
                                      const std::vector<AggNode*>& roots) {
    for (AggNode* r : roots)
        detect_perf_anomaly_self(sink, r, "(top-level)", /*depth=*/0);
}

void prune_hot_paths(AggNode* node, double threshold_pct) {
    if (node->children.empty()) return;
    long long max_dur = std::numeric_limits<long long>::min();
    for (const AggNode* c : node->children) max_dur = std::max(max_dur, c->dur);
    const long long cutoff =
        static_cast<long long>(static_cast<double>(max_dur) *
                               (threshold_pct / 100.0));
    std::vector<AggNode*> hot;
    hot.reserve(node->children.size());
    for (AggNode* c : node->children) {
        if (c->dur >= cutoff) hot.push_back(c);
    }
    node->children = std::move(hot);
    for (AggNode* c : node->children) prune_hot_paths(c, threshold_pct);
}

void prune_hot_paths_forest(std::vector<AggNode*>& roots,
                            double threshold_pct) {
    threshold_pct = std::clamp(threshold_pct, 1.0, 100.0);
    for (AggNode* r : roots) prune_hot_paths(r, threshold_pct);
    if (roots.size() > 1) {
        long long max_dur = std::numeric_limits<long long>::min();
        for (const AggNode* r : roots) max_dur = std::max(max_dur, r->dur);
        const long long cutoff =
            static_cast<long long>(static_cast<double>(max_dur) *
                                   (threshold_pct / 100.0));
        std::vector<AggNode*> hot;
        for (AggNode* r : roots) {
            if (r->dur >= cutoff) hot.push_back(r);
        }
        roots = std::move(hot);
    }
}

void prune_threshold(AggNode* node, double threshold_pct,
                     long long parent_dur) {
    if (node->children.empty()) return;
    const long long cutoff =
        static_cast<long long>(static_cast<double>(parent_dur) *
                               (threshold_pct / 100.0));
    std::vector<AggNode*> keep;
    keep.reserve(node->children.size());
    for (AggNode* c : node->children) {
        if (c->dur >= cutoff) keep.push_back(c);
    }
    node->children = std::move(keep);
    for (AggNode* c : node->children)
        prune_threshold(c, threshold_pct, node->dur);
}

void prune_threshold_forest(std::vector<AggNode*>& roots, double threshold_pct,
                            long long total_dur) {
    threshold_pct = std::clamp(threshold_pct, 1.0, 100.0);
    for (AggNode* r : roots) prune_threshold(r, threshold_pct, r->dur);
    if (roots.size() > 1 && total_dur > 0) {
        const long long cutoff =
            static_cast<long long>(static_cast<double>(total_dur) *
                                   (threshold_pct / 100.0));
        std::vector<AggNode*> keep;
        for (AggNode* r : roots) {
            if (r->dur >= cutoff) keep.push_back(r);
        }
        roots = std::move(keep);
    }
}

// ── Projection: Bucket -> AggForest ─────────────────────────────────────────
//
// Nesting is inferred ClarIOn-style from time-span containment (sort by
// start time, outer interval first on ties, then a single stack sweep).

// `track_perf_samples` (== --detect-anomaly) seeds each node's own
// perf_samples with its single initial occurrence; merge_subtree then
// concatenates these as nodes fold together, so every node ends up with the
// full duration list of everything it ever absorbed. Left false, this stays
// empty and costs nothing -- most runs don't need it.
void project_bucket(const Bucket& events, bool inclusive_containment,
                    AggForest& forest, bool track_perf_samples) {
    struct Span {
        AggNode* node;
        std::uint64_t ts;
        std::uint64_t te;
    };
    std::vector<Span> spans;
    spans.reserve(events.size());

    for (const RawEvent& e : events) {
        AggNode* n = forest.make();
        n->name = e.name;
        n->first_ts = e.ts;
        n->dur = static_cast<long long>(e.dur);
        n->count = 1;
        n->min = n->dur;
        n->max = n->dur;
        if (track_perf_samples) n->perf_samples.push_back(n->dur);

        const std::uint64_t te = e.ts + e.dur;
        forest.span_start = std::min(forest.span_start, e.ts);
        forest.span_end = std::max(forest.span_end, te);
        spans.push_back({n, e.ts, te});
    }

    std::sort(spans.begin(), spans.end(), [](const Span& a, const Span& b) {
        if (a.ts != b.ts) return a.ts < b.ts;
        return a.te > b.te;  // outer interval first for same start
    });

    auto contains = [inclusive_containment](const Span& p, const Span& c) {
        if (inclusive_containment) return p.ts <= c.ts && p.te >= c.te;
        return p.ts < c.ts && p.te > c.te;
    };

    std::vector<Span> stack;
    stack.reserve(64);
    for (const Span& s : spans) {
        while (!stack.empty() && !contains(stack.back(), s)) stack.pop_back();
        if (!stack.empty())
            stack.back().node->children.push_back(s.node);
        else
            forest.roots.push_back(s.node);
        stack.push_back(s);
    }
}

AggNode* deep_copy(const AggNode* src, AggForest& into) {
    AggNode* c = into.make();
    c->name = src->name;
    c->first_ts = src->first_ts;
    c->dur = src->dur;
    c->count = src->count;
    c->min = src->min;
    c->max = src->max;
    c->hash = src->hash;
    c->perf_samples = src->perf_samples;
    c->children.reserve(src->children.size());
    for (const AggNode* sc : src->children)
        c->children.push_back(deep_copy(sc, into));
    return c;
}

// ── Text output (byte-for-byte ClarIOn print_tree format) ──────────────────

void render_tree_nodes(const std::vector<AggNode*>& nodes,
                       long long total_run_time, const std::string& prefix,
                       long long parent_dur, int depth, std::string& out) {
    const std::size_t n = nodes.size();
    char buf[512];
    for (std::size_t i = 0; i < n; ++i) {
        const AggNode* node = nodes[i];
        if (node->name.empty()) continue;
        const char* connector = (i == n - 1) ? "└── " : "├── ";

        out += prefix;
        out += connector;
        out.append(node->name.data(), node->name.size());

        int w;
        if (node->count > 1) {
            w = std::snprintf(
                buf, sizeof(buf),
                " (dur: %lld, depth: %d, count: %lld, min: %lld, max: %lld, "
                "mean: %lld)",
                node->dur, depth, node->count, node->min, node->max,
                node->count > 0 ? node->dur / node->count : node->dur);
        } else {
            w = std::snprintf(buf, sizeof(buf), " (dur: %lld, depth: %d)",
                              node->dur, depth);
        }
        out.append(buf, static_cast<std::size_t>(w));

        if (parent_dur == -1 && total_run_time > 0) {
            w = std::snprintf(buf, sizeof(buf), " [%.2f%% of total]",
                              100.0 * static_cast<double>(node->dur) /
                                  static_cast<double>(total_run_time));
            out.append(buf, static_cast<std::size_t>(w));
        } else if (parent_dur > 0) {
            w = std::snprintf(buf, sizeof(buf), " [%.2f%% of parent]",
                              100.0 * static_cast<double>(node->dur) /
                                  static_cast<double>(parent_dur));
            out.append(buf, static_cast<std::size_t>(w));
        }
        out += '\n';

        if (!node->children.empty()) {
            std::string new_prefix = prefix + ((i == n - 1) ? "    " : "│   ");
            render_tree_nodes(node->children, total_run_time, new_prefix,
                              node->dur, depth + 1, out);
        }
    }
}

void render_forest_text(const std::vector<AggNode*>& roots,
                        long long total_run_time, std::string& out) {
    char buf[128];
    int w = std::snprintf(buf, sizeof(buf), " Total run time: %lld \n",
                          total_run_time);
    out.append(buf, static_cast<std::size_t>(w));
    render_tree_nodes(roots, total_run_time, std::string(""), -1, 0, out);
}


bool write_file(const std::string& path, const std::string& bytes) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    const bool ok =
        std::fwrite(bytes.data(), 1, bytes.size(), f) == bytes.size();
    std::fclose(f);
    return ok;
}

// ── Anomaly report (plain text tables) ──────────────────────────────────────

std::string join_names(const std::vector<std::string_view>& names) {
    if (names.empty()) return "-";
    std::string out;
    for (std::size_t i = 0; i < names.size(); ++i) {
        if (i) out += ',';
        out.append(names[i].data(), names[i].size());
    }
    return out;
}

void render_table(const std::vector<std::string>& headers,
                  const std::vector<std::vector<std::string>>& rows,
                  std::string& out) {
    std::vector<std::size_t> widths(headers.size());
    for (std::size_t c = 0; c < headers.size(); ++c) widths[c] = headers[c].size();
    for (const auto& row : rows)
        for (std::size_t c = 0; c < row.size(); ++c)
            widths[c] = std::max(widths[c], row[c].size());

    auto emit_row = [&](const std::vector<std::string>& cells) {
        for (std::size_t c = 0; c < cells.size(); ++c) {
            out += cells[c];
            out.append(widths[c] - cells[c].size() + 2, ' ');
        }
        out += '\n';
    };
    emit_row(headers);
    std::size_t total_width = 0;
    for (std::size_t w : widths) total_width += w + 2;
    out.append(total_width, '-');
    out += '\n';
    for (const auto& row : rows) emit_row(row);
}

void render_perf_anomalies(const std::vector<PerfAnomaly>& items,
                          std::string& out) {
    out += "=== Performance Anomalies (" + std::to_string(items.size()) +
          ") ===\n";
    if (items.empty()) {
        out += "(none)\n";
        return;
    }
    const std::vector<std::string> headers{"function", "ancestor", "depth",
                                           "count", "expected_range",
                                           "observed"};
    std::vector<std::vector<std::string>> rows;
    rows.reserve(items.size());
    for (const PerfAnomaly& a : items) {
        rows.push_back({std::string(a.name), std::string(a.ancestor),
                        std::to_string(a.depth), std::to_string(a.count),
                        "[" + std::to_string(a.expected_low) + ", " +
                            std::to_string(a.expected_high) + "]",
                        std::to_string(a.observed)});
    }
    render_table(headers, rows, out);
}

void render_sys_anomalies(const std::vector<SysAnomaly>& items,
                          std::string& out) {
    out += "=== System Anomalies (" + std::to_string(items.size()) +
          ") ===\n";
    if (items.empty()) {
        out += "(none)\n";
        return;
    }
    const std::vector<std::string> headers{
        "function",          "ancestor",           "depth",
        "count",             "only_in_existing",   "only_in_incoming",
        "existing(dur/count)", "incoming(dur/count)"};
    std::vector<std::vector<std::string>> rows;
    rows.reserve(items.size());
    for (const SysAnomaly& a : items) {
        rows.push_back({std::string(a.name), std::string(a.ancestor),
                        std::to_string(a.depth), std::to_string(a.count),
                        join_names(a.only_in_existing),
                        join_names(a.only_in_incoming),
                        std::to_string(a.existing_dur) + "/" +
                            std::to_string(a.existing_count),
                        std::to_string(a.incoming_dur) + "/" +
                            std::to_string(a.incoming_count)});
    }
    render_table(headers, rows, out);
}

// System Anomalies suppressed by an already-flagged ancestor (see
// suppress_descendant_anomalies) are kept in the sink -- tombstoned, not
// erased, to keep suppression itself cheap -- so this drops them in one
// linear pass before rendering. Performance Anomalies need no such filter:
// detect_perf_anomalies only ever pushes ones that survive suppression.
std::string render_anomaly_report(const AnomalySink& sink) {
    std::vector<SysAnomaly> sys;
    sys.reserve(sink.sys.size());
    for (const SysAnomaly& a : sink.sys)
        if (!a.suppressed) sys.push_back(a);

    std::string out;
    render_perf_anomalies(sink.perf, out);
    out += '\n';
    render_sys_anomalies(sys, out);
    return out;
}

// ── JSON output (Chrome Tracing) ────────────────────────────────────────────

void append_escaped(std::string& out, std::string_view s) {
    for (char ch : s) {
        switch (ch) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\t':
                out += "\\t";
                break;
            case '\r':
                out += "\\r";
                break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", ch);
                    out += buf;
                } else {
                    out += ch;
                }
        }
    }
}


void serialize_agg(const AggNode* n, std::uint64_t start, int depth,
                   bool synthetic, std::uint32_t pid, std::uint32_t tid,
                   std::uint64_t& idx, std::string& out) {
    const std::uint64_t ts = synthetic ? start : n->first_ts;
    const long long mean = n->count > 0 ? n->dur / n->count : n->dur;

    char buf[512];
    int w = std::snprintf(
        buf, sizeof(buf),
        "{\"id\":%llu,\"name\":\"", static_cast<unsigned long long>(idx++));
    out.append(buf, static_cast<std::size_t>(w));
    append_escaped(out, n->name);
    w = std::snprintf(
        buf, sizeof(buf),
        "\",\"cat\":\"clarion\",\"pid\":%u,\"tid\":%u,\"ts\":%llu,"
        "\"dur\":%lld,\"ph\":\"X\",\"args\":{\"count\":%lld,\"min\":%lld,"
        "\"max\":%lld,\"mean\":%lld,\"hash\":%zu,\"depth\":%d}},\n",
        pid, tid, static_cast<unsigned long long>(ts), n->dur, n->count,
        n->min, n->max, mean, n->hash, depth);
    out.append(buf, static_cast<std::size_t>(w));

    std::uint64_t cursor = ts;
    for (const AggNode* c : n->children) {
        serialize_agg(c, cursor, depth + 1, synthetic, pid, tid, idx, out);
        cursor += static_cast<std::uint64_t>(std::max<long long>(c->dur, 0));
    }
}
struct FoundNode {
    const AggNode* node = nullptr;
    ProcessKey key;         // bucket the match came from
    long long total_run_time = 0;  // that bucket's span, for %-of-total
};

void find_in_nodes(const std::vector<AggNode*>& nodes, std::string_view needle,
                   const ProcessKey& key, long long total_run_time,
                   std::vector<FoundNode>& out) {
    for (const AggNode* n : nodes) {
        if (n->name.find(needle) != std::string_view::npos) {
            out.push_back({n, key, total_run_time});
            continue;  // subtree already covered by this hit
        }
        find_in_nodes(n->children, needle, key, total_run_time, out);
    }
}

std::vector<FoundNode> find_in_forest(const AggForest& forest,
                                      std::string_view needle) {
    std::vector<FoundNode> out;
    find_in_nodes(forest.roots, needle, forest.key, forest.total_run_time(),
                  out);
    return out;
}

// text: every match rendered as its own tree, one after another.
void render_matches_text(const std::vector<FoundNode>& matches,
                         std::string_view needle, bool with_bucket_header,
                         std::string& out) {
    char buf[256];
    if (matches.empty()) {
        int w = std::snprintf(buf, sizeof(buf), "No match for \"%.*s\"\n",
                              static_cast<int>(needle.size()), needle.data());
        out.append(buf, static_cast<std::size_t>(w));
        return;
    }
    for (std::size_t i = 0; i < matches.size(); ++i) {
        const FoundNode& m = matches[i];
        int w = std::snprintf(buf, sizeof(buf), "=== match %zu/%zu: ",
                              i + 1, matches.size());
        out.append(buf, static_cast<std::size_t>(w));
        out.append(m.node->name.data(), m.node->name.size());
        if (with_bucket_header) {
            w = std::snprintf(buf, sizeof(buf), " (pid %u tid %u node %u)",
                              m.key.pid, m.key.tid, m.key.node_id);
            out.append(buf, static_cast<std::size_t>(w));
        }
        out += " ===\n";
        // one-element forest: the match is the root, so its line carries
        // "% of total" and its descendants "% of parent"
        const std::vector<AggNode*> root{const_cast<AggNode*>(m.node)};
        render_forest_text(root, m.total_run_time, out);
        out += '\n';
    }
}

// json: a complete Chrome Tracing document for a single match.
std::string render_match_json(const FoundNode& match, bool synthetic) {
    std::string out;
    out.append("[\n", 2);
    out.append(
        "{\"name\":\"format\",\"cat\":\"M\",\"pid\":0,\"tid\":0,\"ph\":\"M\","
        "\"args\":{\"value\":\"clarion_call_tree_find\"}},\n");
    std::uint64_t idx = 0;
    serialize_agg(match.node, /*start=*/0, /*depth=*/0, synthetic,
                  match.key.pid, match.key.tid, idx, out);
    if (out.size() >= 2 && out[out.size() - 2] == ',' &&
        out[out.size() - 1] == '\n') {
        out.resize(out.size() - 2);
        out.append("\n]\n", 3);
    } else {
        out.append("]\n", 2);
    }
    return out;
}

// json/binary: <stem>_<sanitized name>_<index><ext>, one file per match.
std::string match_output_path(const std::string& base, const FoundNode& match,
                              std::size_t index, const std::string& ext) {
    std::string stem = base;
    if (stem.size() >= ext.size() &&
        stem.compare(stem.size() - ext.size(), ext.size(), ext) == 0) {
        stem.resize(stem.size() - ext.size());
    }
    std::string name;
    name.reserve(match.node->name.size());
    for (char c : match.node->name) {
        const bool safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                          (c >= '0' && c <= '9') || c == '.' || c == '-' ||
                          c == '_';
        name += safe ? c : '_';
    }
    if (name.size() > 96) name.resize(96);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "_%zu", index);
    return stem + "_" + name + buf + ext;
}

// <output_stem>.anomalies.txt, stripping a trailing "."-delimited extension
// (the part of output_path after the last '.' that follows the last '/').
std::string anomaly_report_path(const std::string& output_path) {
    std::string stem = output_path;
    const auto pos = stem.find_last_of('.');
    const auto slash = stem.find_last_of('/');
    if (pos != std::string::npos && (slash == std::string::npos || pos > slash))
        stem.resize(pos);
    return stem + ".anomalies.txt";
}
// ── CLI / pipeline plumbing ─────────────────────────────────────────────────

class ClarionArgParse : public cli::ArgParse {
   public:
    cli::PipelineArgs pipeline;

    std::vector<std::string> inputs;
    bool recursive = false;
    std::string output;
    std::string find;
    bool no_save = false;
    bool gzip = false;
    bool time_exclusive = false;
    bool aggregate = false;
    bool global_merge = false;
    bool hotpath = false;
    double hotpath_threshold = 50.0;
    double threshold = -1.0;
    bool detect_anomaly = false;
    double anomaly_threshold = 50.0;
    long long anomaly_min_samples = 3;
    long long anomaly_min_dur = 100;
    OutputFormat format = OutputFormat::TEXT;

    explicit ClarionArgParse(argparse::ArgumentParser& p) : ArgParse(p) {
        schema(pipeline);
    }

   protected:
    void register_args() override {
        parser()
            .add_argument("inputs")
            .help("Trace files (.pfw, .pfw.gz) or directories")
            .nargs(argparse::nargs_pattern::at_least_one);
        parser().add_argument("-r", "--recursive").flag();
        parser()
            .add_argument("-o", "--output")
            .help("Output path (default: derived from input)")
            .default_value<std::string>("");
        parser().add_argument("--no-save").flag();
        parser()
            .add_argument("--gzip")
            .help("gzip the output (text/json only)")
            .flag();
        parser()
            .add_argument("-t", "--time-exclusive")
            .help("Exclusive time containment when nesting "
                  "(default: inclusive)")
            .flag();
        parser()
            .add_argument("-f", "--format")
            .help("Output format: 'text' (ClarIOn tree) or 'json' (Chrome Tracing)")
            .default_value<std::string>("text");
        parser()
            .add_argument("-a", "--aggregate")
            .help("Merge structurally identical subtrees (same hash) per "
                  "process; accumulates count/min/max/mean")
            .flag();
        parser()
            .add_argument("--global")
            .help("Also merge across processes into a single profile "
                  "(implies --aggregate); emits one global forest instead of "
                  "per-process sections")
            .flag();
        parser()
            .add_argument("--hotpath")
            .help("Keep only children within --hotpath-threshold %% of the "
                  "hottest sibling")
            .flag();
        parser()
            .add_argument("--hotpath-threshold")
            .default_value<double>(50.0)
            .scan<'g', double>();
        parser()
            .add_argument("--threshold")
            .help("Drop children below this %% of their parent's duration")
            .default_value<double>(-1.0)
            .scan<'g', double>();
        parser()
            .add_argument("--find")
            .help("Find a specific node in the call tree")
            .default_value<std::string>("");
        parser()
            .add_argument("--detect-anomaly")
            .help("Flag performance outliers and structural divergences "
                  "among aggregation candidates as <output>.anomalies.txt "
                  "(implies --aggregate)")
            .flag();
        parser()
            .add_argument("--anomaly-threshold")
            .help("%% deviation from mean duration that flags a Performance "
                  "Anomaly")
            .default_value<double>(50.0)
            .scan<'g', double>();
        parser()
            .add_argument("--anomaly-min-samples")
            .help("Don't flag a Performance Anomaly for a call site until it "
                  "has at least this many OTHER recorded occurrences to "
                  "compare against (guards against false positives from a "
                  "baseline built on too few samples)")
            .default_value<long long>(3)
            .scan<'d', long long>();
        parser()
            .add_argument("--anomaly-min-dur")
            .help("Ignore Performance Anomaly comparisons where the "
                  "baseline or observed duration is below this (raw trace "
                  "time units, e.g. microseconds) -- too short to be "
                  "anything but measurement noise")
            .default_value<long long>(100)
            .scan<'d', long long>();
    }

    void post_parse() override {
        inputs = parser().get<std::vector<std::string>>("inputs");
        recursive = parser().get<bool>("--recursive");
        output = parser().get<std::string>("--output");
        no_save = parser().get<bool>("--no-save");
        gzip = parser().get<bool>("--gzip");
        time_exclusive = parser().get<bool>("--time-exclusive");
        aggregate = parser().get<bool>("--aggregate");
        global_merge = parser().get<bool>("--global");
        hotpath = parser().get<bool>("--hotpath");
        hotpath_threshold = parser().get<double>("--hotpath-threshold");
        find = parser().get<std::string>("--find");
        threshold = parser().get<double>("--threshold");
        if (global_merge) aggregate = true;
        detect_anomaly = parser().get<bool>("--detect-anomaly");
        anomaly_threshold = parser().get<double>("--anomaly-threshold");
        anomaly_min_samples = parser().get<long long>("--anomaly-min-samples");
        anomaly_min_dur = parser().get<long long>("--anomaly-min-dur");
        if (detect_anomaly) aggregate = true;

        const std::string fmt = parser().get<std::string>("--format");
        if (fmt == "text") {
            format = OutputFormat::TEXT;
        } else if (fmt == "json") {
            format = OutputFormat::JSON;
        } else {
            throw std::runtime_error(
                "--format must be 'text' or 'json'");
        }
    }
};

struct RunCtx {
    const ClarionArgParse* cli = nullptr;
    std::string find;
    std::vector<std::string> trace_files;
    std::vector<BucketMap> per_file;
    BucketMap merged;
    std::vector<ProcessKey> process_keys;

    std::vector<AggForest> forests;  // one per bucket
    AggForest global_forest;         // used with --global
    long long global_run_time = 0;

    std::vector<AnomalySink> bucket_anomalies;  // one per bucket, filled in task_analyze
    AnomalySink anomalies;                      // flattened across buckets + global reduce

    std::string output_path;
    bool failed = false;
};

coro::CoroTask<void> task_scan(RunCtx* ctx, CoroScope& scope) {
    ctx->trace_files = co_await cli::collect_input_trace_files(
        scope, ctx->cli->inputs, ctx->cli->recursive);
    if (ctx->trace_files.empty()) {
        DFTRACER_UTILS_LOG_ERROR("%s", "no trace files found");
        ctx->failed = true;
    }
    co_return;
}

// Ingest one trace file into a private BucketMap using dftracer's indexed
// reader and simdjson ondemand event parser (same machinery as the library's
// read_trace_file_async, inlined here so bucketing can fall back to the
// top-level tid without modifying the library).
coro::CoroTask<void> ingest_one_file(std::string path, BucketMap* out,
                                     std::atomic<std::size_t>* total) {
    using composites::dft::DFTracerEvent;
    using reader::ReadConfig;
    using reader::TraceReaderConfig;

    TraceReaderConfig cfg;
    cfg.file_path = path;
    cfg.auto_build_index = true;
    reader::TraceReader trace_reader(std::move(cfg));

    std::size_t processed = 0;
    auto gen = trace_reader.read_json(ReadConfig{});
    while (auto opt = co_await gen.next()) {
        DFTracerEvent ev;
        if (!DFTracerEvent::parse_ondemand(*opt->parser, ev)) continue;
        if (!ev.is_complete()) continue;

        // DFTracer-style traces carry tid/node_id in args; fall back to the
        // event's top-level tid otherwise (e.g. HDF5 traces).
        std::uint32_t tid = static_cast<std::uint32_t>(ev.tid);
        std::uint32_t node_id = 0;
        if (auto p = ev.args["tid"])
            tid = static_cast<std::uint32_t>(p.get<std::uint64_t>());
        if (auto p = ev.args["node_id"])
            node_id = static_cast<std::uint32_t>(p.get<std::uint64_t>());

        const ProcessKey key(static_cast<std::uint32_t>(ev.pid), tid, node_id);
        (*out)[key].push_back(
            {name_intern().intern(ev.name), ev.ts, ev.dur});
        ++processed;
    }
    total->fetch_add(processed, std::memory_order_relaxed);
    co_return;
}

coro::CoroTask<void> ingest_all_files(CoroScope* child,
                                      const std::vector<std::string>* paths,
                                      std::vector<BucketMap>* per_file,
                                      std::atomic<std::size_t>* total) {
    for (std::size_t i = 0; i < paths->size(); ++i) {
        std::string path = (*paths)[i];
        BucketMap* out = &(*per_file)[i];
        child->spawn([path = std::move(path), out,
                      total](CoroScope&) mutable -> coro::CoroTask<void> {
            co_await ingest_one_file(std::move(path), out, total);
        });
    }
    co_return;
}

coro::CoroTask<void> task_build(RunCtx* ctx, CoroScope* scope) {
    if (ctx->failed) co_return;
    const std::size_t n = ctx->trace_files.size();
    ctx->per_file.clear();
    ctx->per_file.resize(n);

    std::atomic<std::size_t> total_events{0};
    std::atomic<std::size_t>* total_ptr = &total_events;
    const std::vector<std::string>* paths_ptr = &ctx->trace_files;
    std::vector<BucketMap>* per_file_ptr = &ctx->per_file;

    co_await scope->scope(
        [paths_ptr, per_file_ptr,
         total_ptr](CoroScope& child) mutable -> coro::CoroTask<void> {
            co_await ingest_all_files(&child, paths_ptr, per_file_ptr,
                                      total_ptr);
        });

    DFTRACER_UTILS_LOG_DEBUG("[build] %zu events across %zu files",
                             total_events.load(), n);
    co_return;
}

coro::CoroTask<void> task_merge(RunCtx* ctx) {
    if (ctx->failed) co_return;
    for (BucketMap& fragment : ctx->per_file) {
        for (auto& [key, events] : fragment) {
            Bucket& dst = ctx->merged[key];
            if (dst.empty()) {
                dst = std::move(events);
            } else {
                dst.insert(dst.end(), events.begin(), events.end());
            }
        }
        fragment.clear();
    }
    ctx->per_file.clear();

    ctx->process_keys.clear();
    ctx->process_keys.reserve(ctx->merged.size());
    for (const auto& [key, events] : ctx->merged)
        ctx->process_keys.push_back(key);

    DFTRACER_UTILS_LOG_DEBUG("[merge] %zu buckets", ctx->process_keys.size());
    co_return;
}

// analyze: containment nesting + hash + dedup + prune, one bucket per
// coroutine
coro::CoroTask<void> analyze_one(RunCtx* ctx, std::size_t index,
                                 AnomalySink* sink) {
    const ProcessKey key = ctx->process_keys[index];
    AggForest& forest = ctx->forests[index];
    forest.key = key;

    auto it = ctx->merged.find(key);
    if (it == ctx->merged.end()) co_return;
    project_bucket(it->second, !ctx->cli->time_exclusive, forest,
                   ctx->cli->detect_anomaly);

    const std::size_t before = forest.pool.size();
    if (ctx->cli->aggregate) {
        dedup_forest(forest.roots, sink);
        if (sink) detect_perf_anomalies(sink, forest.roots);
    } else {
        // hashes are part of the JSON args, so compute
        // them even when not aggregating
        for (AggNode* r : forest.roots) compute_hash(r);
    }

    if (ctx->cli->hotpath)
        prune_hot_paths_forest(forest.roots, ctx->cli->hotpath_threshold);

    if (ctx->cli->threshold > 0) {
        long long total = 0;
        for (const AggNode* r : forest.roots) total += r->dur;
        prune_threshold_forest(forest.roots, ctx->cli->threshold, total);
    }

    if (ctx->cli->aggregate) {
        std::size_t live = 0;
        std::function<void(const AggNode*)> count_live =
            [&](const AggNode* n) {
                ++live;
                for (const AggNode* c : n->children) count_live(c);
            };
        for (const AggNode* r : forest.roots) count_live(r);
        DFTRACER_UTILS_LOG_DEBUG(
            "[analyze] pid=%u tid=%u: %zu -> %zu nodes", key.pid, key.tid,
            before, live);
    }
    co_return;
}

coro::CoroTask<void> analyze_all(CoroScope* child, RunCtx* ctx) {
    for (std::size_t i = 0; i < ctx->process_keys.size(); ++i) {
        child->spawn([ctx, i](CoroScope&) mutable -> coro::CoroTask<void> {
            AnomalySink* sink =
                ctx->cli->detect_anomaly ? &ctx->bucket_anomalies[i] : nullptr;
            co_await analyze_one(ctx, i, sink);
        });
    }
    co_return;
}

coro::CoroTask<void> task_analyze(RunCtx* ctx, CoroScope* scope) {
    if (ctx->failed) co_return;
    ctx->forests.clear();
    ctx->forests.resize(ctx->process_keys.size());
    if (ctx->cli->detect_anomaly) {
        ctx->bucket_anomalies.clear();
        ctx->bucket_anomalies.resize(ctx->process_keys.size());
        for (AnomalySink& s : ctx->bucket_anomalies) {
            s.threshold_pct = ctx->cli->anomaly_threshold;
            s.min_samples = ctx->cli->anomaly_min_samples;
            s.min_dur = ctx->cli->anomaly_min_dur;
        }
        ctx->anomalies.threshold_pct = ctx->cli->anomaly_threshold;
        ctx->anomalies.min_samples = ctx->cli->anomaly_min_samples;
        ctx->anomalies.min_dur = ctx->cli->anomaly_min_dur;
    }
    RunCtx* ctx_ptr = ctx;
    co_await scope->scope(
        [ctx_ptr](CoroScope& child) mutable -> coro::CoroTask<void> {
            co_await analyze_all(&child, ctx_ptr);
        });

    // per-bucket coroutines have all completed (scope closed above), so
    // this sequential fold needs no locking.
    if (ctx->cli->detect_anomaly) {
        for (AnomalySink& s : ctx->bucket_anomalies) {
            ctx->anomalies.perf.insert(ctx->anomalies.perf.end(),
                                       std::make_move_iterator(s.perf.begin()),
                                       std::make_move_iterator(s.perf.end()));
            ctx->anomalies.sys.insert(ctx->anomalies.sys.end(),
                                      std::make_move_iterator(s.sys.begin()),
                                      std::make_move_iterator(s.sys.end()));
        }
        ctx->bucket_anomalies.clear();
    }
    co_return;
}

// reduce: cross-process merge (sequential; inputs are already deduped)
coro::CoroTask<void> task_reduce(RunCtx* ctx) {
    if (ctx->failed || !ctx->cli->global_merge) co_return;

    std::uint64_t span_start = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t span_end = 0;
    for (AggForest& f : ctx->forests) {
        span_start = std::min(span_start, f.span_start);
        span_end = std::max(span_end, f.span_end);
        for (const AggNode* r : f.roots)
            ctx->global_forest.roots.push_back(
                deep_copy(r, ctx->global_forest));
        f.pool.clear();
        f.roots.clear();
    }
    ctx->global_run_time =
        span_end > span_start ? static_cast<long long>(span_end - span_start)
                              : 0;

    dedup_list(ctx->global_forest.roots,
              ctx->cli->detect_anomaly ? &ctx->anomalies : nullptr,
              "(top-level)", /*depth=*/0);
    if (ctx->cli->detect_anomaly)
        detect_perf_anomalies_roots_only(&ctx->anomalies,
                                         ctx->global_forest.roots);
    if (ctx->cli->hotpath)
        prune_hot_paths_forest(ctx->global_forest.roots,
                               ctx->cli->hotpath_threshold);
    if (ctx->cli->threshold > 0) {
        long long total = 0;
        for (const AggNode* r : ctx->global_forest.roots) total += r->dur;
        prune_threshold_forest(ctx->global_forest.roots, ctx->cli->threshold,
                               total);
    }
    DFTRACER_UTILS_LOG_DEBUG("[reduce] global forest: %zu roots",
                             ctx->global_forest.roots.size());
    co_return;
}

// ── write: text / json ─────────────────────────────────────────────

void serialize_json_forest(const AggForest& forest, bool synthetic,
                           std::uint32_t pid, std::uint32_t tid,
                           std::uint64_t starting_index, std::string& out) {
    std::uint64_t idx = starting_index;
    std::uint64_t cursor = 0;
    for (const AggNode* r : forest.roots) {
        serialize_agg(r, cursor, 0, synthetic, pid, tid, idx, out);
        cursor += static_cast<std::uint64_t>(std::max<long long>(r->dur, 0));
    }
}

void serialize_text_section(const AggForest& forest, bool with_header,
                            std::string& out) {
    if (with_header) {
        char buf[128];
        int w = std::snprintf(buf, sizeof(buf),
                              "=== pid %u tid %u node %u ===\n", forest.key.pid,
                              forest.key.tid, forest.key.node_id);
        out.append(buf, static_cast<std::size_t>(w));
    }
    render_forest_text(forest.roots, forest.total_run_time(), out);
    if (with_header) out += '\n';
}

coro::CoroTask<void> serialize_all_slices(CoroScope* child, RunCtx* ctx,
                                          std::vector<std::string>* buffers,
                                          std::uint64_t stride) {
    const bool synthetic = ctx->cli->aggregate;
    const OutputFormat format = ctx->cli->format;
    const bool multi = ctx->forests.size() > 1;
    for (std::size_t i = 0; i < ctx->forests.size(); ++i) {
        std::uint64_t start_idx = i * stride;
        child->spawn([ctx, buffers, i, start_idx, synthetic, format,
                      multi](CoroScope&) mutable -> coro::CoroTask<void> {
            const AggForest& f = ctx->forests[i];
            if (format == OutputFormat::JSON) {
                serialize_json_forest(f, synthetic, f.key.pid, f.key.tid,
                                      start_idx, (*buffers)[i]);
            } else {
                serialize_text_section(f, multi, (*buffers)[i]);
            }
            co_return;
        });
    }
    co_return;
}
coro::CoroTask<void> task_write_find(RunCtx* ctx) {
    const OutputFormat format = ctx->cli->format;
    const std::string& needle = ctx->cli->find;

    std::vector<FoundNode> matches;
    if (ctx->cli->global_merge) {
        matches = find_in_forest(ctx->global_forest, needle);
        for (FoundNode& m : matches) m.total_run_time = ctx->global_run_time;
    } else {
        for (const AggForest& f : ctx->forests) {
            auto found = find_in_forest(f, needle);
            matches.insert(matches.end(), found.begin(), found.end());
        }
    }

    DFTRACER_UTILS_LOG_INFO("[find] \"%s\": %zu match(es)", needle.c_str(),
                            matches.size());

    if (format == OutputFormat::TEXT) {
        std::string out;
        render_matches_text(matches, needle,
                            /*with_bucket_header=*/!ctx->cli->global_merge,
                            out);
        if (!write_file(ctx->output_path, out)) {
            DFTRACER_UTILS_LOG_ERROR("failed to write %s",
                                     ctx->output_path.c_str());
            ctx->failed = true;
            co_return;
        }
        std::printf("Output file: %s\n", ctx->output_path.c_str());
        co_return;
    }

    // json / binary: one file per match
    const bool synthetic = ctx->cli->aggregate;
    const std::string ext = ".pfw";
    for (std::size_t i = 0; i < matches.size(); ++i) {
        const std::string body = render_match_json(matches[i], synthetic);
                                     
        const std::string path =
            match_output_path(ctx->output_path, matches[i], i, ext);
        if (!write_file(path, body)) {
            DFTRACER_UTILS_LOG_ERROR("failed to write %s", path.c_str());
            ctx->failed = true;
            co_return;
        }
        std::printf("Output file: %s\n", path.c_str());
    }
    co_return;
}

coro::CoroTask<void> task_write(RunCtx* ctx, CoroScope* scope) {
    if (ctx->failed || ctx->cli->no_save) co_return;
    const OutputFormat format = ctx->cli->format;

    if (ctx->cli->detect_anomaly) {
        const std::string report = render_anomaly_report(ctx->anomalies);
        const std::string path = anomaly_report_path(ctx->output_path);
        if (!write_file(path, report)) {
            DFTRACER_UTILS_LOG_ERROR("failed to write %s", path.c_str());
            ctx->failed = true;
            co_return;
        }
        std::printf("Anomaly report: %s\n", path.c_str());
    }

    if (!ctx->cli->find.empty()) {
        co_await task_write_find(ctx);
        co_return;
    }
    // ── serialize ───────────────────────────────────────────────────────
    std::vector<std::string> slice_buffers;
    static constexpr std::uint64_t IDX_STRIDE = 1ull << 20;

    if (ctx->cli->global_merge) {
        slice_buffers.resize(1);
        if (format == OutputFormat::JSON) {
            serialize_json_forest(ctx->global_forest, /*synthetic=*/true,
                                  /*pid=*/0, /*tid=*/0, 0, slice_buffers[0]);
        } else if (format == OutputFormat::TEXT) {
            render_forest_text(ctx->global_forest.roots, ctx->global_run_time,
                               slice_buffers[0]);
        } 
    } else {
        slice_buffers.resize(ctx->forests.size());
        std::vector<std::string>* buffers_ptr = &slice_buffers;
        RunCtx* ctx_ptr = ctx;
        co_await scope->scope(
            [ctx_ptr,
             buffers_ptr](CoroScope& child) mutable -> coro::CoroTask<void> {
                co_await serialize_all_slices(&child, ctx_ptr, buffers_ptr,
                                              IDX_STRIDE);
            });
    }

    

    // ── text / json: ParallelWriter (sharded, optional gzip) ────────────
    std::string header;
    if (format == OutputFormat::JSON) {
        header.append("[\n", 2);
        header.append(
            "{\"name\":\"format\",\"cat\":\"M\",\"pid\":0,\"tid\":0,\"ph\":"
            "\"M\",\"args\":{\"value\":\"clarion_call_tree\"}},\n");
    }

    fileio::parallel::WriterConfig wc;
    wc.layout = fileio::parallel::FileLayout::SHARDED;
    wc.gzip = ctx->cli->gzip;
    auto writer = fileio::parallel::make_writer(wc);

    // Only reserve a header chunk when there is a header to write (JSON);
    // every opened worker slot must receive exactly one write.
    const std::size_t header_chunks = header.empty() ? 0 : 1;
    const std::size_t n = slice_buffers.size();
    const std::size_t total_workers = n + header_chunks;
    if (co_await writer->open(ctx->output_path, total_workers, ctx->cli->gzip,
                              scope) != 0) {
        DFTRACER_UTILS_LOG_ERROR("failed to open writer: %s",
                                 ctx->output_path.c_str());
        ctx->failed = true;
        co_return;
    }

    if (header_chunks != 0 &&
        co_await writer->write_chunk(
            0, ByteView(header.data(), header.size())) != 0) {
        ctx->failed = true;
    }

    for (std::size_t i = 0; i < n && !ctx->failed; ++i) {
        std::string& b = slice_buffers[i];
        if (format == OutputFormat::JSON && i + 1 == n) {
            if (b.size() >= 2 && b[b.size() - 2] == ',' &&
                b[b.size() - 1] == '\n') {
                b.resize(b.size() - 2);
                b.append("\n]\n", 3);
            } else {
                b.append("]\n", 2);
            }
        }
        if (co_await writer->write_chunk(i + header_chunks,
                                         ByteView(b.data(), b.size())) != 0) {
            ctx->failed = true;
            break;
        }
    }

    if (co_await writer->close() != 0) ctx->failed = true;

    if (!ctx->failed) {
        auto shards = writer->output_paths();
        if (co_await fileio::parallel::merge_shards(ctx->output_path, shards) !=
            0) {
            DFTRACER_UTILS_LOG_ERROR("merge_shards failed for %s",
                                     ctx->output_path.c_str());
            ctx->failed = true;
        }
    }
    if (!ctx->failed) {
        std::printf("Output file: %s\n", ctx->output_path.c_str());
    }
    co_return;
}

const char* default_extension(OutputFormat format) {
    switch (format) {
        case OutputFormat::TEXT:
            return "call_tree.txt";
        case OutputFormat::JSON:
            return ".pfw";
    }
    return ".out";
}

int run(int argc, char** argv) {
    dftracer::utils::logger::init();

    argparse::ArgumentParser program("clarion_calltree",
                                     DFTRACER_UTILS_PACKAGE_VERSION);
    program.add_description(
        "Build per-process call trees from DFTracer traces (dftracer-style "
        "parallel ingestion) with ClarIOn hashing, aggregation, pruning, and "
        "output formats (text tree or Chrome Tracing "
        "JSON).");

    ClarionArgParse cli(program);
    if (!cli::setup_and_parse(cli, argc, argv)) return 1;

    RunCtx ctx;
    ctx.cli = &cli;

    if (cli.output.empty()) {
        std::string base = "clarion";
        if (!cli.inputs.empty()) {
            fs::path p(cli.inputs.front());
            if (fs::is_directory(p))
                base = p.filename().string();
            else
                base = p.stem().string();
            if (base.empty()) base = "clarion";
        }
        ctx.output_path = base + default_extension(cli.format);
    } else {
        ctx.output_path = cli.output;
    }
    // if (cli.gzip && cli.format != OutputFormat::BINARY &&
    //     (ctx.output_path.size() < 3 ||
    //      ctx.output_path.compare(ctx.output_path.size() - 3, 3, ".gz") != 0)) {
    //     ctx.output_path += ".gz";
    // }

    auto pipeline_config =
        cli::build_pipeline_config("ClarIOn CallTree", cli.pipeline);
    Pipeline pipeline(pipeline_config);

    RunCtx* ctx_ptr = &ctx;
    auto scan = make_task(
        [ctx_ptr](CoroScope& scope) -> coro::CoroTask<void> {
            co_await task_scan(ctx_ptr, scope);
        },
        "scan");
    auto build = make_task(
        [ctx_ptr](CoroScope& scope) -> coro::CoroTask<void> {
            co_await task_build(ctx_ptr, &scope);
        },
        "build");
    auto merge = make_task(
        [ctx_ptr](CoroScope&) -> coro::CoroTask<void> {
            co_await task_merge(ctx_ptr);
        },
        "merge");
    auto analyze = make_task(
        [ctx_ptr](CoroScope& scope) -> coro::CoroTask<void> {
            co_await task_analyze(ctx_ptr, &scope);
        },
        "analyze");
    auto reduce = make_task(
        [ctx_ptr](CoroScope&) -> coro::CoroTask<void> {
            co_await task_reduce(ctx_ptr);
        },
        "reduce");
    auto write = make_task(
        [ctx_ptr](CoroScope& scope) -> coro::CoroTask<void> {
            co_await task_write(ctx_ptr, &scope);
        },
        "write");

    build->depends_on(scan);
    merge->depends_on(build);
    analyze->depends_on(merge);
    reduce->depends_on(analyze);
    write->depends_on(reduce);

    pipeline.set_source(scan);
    pipeline.set_destination(write);
    pipeline.execute();

    return ctx.failed ? 1 : 0;
}

}  // namespace

int main(int argc, char** argv) { return run(argc, argv); }
