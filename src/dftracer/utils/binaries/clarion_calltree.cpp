// ClarIOn call tree analysis on the dftracer_call_tree pipeline.
//
// Ingestion/processing is dftracer-style (indexed TraceReader, simdjson
// ondemand event parsing, coroutine pipeline with per-file and per-process
// fan-out); results and output are ClarIOn-style. Fully self-contained:
// uses only public dftracer-utils APIs, no library modifications.
//
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
// reduce    : (--global only) merge all per-bucket forests into one
//             cross-process profile
// write     : --format text   -> ClarIOn print_tree output
//                                (dur/depth/count/min/max/mean, %% of
//                                total/parent)
//             --format binary -> ClarIOn .call_tree format
//                                (magic 0xCA117EE1, byte-compatible with
//                                ClarIOn's load_calltree)
//             --format json   -> Chrome Tracing JSON with agg stats in args

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

enum class OutputFormat { TEXT, BINARY, JSON };

// ── ClarIOn binary file format constants ────────────────────────────────────

constexpr std::uint32_t CALLTREE_MAGIC = 0xCA117EE1;
constexpr std::uint32_t CALLTREE_VERSION = 0x00000001;

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
    std::uint64_t first_ts = 0;  // earliest occurrence (raw JSON layout)
    long long dur = 0;           // inclusive, summed across merged occurrences
    long long count = 1;
    long long min = std::numeric_limits<long long>::max();
    long long max = std::numeric_limits<long long>::min();
    std::size_t hash = 0;
    std::vector<AggNode*> children;
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

void dedup_list(std::vector<AggNode*>& list) {
    std::unordered_map<std::size_t, AggNode*> seen;
    std::vector<AggNode*> out;
    out.reserve(list.size());
    for (AggNode* n : list) {
        auto it = seen.find(n->hash);
        if (it != seen.end() && subtrees_equal(it->second, n)) {
            merge_subtree(it->second, n);
        } else {
            seen.emplace(n->hash, n);
            out.push_back(n);
        }
    }
    list = std::move(out);
}

void dedup_tree(AggNode* n) {
    for (AggNode* c : n->children) dedup_tree(c);
    dedup_list(n->children);
}

void dedup_forest(std::vector<AggNode*>& roots) {
    for (AggNode* r : roots) {
        compute_hash(r);
        dedup_tree(r);
    }
    dedup_list(roots);
}

// ── Pruning (ported from ClarIOn) ───────────────────────────────────────────

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
// This deliberately does NOT use DFTracer's args["level"], which many
// traces (e.g. HDF5/VOL ones) lack. Containment needs only ts/dur, and
// within a (pid, tid, node) bucket it reproduces ClarIOn's tree exactly.

void project_bucket(const Bucket& events, bool inclusive_containment,
                    AggForest& forest) {
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

// ── Binary output (byte-compatible with ClarIOn save_calltree) ─────────────

template <typename T>
void append_pod(std::string& out, const T& v) {
    out.append(reinterpret_cast<const char*>(&v), sizeof(T));
}

void append_binary_node(std::string& out, const AggNode* n) {
    const std::uint16_t name_len = static_cast<std::uint16_t>(n->name.size());
    append_pod(out, name_len);
    out.append(n->name.data(), name_len);
    append_pod(out, n->dur);  // long long
    const std::int32_t count = static_cast<std::int32_t>(n->count);
    append_pod(out, count);
    append_pod(out, n->min);   // long long
    append_pod(out, n->max);   // long long
    append_pod(out, n->hash);  // std::size_t
    const std::uint32_t n_children =
        static_cast<std::uint32_t>(n->children.size());
    append_pod(out, n_children);
    for (const AggNode* c : n->children) append_binary_node(out, c);
}

void render_forest_binary(const std::vector<AggNode*>& roots,
                          std::string& out) {
    append_pod(out, CALLTREE_MAGIC);
    append_pod(out, CALLTREE_VERSION);
    const std::uint64_t n_roots = roots.size();
    append_pod(out, n_roots);
    for (const AggNode* r : roots) append_binary_node(out, r);
}

bool write_file(const std::string& path, const std::string& bytes) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    const bool ok =
        std::fwrite(bytes.data(), 1, bytes.size(), f) == bytes.size();
    std::fclose(f);
    return ok;
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

// Emit one node and its subtree. When `synthetic` is set (aggregated trees
// have no meaningful timestamps), children are packed flame-graph style
// inside the parent span; otherwise real first-occurrence timestamps are
// used. Every event line ends with ",\n"; the caller trims the last one.
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

// ── CLI / pipeline plumbing ─────────────────────────────────────────────────

class ClarionArgParse : public cli::ArgParse {
   public:
    cli::PipelineArgs pipeline;

    std::vector<std::string> inputs;
    bool recursive = false;
    std::string output;
    bool no_save = false;
    bool gzip = false;
    bool time_exclusive = false;
    bool aggregate = false;
    bool global_merge = false;
    bool hotpath = false;
    double hotpath_threshold = 50.0;
    double threshold = -1.0;
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
            .help("Output format: 'text' (ClarIOn tree), 'binary' (ClarIOn "
                  ".call_tree), or 'json' (Chrome Tracing)")
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
        threshold = parser().get<double>("--threshold");
        if (global_merge) aggregate = true;

        const std::string fmt = parser().get<std::string>("--format");
        if (fmt == "text") {
            format = OutputFormat::TEXT;
        } else if (fmt == "binary") {
            format = OutputFormat::BINARY;
        } else if (fmt == "json") {
            format = OutputFormat::JSON;
        } else {
            throw std::runtime_error(
                "--format must be 'text', 'binary', or 'json'");
        }
    }
};

struct RunCtx {
    const ClarionArgParse* cli = nullptr;

    std::vector<std::string> trace_files;
    std::vector<BucketMap> per_file;
    BucketMap merged;
    std::vector<ProcessKey> process_keys;

    std::vector<AggForest> forests;  // one per bucket
    AggForest global_forest;         // used with --global
    long long global_run_time = 0;

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
coro::CoroTask<void> analyze_one(RunCtx* ctx, std::size_t index) {
    const ProcessKey key = ctx->process_keys[index];
    AggForest& forest = ctx->forests[index];
    forest.key = key;

    auto it = ctx->merged.find(key);
    if (it == ctx->merged.end()) co_return;
    project_bucket(it->second, !ctx->cli->time_exclusive, forest);

    const std::size_t before = forest.pool.size();
    if (ctx->cli->aggregate) {
        dedup_forest(forest.roots);
    } else {
        // hashes are part of the binary format and JSON args, so compute
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
            co_await analyze_one(ctx, i);
        });
    }
    co_return;
}

coro::CoroTask<void> task_analyze(RunCtx* ctx, CoroScope* scope) {
    if (ctx->failed) co_return;
    ctx->forests.clear();
    ctx->forests.resize(ctx->process_keys.size());
    RunCtx* ctx_ptr = ctx;
    co_await scope->scope(
        [ctx_ptr](CoroScope& child) mutable -> coro::CoroTask<void> {
            co_await analyze_all(&child, ctx_ptr);
        });
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

    dedup_list(ctx->global_forest.roots);
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

// ── write: text / binary / json ─────────────────────────────────────────────

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
            } else if (format == OutputFormat::TEXT) {
                serialize_text_section(f, multi, (*buffers)[i]);
            } else {  // BINARY: one standalone .call_tree blob per bucket
                render_forest_binary(f.roots, (*buffers)[i]);
            }
            co_return;
        });
    }
    co_return;
}

std::string binary_slice_path(const std::string& base, const ProcessKey& key,
                              bool multi) {
    if (!multi) return base;
    std::string stem = base;
    const std::string ext = ".call_tree";
    if (stem.size() >= ext.size() &&
        stem.compare(stem.size() - ext.size(), ext.size(), ext) == 0) {
        stem.resize(stem.size() - ext.size());
    }
    char buf[96];
    std::snprintf(buf, sizeof(buf), "_pid%u_tid%u_node%u", key.pid, key.tid,
                  key.node_id);
    return stem + buf + ext;
}

coro::CoroTask<void> task_write(RunCtx* ctx, CoroScope* scope) {
    if (ctx->failed || ctx->cli->no_save) co_return;
    const OutputFormat format = ctx->cli->format;

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
        } else {
            render_forest_binary(ctx->global_forest.roots, slice_buffers[0]);
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

    // ── binary: standalone file(s), ClarIOn-compatible ──────────────────
    if (format == OutputFormat::BINARY) {
        if (ctx->cli->gzip) {
            DFTRACER_UTILS_LOG_WARN(
                "%s", "--gzip is ignored for --format binary");
        }
        const bool multi = !ctx->cli->global_merge && slice_buffers.size() > 1;
        for (std::size_t i = 0; i < slice_buffers.size(); ++i) {
            const std::string path =
                ctx->cli->global_merge
                    ? ctx->output_path
                    : binary_slice_path(ctx->output_path,
                                        ctx->forests[i].key, multi);
            if (!write_file(path, slice_buffers[i])) {
                DFTRACER_UTILS_LOG_ERROR("failed to write %s", path.c_str());
                ctx->failed = true;
                co_return;
            }
            std::printf("Output file: %s\n", path.c_str());
        }
        co_return;
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
        case OutputFormat::BINARY:
            return ".call_tree";
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
        "output formats (text tree, .call_tree binary, Chrome Tracing "
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
    if (cli.gzip && cli.format != OutputFormat::BINARY &&
        (ctx.output_path.size() < 3 ||
         ctx.output_path.compare(ctx.output_path.size() - 3, 3, ".gz") != 0)) {
        ctx.output_path += ".gz";
    }

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
