// ClarIOn call tree comparator on dftracer-utils infrastructure.
//
// Compares two call trees produced by clarion_calltree and reports the
// differences. Fully self-contained: uses only public dftracer-utils APIs.
//
// Inputs (auto-detected per file):
//   - ClarIOn binary .call_tree (magic 0xCA117EE1), as written by
//     clarion_calltree --format binary
//   - JSON traces read the dftracer way (indexed reader::TraceReader +
//     simdjson ondemand DFTracerEvent + ArgsMap): clarion_calltree
//     --format json output (count/min/max/hash in args) or any plain
//     .pfw/.pfw.gz trace (count defaults to 1). Events are bucketed by
//     (pid, tid) and nested by time-span containment, so per-process
//     structure is preserved; the buckets' roots are concatenated into
//     one forest for comparison.
//
// Diff semantics (ported from ClarIOn's clarIOn_comparator):
//   - equal structural hash          -> subtree pruned, "-st" suffix,
//                                       dur/count delta only (omitted
//                                       entirely when identical)
//   - only in A / only in B          -> whole subtree tagged "-1" / "-2"
//   - same name, different structure -> DIVERGED, recurse into children
//                                       matched by name
// Structural hashes are always recomputed after loading with the same
// order/multiplicity-independent algorithm clarion_calltree uses, so
// binary and JSON inputs are directly comparable.
//
// Outputs (--format), written to diff.txt / diff.dot / diff.json unless -o:
//   text : ClarIOn diff tree (default)
//   dot  : Graphviz digraph with ClarIOn's colors and legend
//   json : nested diff tree with dur/count deltas

#include <dftracer/utils/core/common/config.h>
#include <dftracer/utils/core/common/filesystem.h>
#include <dftracer/utils/core/common/logging.h>
#include <dftracer/utils/core/coro/task.h>
#include <dftracer/utils/core/pipeline/pipeline.h>
#include <dftracer/utils/core/tasks/coro_scope.h>
#include <dftracer/utils/core/tasks/task.h>
#include <dftracer/utils/utilities/composites/dft/event.h>
#include <dftracer/utils/utilities/reader/trace_reader.h>

#include <algorithm>
#include <cmath>
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

namespace {

enum class DiffFormat { TEXT, DOT, JSON };

// ── ClarIOn binary file format constants ────────────────────────────────────

constexpr std::uint32_t CALLTREE_MAGIC = 0xCA117EE1;
constexpr std::uint32_t CALLTREE_VERSION = 0x00000001;

// ── Tree model (comparator-local; names are owned) ─────────────────────────

struct Node {
    std::string name;
    std::uint64_t ts = 0;  // only used while rebuilding nesting from JSON
    long long dur = 0;
    long long count = 1;
    long long min = std::numeric_limits<long long>::max();
    long long max = std::numeric_limits<long long>::min();
    std::size_t hash = 0;
    std::vector<Node*> children;
};

struct Forest {
    std::vector<std::unique_ptr<Node>> pool;
    std::vector<Node*> roots;

    Node* make() {
        pool.push_back(std::make_unique<Node>());
        return pool.back().get();
    }
};

// Same order/multiplicity-independent structural hash as clarion_calltree.
std::size_t compute_hash(Node* n) {
    std::size_t h = std::hash<std::string_view>{}(std::string_view(n->name));
    std::unordered_set<std::size_t> uniq;
    uniq.reserve(n->children.size());
    for (Node* c : n->children) uniq.insert(compute_hash(c));
    for (std::size_t ch : uniq) h ^= ch + 0x9e3779b9 + (h << 6) + (h >> 2);
    n->hash = h;
    return h;
}

// ── Binary loader (ClarIOn .call_tree format) ───────────────────────────────

class BinaryCursor {
   public:
    BinaryCursor(const char* data, std::size_t size)
        : data_(data), size_(size) {}

    template <typename T>
    bool read(T& out) {
        if (pos_ + sizeof(T) > size_) return false;
        std::memcpy(&out, data_ + pos_, sizeof(T));
        pos_ += sizeof(T);
        return true;
    }

    bool read_str(std::string& out, std::size_t len) {
        if (pos_ + len > size_) return false;
        out.assign(data_ + pos_, len);
        pos_ += len;
        return true;
    }

   private:
    const char* data_;
    std::size_t size_;
    std::size_t pos_ = 0;
};

Node* read_binary_node(BinaryCursor& cur, Forest& forest, bool& ok) {
    Node* n = forest.make();
    std::uint16_t name_len = 0;
    std::int32_t count = 0;
    std::uint32_t n_children = 0;
    if (!cur.read(name_len) || !cur.read_str(n->name, name_len) ||
        !cur.read(n->dur) || !cur.read(count) || !cur.read(n->min) ||
        !cur.read(n->max) || !cur.read(n->hash) || !cur.read(n_children)) {
        ok = false;
        return n;
    }
    n->count = count;
    n->children.reserve(n_children);
    for (std::uint32_t i = 0; i < n_children && ok; ++i) {
        n->children.push_back(read_binary_node(cur, forest, ok));
    }
    return n;
}

bool load_binary(const std::string& path, const std::string& bytes,
                 Forest& forest) {
    BinaryCursor cur(bytes.data(), bytes.size());
    std::uint32_t magic = 0, version = 0;
    std::uint64_t n_roots = 0;
    if (!cur.read(magic) || !cur.read(version) || !cur.read(n_roots)) {
        DFTRACER_UTILS_LOG_ERROR("truncated call_tree header: %s",
                                 path.c_str());
        return false;
    }
    if (magic != CALLTREE_MAGIC) {
        DFTRACER_UTILS_LOG_ERROR("not a call_tree file (got 0x%08X): %s",
                                 magic, path.c_str());
        return false;
    }
    if (version != CALLTREE_VERSION) {
        DFTRACER_UTILS_LOG_ERROR("unsupported call_tree version %u: %s",
                                 version, path.c_str());
        return false;
    }
    forest.roots.reserve(n_roots);
    bool ok = true;
    for (std::uint64_t i = 0; i < n_roots && ok; ++i) {
        forest.roots.push_back(read_binary_node(cur, forest, ok));
    }
    if (!ok) {
        DFTRACER_UTILS_LOG_ERROR("truncated call_tree data: %s", path.c_str());
    }
    return ok;
}

// ── JSON loader (dftracer reader + event parser + args map) ────────────────

struct JsonEvent {
    std::string name;
    std::uint64_t ts = 0;
    std::uint64_t dur = 0;
    long long count = 1;
    long long min = -1;
    long long max = -1;
};

coro::CoroTask<bool> load_json(std::string path, Forest* forest) {
    using composites::dft::DFTracerEvent;
    using reader::ReadConfig;
    using reader::TraceReaderConfig;

    TraceReaderConfig cfg;
    cfg.file_path = path;
    cfg.auto_build_index = true;
    reader::TraceReader trace_reader(std::move(cfg));

    // bucket by (pid, tid) so concurrent processes never nest into each
    // other, mirroring clarion_calltree
    std::unordered_map<std::uint64_t, std::vector<JsonEvent>> buckets;

    auto gen = trace_reader.read_json(ReadConfig{});
    while (auto opt = co_await gen.next()) {
        DFTracerEvent ev;
        if (!DFTracerEvent::parse_ondemand(*opt->parser, ev)) continue;
        if (!ev.is_complete()) continue;

        std::uint64_t tid = ev.tid;
        if (auto p = ev.args["tid"]) tid = p.get<std::uint64_t>();

        JsonEvent je;
        je.name.assign(ev.name.data(), ev.name.size());
        je.ts = ev.ts;
        je.dur = ev.dur;
        // clarion_calltree --format json carries aggregation stats in args
        if (auto p = ev.args["count"])
            je.count = static_cast<long long>(p.get<std::int64_t>());
        if (auto p = ev.args["min"])
            je.min = static_cast<long long>(p.get<std::int64_t>());
        if (auto p = ev.args["max"])
            je.max = static_cast<long long>(p.get<std::int64_t>());

        const std::uint64_t bucket_key = (ev.pid << 20) ^ tid;
        buckets[bucket_key].push_back(std::move(je));
    }

    // per-bucket containment sweep, roots concatenated into one forest
    for (auto& [key, events] : buckets) {
        struct Span {
            Node* node;
            std::uint64_t ts;
            std::uint64_t te;
        };
        std::vector<Span> spans;
        spans.reserve(events.size());
        for (JsonEvent& e : events) {
            Node* n = forest->make();
            n->name = std::move(e.name);
            n->ts = e.ts;
            n->dur = static_cast<long long>(e.dur);
            n->count = e.count;
            n->min = e.min >= 0 ? e.min : n->dur;
            n->max = e.max >= 0 ? e.max : n->dur;
            spans.push_back({n, e.ts, e.ts + e.dur});
        }
        // stable: for identical spans the emission order (parent before
        // child in clarion_calltree JSON) is preserved
        std::stable_sort(spans.begin(), spans.end(),
                         [](const Span& a, const Span& b) {
                             if (a.ts != b.ts) return a.ts < b.ts;
                             return a.te > b.te;
                         });
        std::vector<Span> stack;
        stack.reserve(64);
        for (const Span& s : spans) {
            while (!stack.empty() && !(stack.back().ts <= s.ts &&
                                       stack.back().te >= s.te)) {
                stack.pop_back();
            }
            if (!stack.empty())
                stack.back().node->children.push_back(s.node);
            else
                forest->roots.push_back(s.node);
            stack.push_back(s);
        }
    }
    co_return true;
}

// ── Format detection + load ────────────────────────────────────────────────

bool read_prefix(const std::string& path, char* buf, std::size_t len) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    const bool ok = std::fread(buf, 1, len, f) == len;
    std::fclose(f);
    return ok;
}

bool read_all(const std::string& path, std::string& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    const long size = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    out.resize(static_cast<std::size_t>(size));
    const bool ok =
        std::fread(out.data(), 1, out.size(), f) == out.size();
    std::fclose(f);
    return ok;
}

coro::CoroTask<bool> load_tree(std::string path, Forest* forest) {
    char prefix[4] = {};
    if (!read_prefix(path, prefix, sizeof(prefix))) {
        DFTRACER_UTILS_LOG_ERROR("cannot open input: %s", path.c_str());
        co_return false;
    }
    std::uint32_t magic = 0;
    std::memcpy(&magic, prefix, sizeof(magic));

    bool ok = false;
    if (magic == CALLTREE_MAGIC) {
        std::string bytes;
        ok = read_all(path, bytes) && load_binary(path, bytes, *forest);
    } else {
        ok = co_await load_json(std::move(path), forest);
    }
    if (ok) {
        for (Node* r : forest->roots) compute_hash(r);
    }
    co_return ok;
}

// ── Diff (ported from ClarIOn's clarIOn_comparator) ────────────────────────

enum class DiffType {
    PRUNED_SUBTREE,  // identical structure, children pruned, only dur differs
    ONLY_IN_A,       // node exists only in tree A
    ONLY_IN_B,       // node exists only in tree B
    DIVERGED,        // same name, different subtree structure
};

struct DiffNode {
    std::string name;  // includes suffix: -st, -1, -2
    DiffType type = DiffType::DIVERGED;
    int depth = 0;
    long long dur_a = 0, dur_b = 0;
    long long count_a = 0, count_b = 0;
    double dur_delta_pct = 0.0;
    std::vector<DiffNode*> children;
};

struct DiffPool {
    std::vector<std::unique_ptr<DiffNode>> pool;
    DiffNode* make() {
        pool.push_back(std::make_unique<DiffNode>());
        return pool.back().get();
    }
};

DiffNode* make_only_in(const Node* src, DiffType type,
                       const std::string& suffix, int depth, DiffPool& pool) {
    DiffNode* d = pool.make();
    d->name = src->name + suffix;
    d->type = type;
    d->depth = depth;
    d->dur_a = (type == DiffType::ONLY_IN_A) ? src->dur : 0;
    d->dur_b = (type == DiffType::ONLY_IN_B) ? src->dur : 0;
    d->count_a = (type == DiffType::ONLY_IN_A) ? src->count : 0;
    d->count_b = (type == DiffType::ONLY_IN_B) ? src->count : 0;
    for (const Node* child : src->children) {
        d->children.push_back(
            make_only_in(child, type, suffix, depth + 1, pool));
    }
    return d;
}

DiffNode* diff_nodes(const Node* a, const Node* b, int depth, DiffPool& pool,
                     bool diverged_only) {
    // Case 1: identical hash -> prune children, report dur diff
    if (a && b && a->hash == b->hash) {
        if (a->dur == b->dur && a->count == b->count) return nullptr;
        DiffNode* d = pool.make();
        d->name = a->name + "-st";
        d->type = DiffType::PRUNED_SUBTREE;
        d->depth = depth;
        d->dur_a = a->dur;
        d->dur_b = b->dur;
        d->count_a = a->count;
        d->count_b = b->count;
        d->dur_delta_pct =
            a->dur != 0 ? 100.0 * static_cast<double>(b->dur - a->dur) /
                              static_cast<double>(a->dur)
                        : 0.0;
        return d;
    }

    // Case 2: only in A
    if (a && !b) {
        if (diverged_only) return nullptr;
        return make_only_in(a, DiffType::ONLY_IN_A, "-1", depth, pool);
    }

    // Case 3: only in B
    if (!a && b) {
        if (diverged_only) return nullptr;
        return make_only_in(b, DiffType::ONLY_IN_B, "-2", depth, pool);
    }

    // Case 4: both present, hashes differ -> recurse, match children by name
    DiffNode* d = pool.make();
    d->name = a->name;
    d->type = DiffType::DIVERGED;
    d->depth = depth;
    d->dur_a = a->dur;
    d->dur_b = b->dur;
    d->count_a = a->count;
    d->count_b = b->count;
    d->dur_delta_pct =
        a->dur != 0 ? 100.0 * static_cast<double>(b->dur - a->dur) /
                          static_cast<double>(a->dur)
                    : 0.0;

    std::unordered_map<std::string_view, const Node*> children_b;
    for (const Node* cb : b->children) children_b[cb->name] = cb;

    std::unordered_set<std::string_view> visited;
    for (const Node* ca : a->children) {
        visited.insert(ca->name);
        auto it = children_b.find(ca->name);
        const Node* cb = (it != children_b.end()) ? it->second : nullptr;
        DiffNode* child = diff_nodes(ca, cb, depth + 1, pool, diverged_only);
        if (child) d->children.push_back(child);
    }
    for (const Node* cb : b->children) {
        if (visited.count(cb->name)) continue;
        DiffNode* child =
            diff_nodes(nullptr, cb, depth + 1, pool, diverged_only);
        if (child) d->children.push_back(child);
    }
    return d;
}

std::vector<DiffNode*> diff_forests(const std::vector<Node*>& roots_a,
                                    const std::vector<Node*>& roots_b,
                                    DiffPool& pool, bool diverged_only) {
    std::unordered_map<std::string_view, const Node*> map_b;
    for (const Node* r : roots_b) map_b[r->name] = r;

    std::vector<DiffNode*> result;
    std::unordered_set<std::string_view> visited;

    for (const Node* ra : roots_a) {
        visited.insert(ra->name);
        auto it = map_b.find(ra->name);
        const Node* rb = (it != map_b.end()) ? it->second : nullptr;
        DiffNode* d = diff_nodes(ra, rb, 0, pool, diverged_only);
        if (d) result.push_back(d);
    }
    for (const Node* rb : roots_b) {
        if (visited.count(rb->name)) continue;
        DiffNode* d = diff_nodes(nullptr, rb, 0, pool, diverged_only);
        if (d) result.push_back(d);
    }
    return result;
}

// ── Text output (ClarIOn print_diff_tree format) ────────────────────────────

void render_diff_text(const std::vector<DiffNode*>& nodes,
                      const std::string& prefix, double threshold,
                      std::string& out) {
    char buf[512];
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        const DiffNode* d = nodes[i];
        const bool is_last = (i == nodes.size() - 1);
        const char* conn = is_last ? "└── " : "├── ";
        int w = 0;

        switch (d->type) {
            case DiffType::PRUNED_SUBTREE:
                if (std::abs(d->dur_delta_pct) < threshold) break;
                w = std::snprintf(buf, sizeof(buf),
                                  "%s%s%s  dur: %lld→%lld (%+.1f%%)  "
                                  "count: %lld→%lld\n",
                                  prefix.c_str(), conn, d->name.c_str(),
                                  d->dur_a, d->dur_b, d->dur_delta_pct,
                                  d->count_a, d->count_b);
                break;
            case DiffType::ONLY_IN_A:
                w = std::snprintf(buf, sizeof(buf),
                                  "%s%s%s  dur: %lld  count: %lld\n",
                                  prefix.c_str(), conn, d->name.c_str(),
                                  d->dur_a, d->count_a);
                break;
            case DiffType::ONLY_IN_B:
                w = std::snprintf(buf, sizeof(buf),
                                  "%s%s%s  dur: %lld  count: %lld\n",
                                  prefix.c_str(), conn, d->name.c_str(),
                                  d->dur_b, d->count_b);
                break;
            case DiffType::DIVERGED:
                w = std::snprintf(buf, sizeof(buf),
                                  "%s%s%s  dur: %lld→%lld (%+.1f%%)\n",
                                  prefix.c_str(), conn, d->name.c_str(),
                                  d->dur_a, d->dur_b, d->dur_delta_pct);
                break;
        }
        if (w > 0) out.append(buf, static_cast<std::size_t>(w));

        if (!d->children.empty()) {
            std::string new_prefix = prefix + (is_last ? "    " : "│   ");
            render_diff_text(d->children, new_prefix, threshold, out);
        }
    }
}

// ── Dot output (ClarIOn write_diff_dot, colors and legend preserved) ───────

const char* duration_color(double delta_pct) {
    if (delta_pct < -20.0) return "#1a7a3c";
    if (delta_pct < -10.0) return "#2eab55";
    if (delta_pct < -3.0) return "#6dcf94";
    if (delta_pct < 3.0) return "#CCCCCC";
    if (delta_pct < 10.0) return "#f4a460";
    if (delta_pct < 20.0) return "#e05c2a";
    return "#b71c1c";
}

std::string escape_dot(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '"')
            out += "\\\"";
        else if (c == '\\')
            out += "\\\\";
        else if (c == '\n')
            out += "\\n";
        else
            out += c;
    }
    return out;
}

int render_diff_node_dot(const DiffNode* d, bool diverged_only,
                         double threshold, int& next_id, std::string& out) {
    const int my_id = next_id++;
    const bool skip_self =
        (diverged_only && d->type == DiffType::DIVERGED) ||
        (threshold > 0.0 && std::abs(d->dur_delta_pct) < threshold);

    if (!skip_self) {
        std::string label;
        std::string fill_color;
        std::string style = "filled,rounded";
        std::string shape = "box";

        switch (d->type) {
            case DiffType::PRUNED_SUBTREE:
                label = escape_dot(d->name) + "\\nA: " +
                        std::to_string(d->dur_a) + "  B: " +
                        std::to_string(d->dur_b) + "\\n(" +
                        (d->dur_delta_pct >= 0 ? "+" : "") +
                        std::to_string(static_cast<int>(d->dur_delta_pct)) +
                        "%)";
                fill_color = duration_color(d->dur_delta_pct);
                style = "filled,dashed";
                shape = "diamond";
                break;
            case DiffType::ONLY_IN_A:
                label = escape_dot(d->name) + "\\nOnly in A" + "\\ndur: " +
                        std::to_string(d->dur_a) +
                        "  count: " + std::to_string(d->count_a);
                fill_color = "#1565C0";
                break;
            case DiffType::ONLY_IN_B:
                label = escape_dot(d->name) + "\\nOnly in B" + "\\ndur: " +
                        std::to_string(d->dur_b) +
                        "  count: " + std::to_string(d->count_b);
                fill_color = "#E65100";
                break;
            case DiffType::DIVERGED:
                label = escape_dot(d->name) + "\\nA: " +
                        std::to_string(d->dur_a) + "  B: " +
                        std::to_string(d->dur_b) + "\\n(" +
                        (d->dur_delta_pct >= 0 ? "+" : "") +
                        std::to_string(static_cast<int>(d->dur_delta_pct)) +
                        "%)";
                fill_color = duration_color(d->dur_delta_pct);
                break;
        }

        char buf[1024];
        int w = std::snprintf(
            buf, sizeof(buf),
            "  n%d [label=\"%s\", style=\"%s\", fillcolor=\"%s\","
            " color=\"%s\", fontcolor=\"#FFFFFF\","
            " fontname=\"Helvetica\", fontsize=22, shape=%s];\n",
            my_id, label.c_str(), style.c_str(), fill_color.c_str(),
            fill_color.c_str(), shape.c_str());
        out.append(buf, static_cast<std::size_t>(w));
    }

    for (const DiffNode* child : d->children) {
        const int child_id =
            render_diff_node_dot(child, diverged_only, threshold, next_id,
                                 out);
        const char* edge_style = "solid";
        const char* edge_color = "#333333";
        if (child->type == DiffType::PRUNED_SUBTREE) {
            edge_style = "dashed";
            edge_color = "#888888";
        } else if (child->type == DiffType::ONLY_IN_A) {
            edge_color = "#1565C0";
        } else if (child->type == DiffType::ONLY_IN_B) {
            edge_color = "#E65100";
        }
        char buf[160];
        int w = std::snprintf(buf, sizeof(buf),
                              "  n%d -> n%d [style=\"%s\", color=\"%s\","
                              " arrowsize=0.7, penwidth=1.2];\n",
                              my_id, child_id, edge_style, edge_color);
        out.append(buf, static_cast<std::size_t>(w));
    }
    return my_id;
}

void render_diff_dot(const std::vector<DiffNode*>& roots,
                     const std::string& label_a, const std::string& label_b,
                     bool diverged_only, double threshold, std::string& out) {
    out += "digraph calldiff {\n";
    char buf[512];
    int w = std::snprintf(
        buf, sizeof(buf),
        "  graph [rankdir=TB, bgcolor=\"#f9f9f9\","
        " fontname=\"Helvetica\", label=\"%s vs %s\","
        " fontcolor=\"#DDDDDD\", fontsize=14,"
        " splines=ortho, nodesep=0.4, ranksep=0.6];\n",
        escape_dot(label_a).c_str(), escape_dot(label_b).c_str());
    out.append(buf, static_cast<std::size_t>(w));
    out += "  node  [margin=\"0.15,0.08\"];\n";
    out += "  edge  [arrowhead=open];\n\n";

    out +=
        "  subgraph cluster_legend {\n"
        "    label=\"Legend\";\n"
        "    fontcolor=\"#DDDDDD\";\n"
        "    color=\"#555555\";\n"
        "    fontsize=11;\n"
        "    style=rounded;\n"
        "    L0 [label=\"Faster (>20%)\",  style=\"filled,rounded\","
        " fillcolor=\"#1a7a3c\", fontcolor=\"#FFFFFF\","
        " fontsize=10, shape=box];\n"
        "    L1 [label=\"Faster (>3%)\",   style=\"filled,rounded\","
        " fillcolor=\"#6dcf94\", fontcolor=\"#FFFFFF\","
        " fontsize=10, shape=box];\n"
        "    L2 [label=\"No change\",      style=\"filled,rounded\","
        " fillcolor=\"#CCCCCC\", fontcolor=\"#333333\","
        " fontsize=10, shape=box];\n"
        "    L3 [label=\"Slower (>3%)\",  style=\"filled,rounded\","
        " fillcolor=\"#f4a460\", fontcolor=\"#FFFFFF\","
        " fontsize=10, shape=box];\n"
        "    L4 [label=\"Slower (>20%)\", style=\"filled,rounded\","
        " fillcolor=\"#b71c1c\", fontcolor=\"#FFFFFF\","
        " fontsize=10, shape=box];\n"
        "    L5 [label=\"Only in A\",      style=\"filled,rounded\","
        " fillcolor=\"#1565C0\", fontcolor=\"#FFFFFF\","
        " fontsize=10, shape=box];\n"
        "    L6 [label=\"Only in B\",      style=\"filled,rounded\","
        " fillcolor=\"#E65100\", fontcolor=\"#FFFFFF\","
        " fontsize=10, shape=box];\n"
        "    L7 [label=\"Pruned subtree\\n(same hash)\","
        " style=\"filled,rounded,dashed\", shape=\"diamond\","
        " fillcolor=\"#6dcf94\", fontcolor=\"#FFFFFF\","
        " fontsize=22];\n"
        "    L0 -> L1 -> L2 -> L3 -> L4 -> L5 -> L6 -> L7"
        " [style=invis];\n"
        "  }\n\n";

    int next_id = 0;
    for (const DiffNode* root : roots) {
        render_diff_node_dot(root, diverged_only, threshold, next_id, out);
    }
    out += "}\n";
}

// ── JSON output (nested diff tree) ──────────────────────────────────────────

void append_escaped_json(std::string& out, std::string_view s) {
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

const char* diff_type_name(DiffType t) {
    switch (t) {
        case DiffType::PRUNED_SUBTREE:
            return "pruned_subtree";
        case DiffType::ONLY_IN_A:
            return "only_in_a";
        case DiffType::ONLY_IN_B:
            return "only_in_b";
        case DiffType::DIVERGED:
            return "diverged";
    }
    return "unknown";
}

void render_diff_json_node(const DiffNode* d, double threshold, int indent,
                           std::string& out) {
    const std::string pad(static_cast<std::size_t>(indent) * 2, ' ');
    out += pad;
    out += "{\"name\":\"";
    append_escaped_json(out, d->name);
    char buf[256];
    int w = std::snprintf(
        buf, sizeof(buf),
        "\",\"type\":\"%s\",\"depth\":%d,\"dur_a\":%lld,\"dur_b\":%lld,"
        "\"count_a\":%lld,\"count_b\":%lld,\"dur_delta_pct\":%.2f",
        diff_type_name(d->type), d->depth, d->dur_a, d->dur_b, d->count_a,
        d->count_b, d->dur_delta_pct);
    out.append(buf, static_cast<std::size_t>(w));

    // collect printable children (respect threshold for pruned nodes,
    // matching the text output)
    std::vector<const DiffNode*> kids;
    kids.reserve(d->children.size());
    for (const DiffNode* c : d->children) {
        if (c->type == DiffType::PRUNED_SUBTREE &&
            std::abs(c->dur_delta_pct) < threshold) {
            continue;
        }
        kids.push_back(c);
    }
    if (kids.empty()) {
        out += "}";
        return;
    }
    out += ",\"children\":[\n";
    for (std::size_t i = 0; i < kids.size(); ++i) {
        render_diff_json_node(kids[i], threshold, indent + 1, out);
        if (i + 1 < kids.size()) out += ",";
        out += "\n";
    }
    out += pad;
    out += "]}";
}

void render_diff_json(const std::vector<DiffNode*>& roots,
                      const std::string& file_a, const std::string& file_b,
                      double threshold, std::string& out) {
    out += "{\"a\":\"";
    append_escaped_json(out, file_a);
    out += "\",\"b\":\"";
    append_escaped_json(out, file_b);
    out += "\",\"diff\":[\n";
    std::vector<const DiffNode*> printable;
    printable.reserve(roots.size());
    for (const DiffNode* r : roots) {
        if (r->type == DiffType::PRUNED_SUBTREE &&
            std::abs(r->dur_delta_pct) < threshold) {
            continue;
        }
        printable.push_back(r);
    }
    for (std::size_t i = 0; i < printable.size(); ++i) {
        render_diff_json_node(printable[i], threshold, 1, out);
        if (i + 1 < printable.size()) out += ",";
        out += "\n";
    }
    out += "]}\n";
}

// ── CLI / pipeline plumbing ─────────────────────────────────────────────────

class ComparatorArgParse : public cli::ArgParse {
   public:
    cli::PipelineArgs pipeline;

    std::string file_a;
    std::string file_b;
    std::string output;
    double threshold = 0.0;
    bool diverged = false;
    DiffFormat format = DiffFormat::TEXT;

    explicit ComparatorArgParse(argparse::ArgumentParser& p) : ArgParse(p) {
        schema(pipeline);
    }

   protected:
    void register_args() override {
        parser()
            .add_argument("file_a")
            .help("Baseline call tree (.call_tree binary or JSON trace)")
            .required();
        parser()
            .add_argument("file_b")
            .help("Call tree to compare (.call_tree binary or JSON trace)")
            .required();
        parser()
            .add_argument("-o", "--output")
            .help("Output path (default: diff.txt / diff.dot / diff.json "
                  "by format)")
            .default_value<std::string>("");
        parser()
            .add_argument("-f", "--format")
            .help("Output format: 'text', 'dot', or 'json'")
            .default_value<std::string>("text");
        parser()
            .add_argument("--threshold")
            .help("Only report duration changes above this %% (default: 0)")
            .default_value<double>(0.0)
            .scan<'g', double>();
        parser()
            .add_argument("-d", "--diverged")
            .help("Don't report only-in-A/only-in-B subtrees")
            .flag();
    }

    void post_parse() override {
        file_a = parser().get<std::string>("file_a");
        file_b = parser().get<std::string>("file_b");
        output = parser().get<std::string>("--output");
        threshold = parser().get<double>("--threshold");
        diverged = parser().get<bool>("--diverged");

        const std::string fmt = parser().get<std::string>("--format");
        if (fmt == "text") {
            format = DiffFormat::TEXT;
        } else if (fmt == "dot") {
            format = DiffFormat::DOT;
        } else if (fmt == "json") {
            format = DiffFormat::JSON;
        } else {
            throw std::runtime_error(
                "--format must be 'text', 'dot', or 'json'");
        }
    }
};

struct RunCtx {
    const ComparatorArgParse* cli = nullptr;

    Forest forest_a;
    Forest forest_b;
    DiffPool diff_pool;
    std::vector<DiffNode*> diff;

    bool failed = false;
};

// load: both inputs in parallel via CoroScope fan-out
coro::CoroTask<void> load_both(CoroScope* child, RunCtx* ctx) {
    struct Job {
        std::string path;
        Forest* forest;
    };
    const Job jobs[2] = {{ctx->cli->file_a, &ctx->forest_a},
                         {ctx->cli->file_b, &ctx->forest_b}};
    for (const Job& job : jobs) {
        std::string path = job.path;
        Forest* forest = job.forest;
        child->spawn([path = std::move(path), forest,
                      ctx](CoroScope&) mutable -> coro::CoroTask<void> {
            if (!co_await load_tree(std::move(path), forest)) {
                ctx->failed = true;
            }
        });
    }
    co_return;
}

coro::CoroTask<void> task_load(RunCtx* ctx, CoroScope* scope) {
    RunCtx* ctx_ptr = ctx;
    co_await scope->scope(
        [ctx_ptr](CoroScope& child) mutable -> coro::CoroTask<void> {
            co_await load_both(&child, ctx_ptr);
        });
    if (!ctx->failed) {
        DFTRACER_UTILS_LOG_INFO(
            "loaded call trees: A has %zu roots, B has %zu roots",
            ctx->forest_a.roots.size(), ctx->forest_b.roots.size());
    }
    co_return;
}

coro::CoroTask<void> task_diff(RunCtx* ctx) {
    if (ctx->failed) co_return;
    ctx->diff = diff_forests(ctx->forest_a.roots, ctx->forest_b.roots,
                             ctx->diff_pool, ctx->cli->diverged);
    DFTRACER_UTILS_LOG_INFO("diff completed: %zu top-level differences",
                            ctx->diff.size());
    co_return;
}

coro::CoroTask<void> task_write(RunCtx* ctx) {
    if (ctx->failed) co_return;
    const auto& cli = *ctx->cli;

    std::string out;
    switch (cli.format) {
        case DiffFormat::TEXT:
            render_diff_text(ctx->diff, "", cli.threshold, out);
            break;
        case DiffFormat::DOT:
            render_diff_dot(ctx->diff, cli.file_a, cli.file_b, cli.diverged,
                            cli.threshold, out);
            break;
        case DiffFormat::JSON:
            render_diff_json(ctx->diff, cli.file_a, cli.file_b, cli.threshold,
                             out);
            break;
    }

    std::string path = cli.output;
    if (path.empty()) {
        switch (cli.format) {
            case DiffFormat::TEXT:
                path = "diff.txt";
                break;
            case DiffFormat::DOT:
                path = "diff.dot";
                break;
            case DiffFormat::JSON:
                path = "diff.json";
                break;
        }
    }

    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) {
        DFTRACER_UTILS_LOG_ERROR("cannot open output: %s", path.c_str());
        ctx->failed = true;
        co_return;
    }
    const bool ok = std::fwrite(out.data(), 1, out.size(), f) == out.size();
    std::fclose(f);
    if (!ok) {
        ctx->failed = true;
        co_return;
    }
    std::printf("Output file: %s\n", path.c_str());
    co_return;
}

int run(int argc, char** argv) {
    dftracer::utils::logger::init();

    argparse::ArgumentParser program("clarion_comparator",
                                     DFTRACER_UTILS_PACKAGE_VERSION);
    program.add_description(
        "Compare two call trees produced by clarion_calltree (binary "
        ".call_tree or JSON; JSON is read the dftracer way and plain traces "
        "also work). Emits a diff as text, Graphviz dot, or JSON.");

    ComparatorArgParse cli(program);
    if (!cli::setup_and_parse(cli, argc, argv)) return 1;

    RunCtx ctx;
    ctx.cli = &cli;

    auto pipeline_config =
        cli::build_pipeline_config("ClarIOn Comparator", cli.pipeline);
    Pipeline pipeline(pipeline_config);

    RunCtx* ctx_ptr = &ctx;
    auto load = make_task(
        [ctx_ptr](CoroScope& scope) -> coro::CoroTask<void> {
            co_await task_load(ctx_ptr, &scope);
        },
        "load");
    auto diff = make_task(
        [ctx_ptr](CoroScope&) -> coro::CoroTask<void> {
            co_await task_diff(ctx_ptr);
        },
        "diff");
    auto write = make_task(
        [ctx_ptr](CoroScope&) -> coro::CoroTask<void> {
            co_await task_write(ctx_ptr);
        },
        "write");

    diff->depends_on(load);
    write->depends_on(diff);

    pipeline.set_source(load);
    pipeline.set_destination(write);
    pipeline.execute();

    return ctx.failed ? 1 : 0;
}

}  // namespace

int main(int argc, char** argv) { return run(argc, argv); }
