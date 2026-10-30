#ifndef DFTRACER_UTILS_UTILITIES_CATALOG_KNOWLEDGE_TREE_H
#define DFTRACER_UTILS_UTILITIES_CATALOG_KNOWLEDGE_TREE_H

// Knowledge tree + divergence/configuration tables -- the Catalog design of
// "Explaining HPC I/O Performance with Confidence", Sec. IV-C.
//
// ClarIOn maintains one Catalog per I/O API call, shared across every workflow
// that invokes it. A Catalog records how configurations determine the
// execution of that API call using a knowledge tree and two tables.
//
//  * Knowledge tree. The call trees of all profiled configurations (one per
//    run) are merged top-down. At each level a child is matched to an existing
//    child of the same parent by its function name, so two nodes merge only if
//    their entire ancestry coincides. A child with no name match is tagged and
//    appended (the first/baseline run defines the untagged skeleton; only
//    later runs introduce tags). Nodes where configurations or nondeterminism
//    take different paths are branch points, classified -- once enough samples
//    of each configuration are seen -- as configuration-driven (every
//    configuration consistently takes the same path across its runs),
//    noise-driven (configurations split across paths regardless of their
//    parameters), or mixed. Each node holds its function name, call count,
//    branch tag, data size, and a log-scale histogram of its exclusive
//    durations across each configuration.
//
//  * Divergences table. For each tag: the number of runs reaching it, the
//    configurations that took this path, and the bytes it reads and writes.
//
//  * Configuration table. Fully resolved parameter values for each
//    configuration. (Built by the caller; see ConfigRow.)
//
// Data size and the resolved parameter values are not yet emitted by the
// upstream call-tree dumps, so those fields default to 0/empty and flow
// through the structure until the producer fills them in.
//
// This header is intentionally pure (standard library only, no trace I/O) so
// the merge/classify/serialize logic is unit-testable without a reader or
// runtime. The caller (clarion_catalog.cpp) reconstructs KNode trees from the
// on-disk subtree dumps, labels each by its configuration, and writes outputs.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace dftracer::utils::catalog {

// How a branch point's divergence is explained once enough samples of each
// configuration have been observed.
enum class BranchClass {
    None,          // not a branch point (runs agree on the child set here)
    ConfigDriven,  // every configuration consistently takes one path
    NoiseDriven,   // configurations split across paths regardless of parameters
    Mixed          // some configurations consistent, others split
};

inline const char* branch_class_name(BranchClass b) {
    switch (b) {
        case BranchClass::ConfigDriven: return "config-driven";
        case BranchClass::NoiseDriven: return "noise-driven";
        case BranchClass::Mixed: return "mixed";
        case BranchClass::None: break;
    }
    return "";
}

// A node in a knowledge tree. Owns its children, so one KNode root owns a whole
// tree (one Catalog / knowledge tree per distinct root name == per API call).
struct KNode {
    std::string name;
    std::string cat;
    long long dur = 0;        // inclusive duration, summed over merged runs
    long long count = 0;      // call count, summed over merged runs
    long long size = 0;       // data size in bytes (stub: 0 until emitted)
    std::uint64_t first_ts = 0;
    std::size_t hash = 0;     // structural hash (compute_hash), for dedup
    int tag = -1;             // branch tag: >= 0 once appended as a divergence
    BranchClass branch = BranchClass::None;  // set by classify_branches

    // Per-configuration log-scale histogram of this node's exclusive durations
    // (config label -> (bucket -> count)); bucket is floor(log2(excl)) + 1.
    std::map<std::string, std::map<int, long long>> excl_hist;
    // Per-configuration count of runs that reached this node.
    std::map<std::string, long long> runs;
    // Per-configuration accumulators that let the Mitigator (Sec. IV-E) derive
    // a parameter's impact on this node without a search: the summed call count,
    // exclusive duration, and data size over the runs of each configuration.
    // multiplicity(cfg) == cfg_count / runs (calls per run) and intensity(cfg)
    // == cfg_excl / cfg_count (exclusive time per call, divided by bytes per
    // call when cfg_size > 0) are read back from these.
    std::map<std::string, long long> cfg_count;
    std::map<std::string, long long> cfg_excl;
    std::map<std::string, long long> cfg_size;
    // Per-configuration set of distinct child-name signatures seen across the
    // runs that reached this node, used to classify branch points.
    std::map<std::string, std::set<std::string>> child_sigs;

    std::vector<std::unique_ptr<KNode>> children;

    KNode* child_by_name(std::string_view n) {
        for (auto& c : children)
            if (c->name == n) return c.get();
        return nullptr;
    }

    KNode* add_child(std::string n, std::string c = {}) {
        children.push_back(std::make_unique<KNode>());
        KNode* k = children.back().get();
        k->name = std::move(n);
        k->cat = std::move(c);
        return k;
    }
};

// One row of the divergences table: a single tagged (appended) node, with the
// runs and configurations that reached it and the bytes it moves.
struct DivergenceRow {
    int tag_id = -1;
    std::string api_call;            // root function name of the knowledge tree
    std::string node;                // name of the tagged (divergence) node
    int depth = 0;                   // depth of that node (root == 0)
    BranchClass parent_branch = BranchClass::None;  // class of its branch point
    long long num_runs = 0;          // runs reaching this tagged node
    std::set<std::string> configs;   // configurations that took this path
    long long bytes_read = 0;        // stub: 0 until emitted
    long long bytes_write = 0;       // stub: 0 until emitted
};

// One row of the configuration table: a profiled configuration and its fully
// resolved parameter values (stub empty until emitted), plus bookkeeping the
// caller fills in (run count and the API calls it covers).
struct ConfigRow {
    std::string config;
    long long num_runs = 0;
    std::set<std::string> api_calls;
    std::vector<std::pair<std::string, std::string>> params;  // stub: empty
};

// Strip a trailing ":0x<hex>" address suffix, e.g. "H5Dwrite:0xd89d0" ->
// "H5Dwrite". Names without such a suffix are returned unchanged.
inline std::string strip_addr(std::string_view name) {
    const auto pos = name.rfind(":0x");
    if (pos != std::string_view::npos && pos + 3 < name.size() &&
        name.find_first_not_of("0123456789abcdefABCDEF", pos + 3) ==
            std::string_view::npos) {
        return std::string(name.substr(0, pos));
    }
    return std::string(name);
}

// Order/multiplicity-independent structural hash (same scheme as
// clarion_calltree's ClarIOn hashing), computed bottom-up and stored on each
// node so identical subtrees compare in O(1). Used to dedup identical runs.
inline std::size_t compute_hash(KNode* n) {
    std::size_t h = std::hash<std::string>{}(n->name);
    std::unordered_set<std::size_t> uniq;
    uniq.reserve(n->children.size());
    for (auto& c : n->children) uniq.insert(compute_hash(c.get()));
    for (std::size_t ch : uniq) h ^= ch + 0x9e3779b9 + (h << 6) + (h >> 2);
    n->hash = h;
    return h;
}

namespace detail {

// Log-scale histogram bucket for an exclusive duration: 0 for non-positive,
// otherwise floor(log2(v)) + 1, so values double every bucket.
inline int log_bucket(long long v) {
    if (v <= 0) return 0;
    int b = 0;
    unsigned long long x = static_cast<unsigned long long>(v);
    while (x) {
        x >>= 1;
        ++b;
    }
    return b;  // v in (2^(b-1), 2^b]
}

inline std::string join(const std::vector<std::string>& v, char sep = ';') {
    std::string out;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) out += sep;
        out += v[i];
    }
    return out;
}

inline void escape(std::string& out, std::string_view s) {
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\t': out += "\\t"; break;
            case '\r': out += "\\r"; break;
            default: out += c;
        }
    }
}

inline void serialize_node(const KNode* n, std::uint64_t start, int depth,
                           std::uint64_t& idx, std::string& out) {
    char buf[256];
    int w = std::snprintf(buf, sizeof(buf), "{\"id\":%llu,\"name\":\"",
                          static_cast<unsigned long long>(idx++));
    out.append(buf, static_cast<std::size_t>(w));
    escape(out, n->name);
    out.append("\",\"cat\":\"");
    escape(out, n->cat.empty() ? std::string_view("clarion")
                               : std::string_view(n->cat));
    w = std::snprintf(
        buf, sizeof(buf),
        "\",\"pid\":0,\"tid\":0,\"ts\":%llu,\"dur\":%lld,\"ph\":\"X\","
        "\"args\":{\"count\":%lld,\"size\":%lld,\"hash\":%zu,\"depth\":%d",
        static_cast<unsigned long long>(start), n->dur, n->count, n->size,
        n->hash, depth);
    out.append(buf, static_cast<std::size_t>(w));
    if (n->tag >= 0) {
        w = std::snprintf(buf, sizeof(buf), ",\"tag\":%d", n->tag);
        out.append(buf, static_cast<std::size_t>(w));
    }
    if (n->branch != BranchClass::None) {
        out.append(",\"branch\":\"");
        out.append(branch_class_name(n->branch));
        out.append("\"");
    }
    // Per-configuration log-scale histogram of exclusive durations.
    if (!n->excl_hist.empty()) {
        out.append(",\"excl_hist\":{");
        bool first_cfg = true;
        for (const auto& [cfg, hist] : n->excl_hist) {
            if (!first_cfg) out += ',';
            first_cfg = false;
            out += '"';
            escape(out, cfg);
            out.append("\":[");
            bool first_b = true;
            for (const auto& [bucket, cnt] : hist) {
                if (!first_b) out += ',';
                first_b = false;
                w = std::snprintf(buf, sizeof(buf), "[%d,%lld]", bucket, cnt);
                out.append(buf, static_cast<std::size_t>(w));
            }
            out.append("]");
        }
        out.append("}");
    }
    out.append("}},\n");

    std::uint64_t cursor = start;
    for (auto& c : n->children) {
        serialize_node(c.get(), cursor, depth + 1, idx, out);
        cursor += static_cast<std::uint64_t>(std::max<long long>(c->dur, 0));
    }
}

}  // namespace detail

// Merge one run (an incoming aggregated call tree for a single run of
// configuration `cfg`) into the knowledge tree rooted at `knowledge` (both
// share the API call's name). Matching is top-down by function name; a child
// present in the run but not yet in the knowledge tree is appended, and --
// unless `baseline` is set (the first run merged into this tree, which defines
// the untagged skeleton) -- tagged with a fresh id from `next_tag`. Each
// visited node accrues the run's count, duration, data size, a log-scale
// exclusive-duration sample, and its child-set signature, all weighted by
// `mult` (how many identical runs this incoming tree stands in for). Tagging is
// done here; the divergences table is derived afterward (collect_divergences).
inline void merge_run(KNode* knowledge, const KNode* incoming,
                      const std::string& cfg, bool baseline, long long mult,
                      int& next_tag, int depth = 0) {
    knowledge->count += incoming->count * mult;
    knowledge->dur += incoming->dur * mult;
    knowledge->size += incoming->size * mult;
    if (knowledge->first_ts == 0 ||
        (incoming->first_ts != 0 && incoming->first_ts < knowledge->first_ts))
        knowledge->first_ts = incoming->first_ts;
    if (knowledge->cat.empty()) knowledge->cat = incoming->cat;

    long long excl = incoming->dur;
    for (auto& c : incoming->children) excl -= c->dur;
    knowledge->excl_hist[cfg][detail::log_bucket(excl)] += mult;
    knowledge->runs[cfg] += mult;
    knowledge->cfg_count[cfg] += incoming->count * mult;
    knowledge->cfg_excl[cfg] += excl * mult;
    knowledge->cfg_size[cfg] += incoming->size * mult;

    std::vector<std::string> names;
    names.reserve(incoming->children.size());
    for (auto& c : incoming->children) names.push_back(c->name);
    std::sort(names.begin(), names.end());
    knowledge->child_sigs[cfg].insert(detail::join(names));

    for (auto& ic : incoming->children) {
        KNode* kc = knowledge->child_by_name(ic->name);
        if (!kc) {
            kc = knowledge->add_child(ic->name, ic->cat);
            if (!baseline) kc->tag = next_tag++;
        }
        merge_run(kc, ic.get(), cfg, baseline, mult, next_tag, depth + 1);
    }
}

// Classify every branch point in the tree. A node is a branch point when the
// runs that reached it did not all take the same child set (more than one
// distinct child signature across all configurations). The class separates
// configuration-driven divergence from run-to-run nondeterminism (see
// BranchClass). Leaves and nodes with a single observed signature stay None.
inline void classify_branches(KNode* n) {
    std::set<std::string> all_sigs;
    for (const auto& [cfg, sigs] : n->child_sigs)
        for (const auto& s : sigs) all_sigs.insert(s);
    if (all_sigs.size() > 1) {
        bool any_split = false, any_consistent = false;
        for (const auto& [cfg, sigs] : n->child_sigs) {
            if (sigs.size() > 1)
                any_split = true;
            else
                any_consistent = true;
        }
        if (any_split && any_consistent)
            n->branch = BranchClass::Mixed;
        else if (any_split)
            n->branch = BranchClass::NoiseDriven;
        else
            n->branch = BranchClass::ConfigDriven;
    }
    for (auto& c : n->children) classify_branches(c.get());
}

// Walk the knowledge tree and emit one divergences-table row per tagged node:
// the runs reaching it, the configurations that took that path, the class of
// the branch point it hangs off, and the bytes it moves (stub). `api_call` is
// the tree's root function name. Call after merge + classify.
inline void collect_divergences(const KNode* n, const std::string& api_call,
                                std::vector<DivergenceRow>& out, int depth = 0,
                                BranchClass parent_branch = BranchClass::None) {
    if (n->tag >= 0) {
        DivergenceRow r;
        r.tag_id = n->tag;
        r.api_call = api_call;
        r.node = n->name;
        r.depth = depth;
        r.parent_branch = parent_branch;
        for (const auto& [cfg, cnt] : n->runs) {
            r.num_runs += cnt;
            r.configs.insert(cfg);
        }
        r.bytes_read = 0;        // stub until the producer emits per-node bytes
        r.bytes_write = n->size;  // carry the (stub) data size as written bytes
        out.push_back(std::move(r));
    }
    for (auto& c : n->children)
        collect_divergences(c.get(), api_call, out, depth + 1, n->branch);
}

// Serialize one or more knowledge-tree roots as a Chrome-Tracing JSON array
// (the same "[" + newline-delimited ph:X events format the rest of the
// toolchain reads). Tagged nodes carry a "tag" field, branch points a "branch"
// class, and every node a per-configuration exclusive-duration histogram.
inline std::string serialize_knowledge(const std::vector<KNode*>& roots) {
    std::string out = "[\n";
    std::uint64_t idx = 0;
    for (KNode* r : roots) detail::serialize_node(r, 0, 0, idx, out);
    if (out.size() >= 2 && out[out.size() - 2] == ',' &&
        out[out.size() - 1] == '\n') {
        out.resize(out.size() - 2);
        out.append("\n]\n");
    } else {
        out.append("]\n");
    }
    return out;
}

}  // namespace dftracer::utils::catalog

#endif  // DFTRACER_UTILS_UTILITIES_CATALOG_KNOWLEDGE_TREE_H
