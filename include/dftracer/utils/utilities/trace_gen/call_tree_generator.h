#ifndef DFTRACER_UTILS_UTILITIES_TRACE_GEN_CALL_TREE_GENERATOR_H
#define DFTRACER_UTILS_UTILITIES_TRACE_GEN_CALL_TREE_GENERATOR_H

#include <dftracer/utils/utilities/trace_gen/fake_trace_writer.h>

#include <algorithm>
#include <cstdint>
#include <deque>
#include <fstream>
#include <random>
#include <string>
#include <vector>

// Synthetic call-tree trace generation.
//
// Produces DFTracer .pfw / .pfw.gz traces whose events, when read back by the
// call-tree builder, reconstruct into a known call tree. The builder derives
// the hierarchy from each event's explicit depth (args.level) plus time
// containment of [ts, ts+dur] within the same pid/tid. This generator lays the
// events out with an Euler tour so every child's interval is strictly nested
// inside its parent's and siblings never overlap, which makes the reconstructed
// tree match the generated one exactly.
namespace dftracer::utils::utilities::trace_gen {

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
struct CallTreeGenConfig {
    // Total number of nodes (= trace events) in the generated tree. The tree
    // is grown until it holds exactly this many nodes. Must be >= 1 and must
    // fit within a complete `width`-ary tree of the given `depth` (see
    // call_tree_capacity_at_least).
    std::size_t num_nodes = 100;

    // Maximum depth of the tree. The root is at level 0, so a `depth` of D
    // allows levels 0..D (at most D+1 nodes along any root-to-leaf path).
    int depth = 4;

    // Maximum number of children any node may have (branching factor cap).
    int width = 3;

    // 0-100: the chance, rolled independently for each potential extra child
    // slot beyond the first, that the slot is filled. 0 yields a chain-like
    // tree (one child per node where possible); 100 yields a full `width`-ary
    // tree. Each expandable node always receives at least one child so the
    // tree can grow to `num_nodes`.
    int child_chance = 50;

    // Process identity the whole tree is emitted under. A single pid/tid makes
    // the events form one process call tree.
    std::uint32_t pid = 1000;
    std::uint32_t tid = 1000;

    // Timing. Each Euler-tour tick advances the clock by `time_unit`
    // microseconds, starting from `base_ts`. A leaf therefore has a duration of
    // `time_unit`; interior nodes are longer and strictly contain their
    // subtree.
    std::uint64_t base_ts = 1'000'000;
    std::uint64_t time_unit = 1;

    // RNG seed for reproducible trees. 0 means seed from a random device.
    std::uint64_t seed = 0;

    // Event names/categories, cycled across nodes. Defaults mirror the other
    // DFTracer test fixtures.
    std::vector<std::string> names = {"read",  "write", "open",  "close",
                                      "pread", "pwrite", "fread", "fwrite"};
    std::vector<std::string> cats = {"POSIX", "POSIX", "POSIX", "POSIX",
                                     "POSIX", "POSIX", "STDIO", "STDIO"};
};

// A single generated node. Parent/level are recorded so callers (e.g. tests)
// can assert the expected shape without re-reading the file.
struct GeneratedCall {
    std::uint64_t id = 0;
    std::uint64_t parent_id = 0;  // 0 => root
    int level = 0;
    std::uint64_t ts = 0;
    std::uint64_t dur = 0;
    std::string name;
    std::string cat;
    std::vector<std::uint64_t> children;  // child ids, in creation order
};

// ---------------------------------------------------------------------------
// Capacity check: can a complete `width`-ary tree of the given `depth` hold at
// least `n` nodes? Accumulates level sizes with saturation so it never
// overflows for large depth/width.
// ---------------------------------------------------------------------------
inline bool call_tree_capacity_at_least(int depth, int width, std::size_t n) {
    if (n == 0) return true;
    if (depth < 0 || width < 1) return false;
    std::size_t total = 0;        // nodes in levels 0..current
    std::size_t level_nodes = 1;  // nodes at the current level (root level 0)
    const std::size_t w = static_cast<std::size_t>(width);
    for (int level = 0; level <= depth; ++level) {
        total += level_nodes;  // level_nodes is kept <= n below, so no overflow
        if (total >= n) return true;
        // Stop before level_nodes *= w could exceed n (and possibly overflow):
        // if this level alone already reaches n, capacity is sufficient.
        if (level_nodes > n / w) return true;
        level_nodes *= w;
    }
    return total >= n;
}

// ---------------------------------------------------------------------------
// Grow a call tree of exactly cfg.num_nodes nodes and assign Euler-tour timing.
// Returns the nodes in id order (root first, id == index + 1); empty on an
// invalid/infeasible configuration.
// ---------------------------------------------------------------------------
inline std::vector<GeneratedCall> generate_call_tree(
    const CallTreeGenConfig& cfg) {
    std::vector<GeneratedCall> nodes;
    if (cfg.num_nodes == 0 || cfg.depth < 0 || cfg.width < 1) return nodes;
    if (cfg.names.empty() || cfg.cats.empty()) return nodes;
    if (!call_tree_capacity_at_least(cfg.depth, cfg.width, cfg.num_nodes))
        return nodes;

    const int chance = cfg.child_chance < 0     ? 0
                       : cfg.child_chance > 100 ? 100
                                                : cfg.child_chance;

    std::mt19937_64 rng(cfg.seed != 0 ? cfg.seed : std::random_device{}());
    std::uniform_int_distribution<int> roll(1, 100);

    nodes.reserve(cfg.num_nodes);

    auto make_node = [&](std::uint64_t parent_id, int level) -> std::size_t {
        GeneratedCall n;
        n.id = static_cast<std::uint64_t>(nodes.size()) + 1;
        n.parent_id = parent_id;
        n.level = level;
        const std::size_t name_idx = (n.id - 1) % cfg.names.size();
        const std::size_t cat_idx = (n.id - 1) % cfg.cats.size();
        n.name = cfg.names[name_idx];
        n.cat = cfg.cats[cat_idx];
        nodes.push_back(std::move(n));
        return nodes.size() - 1;
    };

    // Root.
    make_node(/*parent_id=*/0, /*level=*/0);
    std::size_t count = 1;

    auto can_parent = [&](std::size_t idx) {
        return nodes[idx].level < cfg.depth &&
               static_cast<int>(nodes[idx].children.size()) < cfg.width;
    };
    auto add_child = [&](std::size_t idx) -> std::size_t {
        const std::size_t child_idx =
            make_node(nodes[idx].id, nodes[idx].level + 1);
        nodes[idx].children.push_back(nodes[child_idx].id);
        ++count;
        return child_idx;
    };

    // Phase 1 - breadth-first growth. Each node, when first reached, gets one
    // mandatory child (so a single path can always extend toward max depth)
    // plus one more child for every further slot whose independent chance roll
    // succeeds. A chance of 0 therefore yields a chain (one child per node); a
    // chance of 100 yields a complete width-ary tree. Growth stops as soon as
    // num_nodes is reached.
    std::deque<std::size_t> queue;
    queue.push_back(0);
    while (count < cfg.num_nodes && !queue.empty()) {
        const std::size_t idx = queue.front();
        queue.pop_front();
        if (nodes[idx].level >= cfg.depth) continue;

        int to_add = 1;  // mandatory first child
        for (int s = 1; s < cfg.width; ++s) {
            if (roll(rng) <= chance) ++to_add;
        }
        const int budget = static_cast<int>(cfg.num_nodes - count);
        if (to_add > budget) to_add = budget;

        for (int c = 0; c < to_add; ++c) {
            const std::size_t child_idx = add_child(idx);
            if (nodes[child_idx].level < cfg.depth) queue.push_back(child_idx);
        }
    }

    // Phase 2 - top-up. Low chances can exhaust the stack before reaching
    // num_nodes (a chain holds at most depth+1 nodes). Fill the remainder
    // deepest-first among nodes that still have free slots, which keeps the
    // added branching close to the existing leaves rather than widening the
    // root. Capacity was validated up front, so this always reaches num_nodes.
    if (count < cfg.num_nodes) {
        // Worklist ordered shallow..deep, so back() is the deepest node.
        std::vector<std::size_t> work;
        for (std::size_t i = 0; i < nodes.size(); ++i)
            if (can_parent(i)) work.push_back(i);
        std::sort(work.begin(), work.end(), [&](std::size_t a, std::size_t b) {
            return nodes[a].level < nodes[b].level;
        });
        while (count < cfg.num_nodes && !work.empty()) {
            const std::size_t idx = work.back();
            if (!can_parent(idx)) {
                work.pop_back();
                continue;
            }
            const std::size_t child_idx = add_child(idx);
            // A fresh leaf that can still host children becomes the new deepest
            // target, so the top-up keeps extending downward before widening.
            if (can_parent(child_idx)) work.push_back(child_idx);
        }
    }

    // Euler-tour timing: pre-order enter tick, post-order exit tick. Parent
    // intervals strictly contain all descendants; siblings stay disjoint.
    std::uint64_t tick = 0;
    struct Frame {
        std::size_t idx;
        std::size_t next_child;  // index into children not yet entered
        bool entered;
    };
    std::vector<Frame> tour;
    tour.push_back({0, 0, false});
    while (!tour.empty()) {
        Frame& f = tour.back();
        GeneratedCall& node = nodes[f.idx];
        if (!f.entered) {
            node.ts = cfg.base_ts + tick * cfg.time_unit;
            ++tick;
            f.entered = true;
        }
        if (f.next_child < node.children.size()) {
            const std::uint64_t child_id = node.children[f.next_child++];
            tour.push_back({static_cast<std::size_t>(child_id - 1), 0, false});
            continue;
        }
        const std::uint64_t exit_tick = tick++;
        node.dur = (cfg.base_ts + exit_tick * cfg.time_unit) - node.ts;
        tour.pop_back();
    }

    return nodes;
}

// ---------------------------------------------------------------------------
// Writers
// ---------------------------------------------------------------------------

// Plain (uncompressed) .pfw sink with the TraceWriter-compatible write()
// surface, so emit_event works against either sink.
class PlainTraceWriter {
   public:
    explicit PlainTraceWriter(const std::string& path)
        : ofs_(path, std::ios::binary) {}
    bool good() const { return ofs_.good(); }
    void write(const std::string& s) {
        ofs_.write(s.data(), static_cast<std::streamsize>(s.size()));
    }
    void close() { ofs_.close(); }

   private:
    std::ofstream ofs_;
};

template <class Writer>
inline void write_call_tree_events(Writer& w,
                                   const std::vector<GeneratedCall>& nodes,
                                   const CallTreeGenConfig& cfg) {
    // The call-tree builder keys each process graph on pid + args.tid +
    // args.node_id (the top-level tid is not used for grouping), so emit tid
    // into args to make the generated tree addressable by cfg.tid.
    const std::string tid_arg = "\"tid\":" + std::to_string(cfg.tid);
    w.write("[\n");
    for (const auto& node : nodes) {
        EventArgs a;
        a.id = node.id;
        a.pid = cfg.pid;
        a.tid = cfg.tid;
        a.name = node.name;
        a.cat = node.cat;
        a.ts = node.ts;
        a.dur = node.dur;
        a.level = node.level;
        a.hhash = make_hash(node.name);
        a.extra = tid_arg;
        emit_event(w, a);
    }
    w.write("]\n");
}

// Generate a call tree per cfg and write it to `path`. When `gzip` is true the
// output is gzip-compressed (.pfw.gz); otherwise it is plain text (.pfw).
// Returns true on success; false on an invalid config or a write failure.
inline bool generate_call_tree_trace(const std::string& path,
                                     const CallTreeGenConfig& cfg,
                                     bool gzip) {
    const auto nodes = generate_call_tree(cfg);
    if (nodes.empty()) return false;

    if (gzip) {
        TraceWriter w(path);
        write_call_tree_events(w, nodes, cfg);
        w.close();
    } else {
        PlainTraceWriter w(path);
        if (!w.good()) return false;
        write_call_tree_events(w, nodes, cfg);
        w.close();
    }
    return true;
}

}  // namespace dftracer::utils::utilities::trace_gen

#endif  // DFTRACER_UTILS_UTILITIES_TRACE_GEN_CALL_TREE_GENERATOR_H
