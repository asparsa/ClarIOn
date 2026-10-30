#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <dftracer/utils/call_tree/internal/call_tree.h>
#include <dftracer/utils/call_tree/internal/node.h>
#include <dftracer/utils/call_tree/internal/process_call_tree.h>
#include <dftracer/utils/call_tree/internal/process_key.h>
#include <dftracer/utils/call_tree/internal/trace_reader.h>
#include <dftracer/utils/core/common/filesystem.h>
#include <dftracer/utils/utilities/trace_gen/call_tree_generator.h>
#include <dftracer/utils/utilities/trace_gen/call_tree_mutator.h>
#include <doctest/doctest.h>
#include <testing_utilities.h>

#include <cstdint>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace dftracer::utils::utilities::trace_gen;
using namespace dftracer::utils::call_tree::internal;
using dft_utils_test::TestEnvironment;

namespace {

// Read a generated trace back through the real CallTree builder and return the
// process graph for cfg.pid/cfg.tid (hierarchy built).
ProcessCallTree* build_from_file(const std::string& path,
                                 const CallTreeGenConfig& cfg, CallTree& tree) {
    tree.initialize();
    read_trace_file(path, tree, nullptr);
    tree.build_hierarchy();
    return tree.get(cfg.pid, cfg.tid);
}

// Count nodes reachable from the roots, and the maximum depth and fan-out, by
// walking the reconstructed hierarchy.
struct TreeStats {
    std::size_t node_count = 0;
    int max_depth = 0;
    std::size_t max_children = 0;
};

TreeStats walk(const ProcessCallTree& g) {
    TreeStats s;
    // DFS from each root.
    std::vector<std::pair<std::uint64_t, int>> stack;
    for (auto root : g.root_calls) stack.push_back({root, 0});
    while (!stack.empty()) {
        auto [id, depth] = stack.back();
        stack.pop_back();
        auto it = g.calls.find(id);
        if (it == g.calls.end()) continue;
        ++s.node_count;
        s.max_depth = std::max(s.max_depth, depth);
        const auto& children = it->second->get_children();
        s.max_children = std::max(s.max_children, children.size());
        for (auto c : children) stack.push_back({c, depth + 1});
    }
    return s;
}

}  // namespace

TEST_SUITE("trace_gen::call_tree_generator") {
    TEST_CASE("generates exactly num_nodes nodes") {
        for (std::size_t n : {1u, 2u, 7u, 50u, 123u}) {
            CallTreeGenConfig cfg;
            cfg.num_nodes = n;
            cfg.depth = 8;
            cfg.width = 4;
            cfg.child_chance = 40;
            cfg.seed = 12345;
            const auto nodes = generate_call_tree(cfg);
            CHECK(nodes.size() == n);
        }
    }

    TEST_CASE("respects max depth and max width") {
        CallTreeGenConfig cfg;
        cfg.num_nodes = 200;
        cfg.depth = 5;
        cfg.width = 3;
        cfg.child_chance = 70;
        cfg.seed = 7;
        const auto nodes = generate_call_tree(cfg);
        REQUIRE(nodes.size() == 200);
        for (const auto& node : nodes) {
            CHECK(node.level >= 0);
            CHECK(node.level <= cfg.depth);
            CHECK(static_cast<int>(node.children.size()) <= cfg.width);
        }
    }

    TEST_CASE("child intervals are strictly nested in the parent") {
        CallTreeGenConfig cfg;
        cfg.num_nodes = 100;
        cfg.depth = 6;
        cfg.width = 4;
        cfg.child_chance = 50;
        cfg.seed = 99;
        const auto nodes = generate_call_tree(cfg);
        REQUIRE(nodes.size() == 100);
        std::unordered_map<std::uint64_t, const GeneratedCall*> by_id;
        for (const auto& n : nodes) by_id[n.id] = &n;
        for (const auto& n : nodes) {
            if (n.parent_id == 0) continue;
            const auto* parent = by_id.at(n.parent_id);
            CHECK(parent->ts <= n.ts);
            CHECK(n.ts + n.dur <= parent->ts + parent->dur);
            CHECK(n.level == parent->level + 1);
        }
    }

    TEST_CASE("chance 0 yields a chain, chance 100 a complete tree") {
        CallTreeGenConfig base;
        base.depth = 6;
        base.width = 3;
        base.seed = 3;

        SUBCASE("chain") {
            CallTreeGenConfig cfg = base;
            cfg.num_nodes = 5;  // fits within depth as a single chain
            cfg.child_chance = 0;
            const auto nodes = generate_call_tree(cfg);
            REQUIRE(nodes.size() == 5);
            for (const auto& n : nodes) CHECK(n.children.size() <= 1u);
        }
        SUBCASE("complete") {
            CallTreeGenConfig cfg = base;
            cfg.num_nodes = 13;  // 1 + 3 + 9 == complete depth-2 ternary tree
            cfg.depth = 2;
            cfg.child_chance = 100;
            const auto nodes = generate_call_tree(cfg);
            REQUIRE(nodes.size() == 13);
            for (const auto& n : nodes)
                if (n.level < cfg.depth) CHECK(n.children.size() == 3u);
        }
    }

    TEST_CASE("infeasible configurations are rejected") {
        CallTreeGenConfig cfg;
        cfg.num_nodes = 100;  // capacity of depth 2, width 3 is only 13
        cfg.depth = 2;
        cfg.width = 3;
        CHECK(generate_call_tree(cfg).empty());
        CHECK_FALSE(call_tree_capacity_at_least(2, 3, 100));
        CHECK(call_tree_capacity_at_least(2, 3, 13));
    }

    TEST_CASE("round-trips through the CallTree builder (.pfw)") {
        TestEnvironment env(0);
        CallTreeGenConfig cfg;
        cfg.num_nodes = 60;
        cfg.depth = 5;
        cfg.width = 3;
        cfg.child_chance = 50;
        cfg.seed = 2024;

        const std::string path = env.get_dir() + "/call_tree.pfw";
        REQUIRE(generate_call_tree_trace(path, cfg, /*gzip=*/false));

        CallTree tree;
        ProcessCallTree* g = build_from_file(path, cfg, tree);
        REQUIRE(g != nullptr);
        CHECK(g->root_calls.size() == 1);  // one connected tree
        const TreeStats s = walk(*g);
        CHECK(s.node_count == cfg.num_nodes);
        CHECK(s.max_depth <= cfg.depth);
        CHECK(static_cast<int>(s.max_children) <= cfg.width);
    }

    TEST_CASE("round-trips through the CallTree builder (.pfw.gz)") {
        TestEnvironment env(0);
        CallTreeGenConfig cfg;
        cfg.num_nodes = 80;
        cfg.depth = 6;
        cfg.width = 4;
        cfg.child_chance = 35;
        cfg.seed = 555;

        const std::string path = env.get_dir() + "/call_tree.pfw.gz";
        REQUIRE(generate_call_tree_trace(path, cfg, /*gzip=*/true));

        CallTree tree;
        ProcessCallTree* g = build_from_file(path, cfg, tree);
        REQUIRE(g != nullptr);
        CHECK(g->root_calls.size() == 1);
        const TreeStats s = walk(*g);
        CHECK(s.node_count == cfg.num_nodes);
        CHECK(s.max_depth <= cfg.depth);
        CHECK(static_cast<int>(s.max_children) <= cfg.width);
    }

    // --- mutate_call_tree_trace -------------------------------------------

    // Read the top-level "name" of every complete event, in file order.
    static std::vector<std::string> read_event_names(const std::string& path) {
        std::vector<std::string> names;
        std::ifstream f(path);
        std::string line;
        while (std::getline(f, line)) {
            if (line.find("\"ph\":\"X\"") == std::string::npos) continue;
            const std::string key = "\"name\":\"";
            const std::size_t p = line.find(key);
            if (p == std::string::npos) continue;
            const std::size_t s = p + key.size();
            const std::size_t e = line.find('"', s);
            names.push_back(line.substr(s, e - s));
        }
        return names;
    }

    TEST_CASE("mutate renames exactly d evenly spaced nodes") {
        TestEnvironment env(0);
        CallTreeGenConfig gen;
        gen.num_nodes = 80;
        gen.depth = 5;
        gen.width = 3;
        gen.child_chance = 55;
        gen.seed = 321;
        const std::string in = env.get_dir() + "/base.pfw";
        REQUIRE(generate_call_tree_trace(in, gen, /*gzip=*/false));

        const std::size_t d = 6;
        MutateConfig mcfg;
        mcfg.num_changes = d;
        const std::string out = env.get_dir() + "/mutated.pfw";
        const MutateResult r = mutate_call_tree_trace(in, out, mcfg, false);
        REQUIRE(r.ok);
        CHECK(r.changed == d);
        CHECK(r.total_events == gen.num_nodes);
        CHECK(r.step == gen.num_nodes / d);

        const std::vector<std::string> names = read_event_names(out);
        REQUIRE(names.size() == gen.num_nodes);

        // Exactly the midpoint of each evenly spaced bucket is renamed
        // mutated<i>: events at step/2, step/2 + step, step/2 + 2*step, ...
        // The offset keeps event 0 (the call-tree root) untouched.
        const std::size_t off = r.step / 2;
        std::size_t renamed = 0;
        for (std::size_t i = 0; i < names.size(); ++i) {
            const bool is_marked =
                names[i].rfind(mcfg.name_prefix, 0) == 0 &&
                names[i] != mcfg.name_prefix;  // "mutated" + digits
            const bool selected = i >= off && (i - off) % r.step == 0 &&
                                  (i - off) / r.step < d;
            if (selected) {
                CHECK(names[i] == mcfg.name_prefix +
                                      std::to_string((i - off) / r.step + 1));
                ++renamed;
            } else {
                CHECK_FALSE(is_marked);
            }
        }
        CHECK(renamed == d);
        CHECK(names[0] != mcfg.name_prefix + "1");  // root is never renamed
    }

    TEST_CASE("mutate leaves non-selected events byte-identical") {
        TestEnvironment env(0);
        CallTreeGenConfig gen;
        gen.num_nodes = 40;
        gen.depth = 4;
        gen.width = 3;
        gen.child_chance = 50;
        gen.seed = 9;
        const std::string in = env.get_dir() + "/base2.pfw";
        REQUIRE(generate_call_tree_trace(in, gen, /*gzip=*/false));

        MutateConfig mcfg;
        mcfg.num_changes = 3;
        const std::string out = env.get_dir() + "/mutated2.pfw";
        REQUIRE(mutate_call_tree_trace(in, out, mcfg, false).ok);

        // Exactly 3 lines differ, and every difference carries a mutated name.
        std::ifstream fin(in), fout(out);
        std::string a, b;
        std::size_t diffs = 0;
        while (std::getline(fin, a) && std::getline(fout, b)) {
            if (a != b) {
                ++diffs;
                CHECK(b.find("\"name\":\"" + mcfg.name_prefix) !=
                      std::string::npos);
            }
        }
        CHECK(diffs == 3);
    }

    TEST_CASE("mutate rejects requests larger than the event count") {
        TestEnvironment env(0);
        CallTreeGenConfig gen;
        gen.num_nodes = 7;
        gen.depth = 10;
        gen.width = 3;
        gen.child_chance = 0;
        gen.seed = 2;
        const std::string in = env.get_dir() + "/small.pfw";
        REQUIRE(generate_call_tree_trace(in, gen, /*gzip=*/false));

        MutateConfig mcfg;
        mcfg.num_changes = 8;  // more than the 7 events
        const std::string out = env.get_dir() + "/small_mut.pfw";
        const MutateResult r = mutate_call_tree_trace(in, out, mcfg, false);
        CHECK_FALSE(r.ok);
        CHECK(r.total_events == 7);
    }
}
