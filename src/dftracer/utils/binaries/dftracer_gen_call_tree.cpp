#include <dftracer/utils/core/common/filesystem.h>
#include <dftracer/utils/utilities/trace_gen/call_tree_generator.h>
#include <dftracer/utils/utilities/trace_gen/call_tree_mutator.h>

#include <cstdint>
#include <cstdio>
#include <string>

#include "common_cli.h"

using namespace dftracer::utils;
using dftracer::utils::utilities::trace_gen::call_tree_capacity_at_least;
using dftracer::utils::utilities::trace_gen::CallTreeGenConfig;
using dftracer::utils::utilities::trace_gen::generate_call_tree_trace;
using dftracer::utils::utilities::trace_gen::mutate_call_tree_trace;
using dftracer::utils::utilities::trace_gen::MutateConfig;
using dftracer::utils::utilities::trace_gen::MutateResult;

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------
struct GenCallTreeArgParse : cli::ArgParse {
    std::string output;
    std::size_t num_traces = 100;
    int depth = 4;
    int width = 3;
    int child_chance = 50;
    bool gzip = false;
    std::uint64_t seed = 0;
    std::uint32_t pid = 1000;
    std::uint32_t tid = 1000;

    // Mutate mode (active when --input is set): rename num_changes evenly
    // spaced nodes of an existing trace instead of generating a new one.
    std::string input;
    std::size_t num_changes = 1;
    std::string name_prefix = "mutated";
    int change_depth = -1;
    std::size_t num_removals = 0;
    bool exclude_root = false;

    explicit GenCallTreeArgParse(argparse::ArgumentParser& p) : ArgParse(p) {}

   protected:
    void register_args() override {
        parser()
            .add_argument("-o", "--output")
            .help("Output trace file path (.pfw, or .pfw.gz with -g)")
            .required();
        parser()
            .add_argument("-n", "--num-traces")
            .help("Total number of nodes (trace events) in the call tree")
            .scan<'u', std::size_t>()
            .default_value(static_cast<std::size_t>(100));
        parser()
            .add_argument("-d", "--depth")
            .help("Maximum depth of the tree (root is at level 0)")
            .scan<'d', int>()
            .default_value(4);
        parser()
            .add_argument("-w", "--width")
            .help("Maximum number of children per node")
            .scan<'d', int>()
            .default_value(3);
        parser()
            .add_argument("-c", "--child-chance")
            .help(
                "0-100: chance that a node gets more than one child (rolled per "
                "extra child slot, capped at --width)")
            .scan<'d', int>()
            .default_value(50);
        parser()
            .add_argument("-g", "--gzip")
            .help("Compress the output as gzip (.pfw.gz)")
            .flag();
        parser()
            .add_argument("--seed")
            .help("Random seed for reproducible trees (0 = random)")
            .scan<'d', std::uint64_t>()
            .default_value(static_cast<std::uint64_t>(0));
        parser()
            .add_argument("--pid")
            .help("Process id the tree is emitted under")
            .scan<'u', std::uint32_t>()
            .default_value(static_cast<std::uint32_t>(1000));
        parser()
            .add_argument("--tid")
            .help("Thread id the tree is emitted under")
            .scan<'u', std::uint32_t>()
            .default_value(static_cast<std::uint32_t>(1000));

        // Mutate mode.
        parser()
            .add_argument("-i", "--input")
            .help(
                "Mutate mode: read this existing trace (.pfw/.pfw.gz), rename "
                "independent nodes, and write to --output instead of "
                "generating a new tree")
            .default_value(std::string(""));
        parser()
            .add_argument("-m", "--num-changes")
            .help(
                "Mutate mode: number of nodes to rename, spread evenly (0 to "
                "rename nothing and only remove with -r)")
            .scan<'u', std::size_t>()
            .default_value(static_cast<std::size_t>(1));
        parser()
            .add_argument("--change-depth")
            .help(
                "Mutate mode: restrict renames to nodes at this call-tree "
                "depth (level); -1 (default) spreads them across all depths")
            .scan<'d', int>()
            .default_value(-1);
        parser()
            .add_argument("-r", "--remove")
            .help(
                "Mutate mode: number of whole subtrees to remove, spread "
                "across depths (never the root)")
            .scan<'u', std::size_t>()
            .default_value(static_cast<std::size_t>(0));
        parser()
            .add_argument("--exclude-root")
            .help(
                "Mutate mode: spread renames across every depth except the "
                "root level (depth 0); use with --num-changes and no "
                "--change-depth")
            .flag();
        parser()
            .add_argument("--name-prefix")
            .help(
                "Mutate mode: base name for changed nodes; the 1-based index "
                "is appended (e.g. mutated1, mutated2)")
            .default_value(std::string("mutated"));
    }

    void post_parse() override {
        output = parser().get<std::string>("--output");
        num_traces = parser().get<std::size_t>("--num-traces");
        depth = parser().get<int>("--depth");
        width = parser().get<int>("--width");
        child_chance = parser().get<int>("--child-chance");
        gzip = parser().get<bool>("--gzip");
        seed = parser().get<std::uint64_t>("--seed");
        pid = parser().get<std::uint32_t>("--pid");
        tid = parser().get<std::uint32_t>("--tid");
        input = parser().get<std::string>("--input");
        num_changes = parser().get<std::size_t>("--num-changes");
        change_depth = parser().get<int>("--change-depth");
        num_removals = parser().get<std::size_t>("--remove");
        exclude_root = parser().get<bool>("--exclude-root");
        name_prefix = parser().get<std::string>("--name-prefix");
    }

    bool validate() override {
        // Mutate mode: only the mutate-specific constraints apply.
        if (!input.empty()) {
            if (num_changes == 0 && num_removals == 0) {
                DFTRACER_UTILS_LOG_ERROR(
                    "%s", "nothing to do: set --num-changes and/or --remove");
                return false;
            }
            if (change_depth < -1) {
                DFTRACER_UTILS_LOG_ERROR("%s", "--change-depth must be >= -1");
                return false;
            }
            if (!fs::exists(input)) {
                DFTRACER_UTILS_LOG_ERROR("input file does not exist: %s",
                                         input.c_str());
                return false;
            }
            return true;
        }
        if (num_traces < 1) {
            DFTRACER_UTILS_LOG_ERROR("%s", "--num-traces must be >= 1");
            return false;
        }
        if (depth < 0) {
            DFTRACER_UTILS_LOG_ERROR("%s", "--depth must be >= 0");
            return false;
        }
        if (width < 1) {
            DFTRACER_UTILS_LOG_ERROR("%s", "--width must be >= 1");
            return false;
        }
        if (child_chance < 0 || child_chance > 100) {
            DFTRACER_UTILS_LOG_ERROR("%s", "--child-chance must be in [0, 100]");
            return false;
        }
        if (!call_tree_capacity_at_least(depth, width, num_traces)) {
            DFTRACER_UTILS_LOG_ERROR(
                "%zu nodes do not fit in a tree of depth %d and width %d; "
                "increase --depth or --width",
                num_traces, depth, width);
            return false;
        }
        return true;
    }
};

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    return cli::cli_main<GenCallTreeArgParse>(
        argc, argv, "dftracer_gen_call_tree",
        "Generate a synthetic DFTracer trace whose events reconstruct into a "
        "call tree. Configurable by node count, max depth, max width, and the "
        "per-child branching chance.",
        [](GenCallTreeArgParse& cli) -> int {
            // Create the parent directory if the path has one.
            const fs::path out_path(cli.output);
            if (out_path.has_parent_path() && !out_path.parent_path().empty()) {
                fs::create_directories(out_path.parent_path());
            }

            // ---------------------------------------------------------------
            // Mutate mode: rename independent nodes of an existing trace.
            // ---------------------------------------------------------------
            if (!cli.input.empty()) {
                MutateConfig mcfg;
                mcfg.num_changes = cli.num_changes;
                mcfg.name_prefix = cli.name_prefix;
                mcfg.change_depth = cli.change_depth;
                mcfg.num_removals = cli.num_removals;
                mcfg.exclude_root = cli.exclude_root;

                std::printf("==========================================\n");
                std::printf("DFTracer Call-Tree Trace Mutator\n");
                std::printf("==========================================\n");
                std::printf("  Input:          %s\n", cli.input.c_str());
                std::printf("  Nodes to rename:%zu\n", mcfg.num_changes);
                if (mcfg.change_depth >= 0)
                    std::printf("  Rename depth:   %d\n", mcfg.change_depth);
                else
                    std::printf("  Rename depth:   all (spread)\n");
                std::printf("  Subtrees remove:%zu\n", mcfg.num_removals);
                std::printf("  Name prefix:    %s\n", mcfg.name_prefix.c_str());
                std::printf("  Format:         %s\n",
                            cli.gzip ? ".pfw.gz (gzip)" : ".pfw (plain)");
                std::printf("  Output:         %s\n", cli.output.c_str());
                std::printf("==========================================\n");

                const MutateResult r = mutate_call_tree_trace(
                    cli.input, cli.output, mcfg, cli.gzip);
                if (!r.ok) {
                    DFTRACER_UTILS_LOG_ERROR("mutation failed: %s",
                                             r.error.c_str());
                    return 1;
                }
                std::printf(
                    "Renamed %zu node(s); removed %zu subtree(s) (%zu events) "
                    "of %zu total; wrote %s\n",
                    r.changed, r.removed_subtrees, r.removed_events,
                    r.total_events, cli.output.c_str());
                return 0;
            }

            CallTreeGenConfig cfg;
            cfg.num_nodes = cli.num_traces;
            cfg.depth = cli.depth;
            cfg.width = cli.width;
            cfg.child_chance = cli.child_chance;
            cfg.seed = cli.seed;
            cfg.pid = cli.pid;
            cfg.tid = cli.tid;

            std::printf("==========================================\n");
            std::printf("DFTracer Call-Tree Trace Generator\n");
            std::printf("==========================================\n");
            std::printf("  Nodes (traces): %zu\n", cfg.num_nodes);
            std::printf("  Max depth:      %d\n", cfg.depth);
            std::printf("  Max width:      %d\n", cfg.width);
            std::printf("  Child chance:   %d%%\n", cfg.child_chance);
            std::printf("  pid/tid:        %u/%u\n", cfg.pid, cfg.tid);
            std::printf("  Format:         %s\n",
                        cli.gzip ? ".pfw.gz (gzip)" : ".pfw (plain)");
            std::printf("  Output:         %s\n", cli.output.c_str());
            std::printf("==========================================\n");

            if (!generate_call_tree_trace(cli.output, cfg, cli.gzip)) {
                DFTRACER_UTILS_LOG_ERROR("failed to generate trace to %s",
                                         cli.output.c_str());
                return 1;
            }

            std::printf("Wrote %zu-node call tree to %s\n", cfg.num_nodes,
                        cli.output.c_str());
            return 0;
        });
}
