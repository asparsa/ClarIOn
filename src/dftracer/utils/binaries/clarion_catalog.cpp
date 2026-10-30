// clarion_catalog: manage the function catalog used to group API-level
// functions into categories (e.g. HDF5: H5Dwrite, H5Fopen; syscall: open,
// read, write). The catalog is a small YAML file, created on first use, that
// downstream tools (e.g. clarion_calltree) can read to know which functions
// belong to which category.
//
// Commands:
//   init             create the catalog file if it doesn't exist yet
//                     (--force to overwrite an existing one)
//   list             print all categories and their functions
//   add-category     add one or more empty categories (-c/--category, may
//                     repeat)
//   remove-category  remove one or more categories and their functions
//                     (-c/--category, may repeat)
//   add-function     add one or more functions to one or more categories,
//                     creating any that don't exist yet (-c/--category,
//                     -f/--function, either may repeat -- every category
//                     gets every function)
//   remove-function  remove one or more functions from one or more
//                     categories (-c/--category, -f/--function, either may
//                     repeat)
//   knowledge        build a Catalog (Sec. IV-C) from a folder of subtree
//                     dumps (one call tree per file, e.g. the *.pfw.gz produced
//                     by clarion_calltree --catalog). Each immediate
//                     subdirectory of -i/--input-dir is one configuration and
//                     its dumps are that configuration's runs (a flat input dir
//                     is a single "default" configuration). Dumps are grouped
//                     by root function name (the API call); for each API call
//                     the runs of all configurations are merged top-down into a
//                     knowledge tree (matched by function name; a child only
//                     some runs reach is tagged and appended), branch points
//                     are classified configuration-driven / noise-driven /
//                     mixed, and each node carries a per-configuration log-scale
//                     histogram of its exclusive durations. Writes
//                     <knowledge-output>/knowledge_tree.pfw.gz (tagged nodes
//                     carry a "tag" id and branch points a "branch" class in
//                     args), divergences_table.csv (per tag: runs reaching it,
//                     the configurations that took the path, bytes R/W), and
//                     configuration_table.csv (per configuration: run count,
//                     covered API calls, resolved parameter values).
//                     -i/--input-dir is required; -f/--function restricts to
//                     one function's dumps by filename prefix. --params <yaml>
//                     supplies the resolved parameter values per configuration
//                     (filling the configuration table and enabling the
//                     mitigator). --mitigate <api/fn/...> then runs the
//                     fight-or-flight mitigator (Sec. IV-E) for that anomalous
//                     node, printing which parameters to tune in place (fight)
//                     or which configuration to switch to (flight);
//                     --mitigate-config names the configuration the anomaly was
//                     seen in.

#include <dftracer/utils/core/common/config.h>
#include <dftracer/utils/core/common/filesystem.h>
#include <dftracer/utils/core/common/logging.h>
#include <dftracer/utils/core/coro/task.h>
#include <dftracer/utils/core/tasks/coro_scope.h>
#include <dftracer/utils/utilities/catalog/knowledge_tree.h>
#include <dftracer/utils/utilities/catalog/mitigator.h>
#include <dftracer/utils/utilities/composites/dft/event.h>
#include <dftracer/utils/utilities/reader/trace_reader.h>

#include <yaml-cpp/yaml.h>
#include <zlib.h>

#include <sys/resource.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <map>
#include <mutex>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "common_cli.h"

using namespace dftracer::utils;
using namespace dftracer::utils::utilities;

namespace {

using Catalog = std::map<std::string, std::vector<std::string>>;

bool write_file(const std::string& path, const std::string& bytes) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    const bool ok =
        std::fwrite(bytes.data(), 1, bytes.size(), f) == bytes.size();
    std::fclose(f);
    return ok;
}

// A freshly-created catalog starts with no categories; use add-category /
// add-function to populate it.
Catalog default_catalog() { return Catalog{}; }

bool load_catalog(const std::string& path, Catalog& out) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const std::exception& err) {
        DFTRACER_UTILS_LOG_ERROR("failed to parse %s: %s", path.c_str(),
                                 err.what());
        return false;
    }
    out.clear();
    if (!root["cat"]) return true;
    for (const auto& entry : root["cat"]) {
        const std::string name = entry.first.as<std::string>();
        std::vector<std::string> fns;
        if (entry.second) {
            for (const auto& fn : entry.second) fns.push_back(fn.as<std::string>());
        }
        std::sort(fns.begin(), fns.end());
        out[name] = std::move(fns);
    }
    return true;
}

bool save_catalog(const std::string& path, const Catalog& catalog) {
    YAML::Node categories(YAML::NodeType::Map);
    for (const auto& [name, fns] : catalog) {
        YAML::Node seq(YAML::NodeType::Sequence);
        for (const auto& fn : fns) seq.push_back(fn);
        categories[name] = seq;
    }
    YAML::Node root;
    root["cat"] = categories;

    YAML::Emitter emit;
    emit.SetIndent(2);
    emit.SetMapFormat(YAML::Block);
    emit.SetSeqFormat(YAML::Block);
    emit << root;

    std::string text(emit.c_str());
    text += "\n";
    return write_file(path, text);
}

void print_catalog(const Catalog& catalog) {
    if (catalog.empty()) {
        std::printf("(empty catalog)\n");
        return;
    }
    for (const auto& [name, fns] : catalog) {
        std::printf("%s:\n", name.c_str());
        if (fns.empty()) {
            std::printf("  (no functions)\n");
            continue;
        }
        for (const auto& fn : fns) std::printf("  - %s\n", fn.c_str());
    }
}

class ClarionCatalogArgParse : public cli::ArgParse {
   public:
    cli::PipelineArgs pipeline;

    std::string command;
    std::string catalog_path;
    std::vector<std::string> categories;
    std::vector<std::string> functions;
    std::string input_dir;
    std::string knowledge_output = "knowledge";
    std::string params_file;
    std::string mitigate_spec;
    std::string mitigate_config;
    bool force = false;

    explicit ClarionCatalogArgParse(argparse::ArgumentParser& p) : ArgParse(p) {
        schema(pipeline);
    }

   protected:
    void register_args() override {
        parser()
            .add_argument("command")
            .help(
                "Action to perform: init, list, add-category, "
                "remove-category, add-function, remove-function, knowledge")
            .choices("init", "list", "add-category", "remove-category",
                    "add-function", "remove-function", "knowledge");
        parser()
            .add_argument("-o", "--output")
            .help("Path to the catalog YAML file")
            .default_value<std::string>("clarion_catalog.yaml");
        parser()
            .add_argument("-c", "--category")
            .help("One or more category names (e.g. HDF5)")
            .nargs(argparse::nargs_pattern::at_least_one)
            .default_value<std::vector<std::string>>({});
        parser()
            .add_argument("-f", "--function")
            .help("One or more function names within --category (e.g. H5Dwrite)")
            .nargs(argparse::nargs_pattern::at_least_one)
            .default_value<std::vector<std::string>>({});
        parser()
            .add_argument("--force")
            .help("With init, overwrite an existing catalog file")
            .flag();
        parser()
            .add_argument("-i", "--input-dir")
            .help(
                "With knowledge, the folder of catalog subtree dumps (.pfw / "
                ".pfw.gz) to merge")
            .default_value<std::string>("");
        parser()
            .add_argument("--knowledge-output")
            .help("With knowledge, the output directory for the knowledge tree "
                  "and table")
            .default_value<std::string>("knowledge");
        parser()
            .add_argument("--params")
            .help("With knowledge, a YAML file of resolved parameter values per "
                  "configuration (params: {<config>: {<param>: <value>}}). "
                  "Fills the configuration table's params column and feeds the "
                  "fight-or-flight mitigator")
            .default_value<std::string>("");
        parser()
            .add_argument("--mitigate")
            .help("With knowledge, after building the catalog, run the "
                  "fight-or-flight mitigator (Sec. IV-E) for the anomalous node "
                  "named by a slash-separated function path from the API-call "
                  "root, e.g. 'H5Dread/readv/contig_readvv'")
            .default_value<std::string>("");
        parser()
            .add_argument("--mitigate-config")
            .help("With --mitigate, the configuration the anomaly was observed "
                  "in (defaults to the first configuration)")
            .default_value<std::string>("");
    }

    void post_parse() override {
        command = parser().get<std::string>("command");
        catalog_path = parser().get<std::string>("--output");
        categories = parser().get<std::vector<std::string>>("--category");
        functions = parser().get<std::vector<std::string>>("--function");
        input_dir = parser().get<std::string>("--input-dir");
        knowledge_output = parser().get<std::string>("--knowledge-output");
        params_file = parser().get<std::string>("--params");
        mitigate_spec = parser().get<std::string>("--mitigate");
        mitigate_config = parser().get<std::string>("--mitigate-config");
        force = parser().get<bool>("--force");
    }

    bool validate() override {
        const bool needs_category =
            command == "add-category" || command == "remove-category" ||
            command == "add-function" || command == "remove-function";
        const bool needs_function =
            command == "add-function" || command == "remove-function";
        if (needs_category && categories.empty()) {
            DFTRACER_UTILS_LOG_ERROR("--category is required for '%s'",
                                     command.c_str());
            return false;
        }
        if (needs_function && functions.empty()) {
            DFTRACER_UTILS_LOG_ERROR("--function is required for '%s'",
                                     command.c_str());
            return false;
        }
        if (command == "knowledge" && input_dir.empty()) {
            DFTRACER_UTILS_LOG_ERROR("%s",
                                     "-i/--input-dir is required for 'knowledge'");
            return false;
        }
        return true;
    }
};

// ── knowledge command ───────────────────────────────────────────────────────
//
// Builds a Catalog (Sec. IV-C): one knowledge tree per I/O API call plus a
// divergences table and a configuration table. Each immediate subdirectory of
// --input-dir is one configuration; the subtree dumps inside it are that
// configuration's runs (a flat --input-dir with dumps directly in it counts as
// a single "default" configuration). Dumps are grouped by their root function
// name (the API call); for each API call the runs of every configuration are
// merged top-down into a knowledge tree, tagging nodes that only some runs
// reach, classifying branch points as configuration-driven / noise-driven /
// mixed, and recording per-tag rows (runs, configurations, bytes) and per-
// configuration rows. Writes <knowledge-output>/knowledge_tree.pfw.gz,
// divergences_table.csv, and configuration_table.csv.

using catalog::BranchClass;
using catalog::ConfigParams;
using catalog::ConfigRow;
using catalog::DivergenceRow;
using catalog::FightRec;
using catalog::FlightRec;
using catalog::KNode;
using catalog::MitigationResult;

// Resolved parameter values of one configuration, as stored in ConfigRow.
using ParamMapVec = std::vector<std::pair<std::string, std::string>>;

// Load resolved per-configuration parameter values from a YAML file of the form
//   params:
//     <config>:
//       <param>: <value>
// Returns false only on a parse error; a missing/empty file yields no params.
bool load_params(const std::string& path,
                 std::map<std::string, ParamMapVec>& out) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const std::exception& err) {
        DFTRACER_UTILS_LOG_ERROR("failed to parse %s: %s", path.c_str(),
                                 err.what());
        return false;
    }
    const YAML::Node node = root["params"] ? root["params"] : root;
    if (!node || !node.IsMap()) return true;
    for (const auto& cfg : node) {
        const std::string name = cfg.first.as<std::string>();
        ParamMapVec kv;
        if (cfg.second && cfg.second.IsMap())
            for (const auto& p : cfg.second)
                kv.emplace_back(p.first.as<std::string>(),
                                p.second.as<std::string>());
        std::sort(kv.begin(), kv.end());
        out[name] = std::move(kv);
    }
    return true;
}

// Split a slash-separated function path ("A/b/c") into its components.
std::vector<std::string> split_path_spec(const std::string& spec) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= spec.size()) {
        const std::size_t slash = spec.find('/', start);
        const std::size_t end = slash == std::string::npos ? spec.size() : slash;
        if (end > start) out.push_back(spec.substr(start, end - start));
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    return out;
}

// Print a fight-or-flight mitigation result (Sec. IV-E) for one anomalous node.
void print_mitigation(const std::string& spec, const std::string& anomaly_cfg,
                      const MitigationResult& r) {
    std::printf("\nMitigation for %s (anomaly config: %s):\n", spec.c_str(),
                anomaly_cfg.c_str());
    if (!r.found_node) {
        std::printf("  node not found in the knowledge tree\n");
        return;
    }

    if (r.fight.empty()) {
        std::printf("  Fight: no safe in-place parameter changes v's cost\n");
    } else {
        std::printf("  Fight (tune the node in place):\n");
        for (const FightRec& f : r.fight)
            std::printf("    - %s  (via %s)%s\n", f.param.c_str(),
                        catalog::impact_type_name(f.impact),
                        f.path_side_effect ? "  [path side effect]" : "");
    }

    if (r.flight.empty()) {
        std::printf(r.unavoidable
                        ? "  Flight: v is unavoidable (no configuration avoids "
                          "it)\n"
                        : "  Flight: no alternative configuration found\n");
    } else {
        std::printf(
            "  Flight (switch configuration at branch point '%s' depth %d, "
            "%s):\n",
            r.flight.front().branch_point.c_str(),
            r.flight.front().branch_depth,
            catalog::branch_class_name(r.flight.front().branch_class));
        for (const FlightRec& f : r.flight) {
            std::printf("    - %s", f.config.c_str());
            if (!f.diff_params.empty()) {
                std::printf("  (change: ");
                for (std::size_t i = 0; i < f.diff_params.size(); ++i) {
                    const bool coupled =
                        std::find(f.path_coupled_params.begin(),
                                  f.path_coupled_params.end(),
                                  f.diff_params[i].first) !=
                        f.path_coupled_params.end();
                    std::printf("%s%s=%s%s", i ? ", " : "",
                                f.diff_params[i].first.c_str(),
                                f.diff_params[i].second.c_str(),
                                coupled ? "*" : "");
                }
                std::printf(")");
            }
            std::printf("\n");
        }
        std::printf("    (* marks the parameter that explains the branch)\n");
    }

    if (r.outside_config_space)
        std::printf(
            "  => anomaly lies outside the captured configuration space\n");
}

bool write_gzip_file(const std::string& path, const std::string& bytes) {
    gzFile f = gzopen(path.c_str(), "wb");
    if (!f) return false;
    std::size_t written = 0;
    bool ok = true;
    while (written < bytes.size()) {
        const unsigned chunk = static_cast<unsigned>(
            std::min<std::size_t>(bytes.size() - written, std::size_t{1} << 20));
        const int rc = gzwrite(f, bytes.data() + written, chunk);
        if (rc <= 0) {
            ok = false;
            break;
        }
        written += static_cast<std::size_t>(rc);
    }
    if (gzclose(f) != Z_OK) ok = false;
    return ok && written == bytes.size();
}

// Quote a CSV field if it contains a comma, quote, or newline.
std::string csv_field(const std::string& s) {
    if (s.find_first_of(",\"\n\r") == std::string::npos) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += '"';
        out += c;
    }
    out += '"';
    return out;
}

// Reconstruct one call tree from a subtree dump. The dump lists nodes in
// pre-order DFS with an explicit args["depth"] (see clarion_calltree's
// serialize_agg), so a depth stack rebuilds the tree directly; the leading
// ph:M metadata line is dropped by is_complete(). Node names have their
// ":0x<addr>" suffix stripped. Returns the root (null if the file had no
// ph:X events).
coro::CoroTask<std::unique_ptr<KNode>> reconstruct_tree(std::string path) {
    using composites::dft::DFTracerEvent;
    using reader::ReadConfig;
    using reader::TraceReaderConfig;

    TraceReaderConfig cfg;
    cfg.file_path = std::move(path);
    cfg.auto_build_index = true;
    reader::TraceReader trace_reader(std::move(cfg));

    std::unique_ptr<KNode> root;
    std::vector<KNode*> stack;  // stack[d] == current node at depth d

    auto gen = trace_reader.read_json(ReadConfig{});
    while (auto opt = co_await gen.next()) {
        DFTracerEvent ev;
        if (!DFTracerEvent::parse_ondemand(*opt->parser, ev)) continue;
        if (!ev.is_complete()) continue;

        int depth = 0;
        if (auto p = ev.args["depth"])
            depth = static_cast<int>(p.get<std::uint64_t>());
        long long count = 1;
        if (auto p = ev.args["count"])
            count = static_cast<long long>(p.get<std::uint64_t>());

        auto node = std::make_unique<KNode>();
        node->name = catalog::strip_addr(ev.name);
        node->cat = std::string(ev.cat);
        node->dur = static_cast<long long>(ev.dur);
        node->count = count;
        node->first_ts = ev.ts;
        KNode* raw = node.get();

        if (depth <= 0) {
            if (root) continue;  // only one root per dump; ignore extras
            root = std::move(node);
            stack.assign(1, raw);
            continue;
        }
        if (!root) continue;  // first node wasn't a root; skip malformed head
        if (static_cast<int>(stack.size()) > depth) stack.resize(depth);
        if (static_cast<int>(stack.size()) != depth) continue;  // gap; skip
        stack.back()->children.push_back(std::move(node));
        stack.push_back(raw);
    }
    co_return root;
}

// A single dump file to reconstruct, tagged with the configuration it belongs
// to (the subdirectory it was found in).
struct DumpInput {
    std::string path;
    std::string config;
};

// One representative run per unique (config, root name, structural hash), with
// how many identical runs it stands in for and the first (sorted) file that
// produced it.
struct RunVariant {
    std::unique_ptr<KNode> tree;
    long long mult = 0;
    std::string first_file;
    std::string config;
    std::string root;  // API call (root function name)
};

bool is_dump_name(const std::string& name) {
    return name.size() > 4 &&
           (name.compare(name.size() - 4, 4, ".pfw") == 0 ||
            (name.size() > 7 &&
             name.compare(name.size() - 7, 7, ".pfw.gz") == 0));
}

int run_knowledge(const ClarionCatalogArgParse& cli) {
    if (!fs::exists(cli.input_dir) || !fs::is_directory(cli.input_dir)) {
        DFTRACER_UTILS_LOG_ERROR("input dir not found: %s",
                                 cli.input_dir.c_str());
        return 1;
    }

    // Optional resolved parameter values per configuration (fills the config
    // table and feeds the mitigator). Empty when --params is not given.
    std::map<std::string, ParamMapVec> params_by_config;
    if (!cli.params_file.empty() &&
        !load_params(cli.params_file, params_by_config))
        return 1;

    // One optional function filter (filename prefix "<fn>_").
    std::string prefix;
    if (!cli.functions.empty()) prefix = cli.functions.front() + "_";

    auto collect = [&](const fs::path& dir, const std::string& config,
                       std::vector<DumpInput>& out) {
        for (const auto& ent : fs::directory_iterator(dir)) {
            if (!ent.is_regular_file()) continue;
            const std::string name = ent.path().filename().string();
            if (!is_dump_name(name)) continue;
            if (!prefix.empty() && name.compare(0, prefix.size(), prefix) != 0)
                continue;
            out.push_back(DumpInput{ent.path().string(), config});
        }
    };

    // Each immediate subdirectory of --input-dir is one configuration. With no
    // subdirectories, the input dir itself is a single "default" configuration.
    std::vector<std::string> subdirs;
    for (const auto& ent : fs::directory_iterator(cli.input_dir))
        if (ent.is_directory()) subdirs.push_back(ent.path().string());
    std::sort(subdirs.begin(), subdirs.end());

    std::vector<DumpInput> dumps;
    if (subdirs.empty()) {
        collect(cli.input_dir, "default", dumps);
    } else {
        for (const auto& sub : subdirs)
            collect(sub, fs::path(sub).filename().string(), dumps);
    }
    std::sort(dumps.begin(), dumps.end(),
              [](const DumpInput& a, const DumpInput& b) {
                  if (a.config != b.config) return a.config < b.config;
                  return a.path < b.path;
              });
    if (dumps.empty()) {
        DFTRACER_UTILS_LOG_ERROR("no subtree dumps (.pfw/.pfw.gz%s) in %s",
                                 prefix.empty() ? "" : " with the given prefix",
                                 cli.input_dir.c_str());
        return 1;
    }

    // Reconstruct every dump in parallel and dedup identical runs within the
    // same configuration (keyed by config + root name + structural hash),
    // keeping a multiplicity so collapsed runs still count toward run totals.
    std::map<std::tuple<std::string, std::string, std::size_t>, RunVariant>
        variants;
    std::mutex mtx;

    const std::size_t threads =
        std::max<std::size_t>(1, cli.pipeline.executor_threads);
    const std::vector<DumpInput>* dumps_ptr = &dumps;

    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();

    const int rc = cli::run_single_task(
        "ClarIOn Knowledge", cli.pipeline,
        [&variants, &mtx, dumps_ptr,
         threads](CoroScope& ctx) -> coro::CoroTask<int> {
            co_await ctx.scope(
                [&variants, &mtx, dumps_ptr,
                 threads](CoroScope& child) -> coro::CoroTask<void> {
                    cli::parallel_for_each(
                        child, *dumps_ptr, threads,
                        [&variants, &mtx](
                            const DumpInput& d) -> coro::CoroTask<void> {
                            auto tree = co_await reconstruct_tree(d.path);
                            if (!tree) co_return;
                            catalog::compute_hash(tree.get());
                            std::tuple<std::string, std::string, std::size_t>
                                key{d.config, tree->name, tree->hash};
                            const std::string base =
                                fs::path(d.path).filename().string();
                            std::lock_guard<std::mutex> lk(mtx);
                            auto it = variants.find(key);
                            if (it == variants.end()) {
                                variants.emplace(
                                    std::move(key),
                                    RunVariant{std::move(tree), 1, base,
                                               d.config, std::string{}});
                            } else {
                                it->second.mult++;
                                if (base < it->second.first_file)
                                    it->second.first_file = base;
                            }
                            co_return;
                        });
                    co_return;
                });
            co_return 0;
        });
    if (rc != 0) return rc;

    const auto t_read = clock::now();

    // Group deduped runs by API call (root name). Also accumulate the
    // configuration table: per configuration, its run count and covered calls.
    std::map<std::string, std::vector<RunVariant*>> by_call;
    std::map<std::string, ConfigRow> config_rows;
    for (auto& [key, v] : variants) {
        v.root = std::get<1>(key);
        by_call[v.root].push_back(&v);
        ConfigRow& cr = config_rows[v.config];
        cr.config = v.config;
        cr.num_runs += v.mult;
        cr.api_calls.insert(v.root);
        if (cr.params.empty()) {
            auto pit = params_by_config.find(v.config);
            if (pit != params_by_config.end()) cr.params = pit->second;
        }
    }

    std::vector<std::unique_ptr<KNode>> owned_roots;
    std::vector<KNode*> roots;
    std::vector<DivergenceRow> div_rows;
    int next_tag = 0;
    std::size_t merge_count = 0;  // number of runs merged into a knowledge tree

    for (auto& [call, vars] : by_call) {
        // Deterministic merge order: by configuration, then first file. The
        // first run defines the untagged baseline skeleton of this API call's
        // knowledge tree; later runs introduce tagged (divergent) nodes.
        std::sort(vars.begin(), vars.end(),
                  [](const RunVariant* a, const RunVariant* b) {
                      if (a->config != b->config) return a->config < b->config;
                      return a->first_file < b->first_file;
                  });

        auto kroot = std::make_unique<KNode>();
        kroot->name = call;
        for (std::size_t i = 0; i < vars.size(); ++i) {
            catalog::merge_run(kroot.get(), vars[i]->tree.get(),
                               vars[i]->config, /*baseline=*/i == 0,
                               vars[i]->mult, next_tag, /*depth=*/0);
            ++merge_count;
        }
        catalog::compute_hash(kroot.get());  // refresh hashes after merging
        catalog::classify_branches(kroot.get());
        catalog::collect_divergences(kroot.get(), call, div_rows);
        roots.push_back(kroot.get());
        owned_roots.push_back(std::move(kroot));
    }

    const auto t_merge = clock::now();

    // Write outputs.
    if (!fs::exists(cli.knowledge_output))
        fs::create_directories(cli.knowledge_output);
    const std::string tree_path =
        (fs::path(cli.knowledge_output) / "knowledge_tree.pfw.gz").string();
    const std::string div_path =
        (fs::path(cli.knowledge_output) / "divergences_table.csv").string();
    const std::string cfg_path =
        (fs::path(cli.knowledge_output) / "configuration_table.csv").string();

    if (!write_gzip_file(tree_path, catalog::serialize_knowledge(roots))) {
        DFTRACER_UTILS_LOG_ERROR("failed to write %s", tree_path.c_str());
        return 1;
    }

    // Divergences table: one row per tagged node.
    std::string div_csv =
        "tag_id,api_call,node,depth,branch_class,num_runs,configs,"
        "bytes_read,bytes_write\n";
    for (const DivergenceRow& r : div_rows) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%d", r.tag_id);
        div_csv += buf;
        div_csv += ',';
        div_csv += csv_field(r.api_call);
        div_csv += ',';
        div_csv += csv_field(r.node);
        div_csv += ',';
        std::snprintf(buf, sizeof(buf), "%d", r.depth);
        div_csv += buf;
        div_csv += ',';
        div_csv += catalog::branch_class_name(r.parent_branch);
        div_csv += ',';
        std::snprintf(buf, sizeof(buf), "%lld", r.num_runs);
        div_csv += buf;
        div_csv += ',';
        div_csv += csv_field(
            catalog::detail::join({r.configs.begin(), r.configs.end()}));
        div_csv += ',';
        std::snprintf(buf, sizeof(buf), "%lld", r.bytes_read);
        div_csv += buf;
        div_csv += ',';
        std::snprintf(buf, sizeof(buf), "%lld", r.bytes_write);
        div_csv += buf;
        div_csv += '\n';
    }
    if (!write_file(div_path, div_csv)) {
        DFTRACER_UTILS_LOG_ERROR("failed to write %s", div_path.c_str());
        return 1;
    }

    // Configuration table: one row per configuration. Resolved parameter
    // values are not yet emitted upstream, so the params column is left empty.
    std::string cfg_csv = "config,num_runs,api_calls,params\n";
    for (const auto& [name, cr] : config_rows) {
        char buf[64];
        cfg_csv += csv_field(cr.config);
        cfg_csv += ',';
        std::snprintf(buf, sizeof(buf), "%lld", cr.num_runs);
        cfg_csv += buf;
        cfg_csv += ',';
        cfg_csv += csv_field(
            catalog::detail::join({cr.api_calls.begin(), cr.api_calls.end()}));
        cfg_csv += ',';
        std::vector<std::string> params;
        for (const auto& [k, v] : cr.params) params.push_back(k + "=" + v);
        cfg_csv += csv_field(catalog::detail::join(params));
        cfg_csv += '\n';
    }
    if (!write_file(cfg_path, cfg_csv)) {
        DFTRACER_UTILS_LOG_ERROR("failed to write %s", cfg_path.c_str());
        return 1;
    }

    std::printf(
        "Catalog: %zu dump(s), %zu configuration(s), %zu API call(s), %zu "
        "unique run variant(s), %d tagged divergence(s)\n"
        "  tree:          %s\n  divergences:   %s\n  configurations: %s\n",
        dumps.size(), config_rows.size(), roots.size(), variants.size(),
        next_tag, tree_path.c_str(), div_path.c_str(), cfg_path.c_str());

    // ── fight-or-flight mitigation (Sec. IV-E) ───────────────────────────────
    // When --mitigate names an anomalous node, run the mitigator over the
    // in-memory knowledge tree (which carries the per-configuration counts and
    // exclusive-duration sums the impact blocks need) and print the fight and
    // flight recommendations.
    if (!cli.mitigate_spec.empty()) {
        const std::vector<std::string> path = split_path_spec(cli.mitigate_spec);
        if (path.empty()) {
            DFTRACER_UTILS_LOG_ERROR("%s", "--mitigate path is empty");
            return 1;
        }
        KNode* target = nullptr;
        for (KNode* r : roots)
            if (r->name == path.front()) {
                target = r;
                break;
            }
        if (!target) {
            DFTRACER_UTILS_LOG_ERROR("--mitigate: no API call named '%s'",
                                     path.front().c_str());
            return 1;
        }
        // Configuration list and resolved parameter values for the mitigator.
        std::vector<std::string> configs;
        ConfigParams cfg_params;
        for (const auto& [name, cr] : config_rows) {
            configs.push_back(name);
            auto& pm = cfg_params[name];
            for (const auto& [k, v] : cr.params) pm[k] = v;
        }
        std::string anomaly_cfg = cli.mitigate_config;
        if (anomaly_cfg.empty() && !configs.empty()) anomaly_cfg = configs.front();

        const MitigationResult mr = catalog::mitigate(target, path, anomaly_cfg,
                                                      configs, cfg_params);
        print_mitigation(cli.mitigate_spec, anomaly_cfg, mr);
    }

    // ── performance report ──────────────────────────────────────────────────
    using us = std::chrono::duration<double, std::micro>;
    using sec = std::chrono::duration<double>;
    const double read_s = sec(t_read - t0).count();
    const double merge_s = sec(t_merge - t_read).count();
    const double total_s = sec(clock::now() - t0).count();
    const double per_file_us =
        dumps.empty() ? 0.0 : us(t_read - t0).count() / dumps.size();
    const double per_merge_us =
        merge_count == 0 ? 0.0 : us(t_merge - t_read).count() / merge_count;

    struct rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    const double peak_mb = ru.ru_maxrss / 1024.0;  // ru_maxrss is KiB on Linux

    std::printf(
        "Performance:\n"
        "  total:                  %.3f s\n"
        "  reconstruct+dedup:      %.3f s  (%zu dumps, %.2f us/dump)\n"
        "  merge into knowledge:   %.3f s  (%zu runs, %.2f us/run merged)\n"
        "  peak memory (maxRSS):   %.1f MiB\n",
        total_s, read_s, dumps.size(), per_file_us, merge_s, merge_count,
        per_merge_us, peak_mb);
    return 0;
}

int run_catalog(const ClarionCatalogArgParse& cli) {
    if (cli.command == "knowledge") return run_knowledge(cli);

    const bool existed = fs::exists(cli.catalog_path);

    if (cli.command == "init") {
        if (existed && !cli.force) {
            std::printf(
                "Catalog already exists: %s (use --force to overwrite)\n",
                cli.catalog_path.c_str());
            return 0;
        }
        if (!save_catalog(cli.catalog_path, default_catalog())) {
            DFTRACER_UTILS_LOG_ERROR("failed to write %s",
                                     cli.catalog_path.c_str());
            return 1;
        }
        std::printf("Created catalog: %s\n", cli.catalog_path.c_str());
        return 0;
    }

    Catalog catalog;
    if (!existed) {
        catalog = default_catalog();
        std::printf("Catalog not found; initializing %s\n",
                    cli.catalog_path.c_str());
    } else if (!load_catalog(cli.catalog_path, catalog)) {
        return 1;
    }

    if (cli.command == "list") {
        print_catalog(catalog);
        return 0;
    }

    bool changed = false;

    if (cli.command == "add-category") {
        for (const auto& cat : cli.categories) {
            if (catalog.emplace(cat, std::vector<std::string>{}).second) {
                std::printf("Added category: %s\n", cat.c_str());
                changed = true;
            } else {
                std::printf("Category already exists: %s\n", cat.c_str());
            }
        }
    } else if (cli.command == "remove-category") {
        for (const auto& cat : cli.categories) {
            if (catalog.erase(cat) > 0) {
                std::printf("Removed category: %s\n", cat.c_str());
                changed = true;
            } else {
                std::printf("Category not found: %s\n", cat.c_str());
            }
        }
    } else if (cli.command == "add-function") {
        for (const auto& cat : cli.categories) {
            auto& fns = catalog[cat];
            for (const auto& fn : cli.functions) {
                if (std::find(fns.begin(), fns.end(), fn) != fns.end()) {
                    std::printf("Function already in %s: %s\n", cat.c_str(),
                                fn.c_str());
                    continue;
                }
                fns.push_back(fn);
                std::printf("Added function to %s: %s\n", cat.c_str(),
                            fn.c_str());
                changed = true;
            }
            std::sort(fns.begin(), fns.end());
        }
    } else if (cli.command == "remove-function") {
        for (const auto& cat : cli.categories) {
            auto it = catalog.find(cat);
            if (it == catalog.end()) {
                std::printf("Category not found: %s\n", cat.c_str());
                continue;
            }
            auto& fns = it->second;
            for (const auto& fn : cli.functions) {
                auto fit = std::find(fns.begin(), fns.end(), fn);
                if (fit == fns.end()) {
                    std::printf("Function not found in %s: %s\n", cat.c_str(),
                                fn.c_str());
                    continue;
                }
                fns.erase(fit);
                std::printf("Removed function from %s: %s\n", cat.c_str(),
                            fn.c_str());
                changed = true;
            }
        }
    }

    if (!changed) return 0;

    if (!save_catalog(cli.catalog_path, catalog)) {
        DFTRACER_UTILS_LOG_ERROR("failed to write %s", cli.catalog_path.c_str());
        return 1;
    }
    std::printf("Updated catalog: %s\n", cli.catalog_path.c_str());
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    return cli::cli_main<ClarionCatalogArgParse>(
        argc, argv, "clarion_catalog",
        "Manage the ClarIOn function catalog: categories of API-level "
        "functions (e.g. HDF5: H5Dwrite/H5Fopen; syscall: open/read/write) "
        "for downstream tools such as clarion_calltree. The 'knowledge' "
        "command instead merges a folder of catalog subtree dumps into a "
        "knowledge tree, tagging where their call trees diverge.",
        run_catalog);
}
