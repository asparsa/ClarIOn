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

#include <dftracer/utils/core/common/config.h>
#include <dftracer/utils/core/common/filesystem.h>
#include <dftracer/utils/core/common/logging.h>

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "common_cli.h"

using namespace dftracer::utils;

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
    std::string command;
    std::string catalog_path;
    std::vector<std::string> categories;
    std::vector<std::string> functions;
    bool force = false;

    explicit ClarionCatalogArgParse(argparse::ArgumentParser& p) : ArgParse(p) {}

   protected:
    void register_args() override {
        parser()
            .add_argument("command")
            .help(
                "Action to perform: init, list, add-category, "
                "remove-category, add-function, remove-function")
            .choices("init", "list", "add-category", "remove-category",
                    "add-function", "remove-function");
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
    }

    void post_parse() override {
        command = parser().get<std::string>("command");
        catalog_path = parser().get<std::string>("--output");
        categories = parser().get<std::vector<std::string>>("--category");
        functions = parser().get<std::vector<std::string>>("--function");
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
        return true;
    }
};

int run_catalog(const ClarionCatalogArgParse& cli) {
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
        "for downstream tools such as clarion_calltree.",
        run_catalog);
}
