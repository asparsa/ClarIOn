#ifndef DFTRACER_UTILS_UTILITIES_CATALOG_MITIGATOR_H
#define DFTRACER_UTILS_UTILITIES_CATALOG_MITIGATOR_H

// Mitigator -- the "fight-or-flight" bottleneck mitigation of "Explaining HPC
// I/O Performance with Confidence", Sec. IV-E.
//
// Once anomaly detection flags a node v in a run's call tree, the Catalog (see
// knowledge_tree.h) supports two complementary, search-free mitigation
// strategies that return concrete configuration-change suggestions grounded in
// observed executions rather than generic rules:
//
//   * Fight keeps execution on its current path and recommends the parameters
//     that change the cost of v itself, together with the mechanism by which
//     they act. It is a lookup, not a search: during analysis the mitigator
//     derives an impact block for each parameter -- the set of nodes that
//     differ consistently (beyond run-to-run variation) between configurations
//     that differ only in that parameter and take the same path, either in the
//     number of calls per run (multiplicity) or in the exclusive time per call
//     (intensity), normalized by bytes for nodes that move data. Given v, fight
//     returns the parameters whose impact block contains v and that are not
//     path-coupled with v (changing a path-coupled parameter could alter
//     whether v is reached at all, so it is discarded); a returned parameter
//     that is path-coupled with another part of the call is flagged as having a
//     path side effect.
//
//   * Flight avoids v by moving execution onto a different path. Starting from
//     v it walks toward the root to the nearest branch point whose divergence
//     is configuration-driven or mixed (noise-driven branch points are skipped,
//     since switching between their children is not controlled by any
//     configuration). The siblings of the path to v at that branch point are
//     the candidate alternatives; a configuration is considered for a sibling
//     only if its runs take that sibling consistently, and is retained only if
//     none of its runs reaches any node with the same function name as v
//     anywhere in the API call. If no candidate remains, the walk continues to
//     the next eligible branch point; if the root is reached, the function is
//     reported as unavoidable. For each retained configuration, flight reports
//     the parameters in which it differs from the anomalous run, preferring
//     candidates that differ in the fewest parameters and, among those, the
//     path-coupled parameters that explain the branch point.
//
// Fight and flight are complementary: fight reduces a bottleneck when the path
// must be kept; flight removes it when a configuration-controlled alternative
// exists. When both fail, the cause lies outside the configuration space
// captured by the knowledge tree (see MitigationResult::outside_config_space).
//
// Like knowledge_tree.h this header is pure (standard library only): it reasons
// over an already-built knowledge tree plus the fully resolved per-configuration
// parameter values, so the fight/flight logic is unit-testable without a reader
// or runtime.

#include <dftracer/utils/utilities/catalog/knowledge_tree.h>

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace dftracer::utils::catalog {

// The mechanism by which a parameter changes a node's cost.
enum class ImpactType {
    None,
    Multiplicity,  // changes the number of calls per run
    Intensity      // changes the exclusive time per call (per byte for data)
};

inline const char* impact_type_name(ImpactType t) {
    switch (t) {
        case ImpactType::Multiplicity: return "multiplicity";
        case ImpactType::Intensity: return "intensity";
        case ImpactType::None: break;
    }
    return "none";
}

// Fully resolved parameter values of one configuration: parameter name ->
// value. Built from the Catalog's configuration table (ConfigRow::params).
using ParamMap = std::map<std::string, std::string>;
// All configurations' parameter maps, keyed by configuration label.
using ConfigParams = std::map<std::string, ParamMap>;

// A parameter's impact block: the nodes whose multiplicity or intensity moves
// with this parameter, mapped to the mechanism observed. Nodes are identified
// by pointer into the knowledge tree the block was built from.
struct ImpactBlock {
    std::string param;
    std::map<const KNode*, ImpactType> nodes;
};

// One fight recommendation: tune `param` to change v's cost through `impact`.
// `path_side_effect` is set when the parameter, while safe to tune for v, is
// path-coupled with another branch point in the call, so tuning it also changes
// a different part of the execution.
struct FightRec {
    std::string param;
    ImpactType impact = ImpactType::None;
    bool path_side_effect = false;
};

// One flight recommendation: a configuration whose runs avoid v, reached by
// switching children at a branch point on the path to v.
struct FlightRec {
    std::string config;        // alternative configuration that avoids v
    std::string branch_point;  // name of the branch-point node switched at
    int branch_depth = 0;      // depth of that branch point (root == 0)
    BranchClass branch_class = BranchClass::None;
    // Parameters in which `config` differs from the anomalous run.
    std::vector<std::pair<std::string, std::string>> diff_params;
    // Of those, the parameters that explain the branch point (path-coupled).
    std::vector<std::string> path_coupled_params;
};

// The outcome of mitigating one anomalous node.
struct MitigationResult {
    bool found_node = false;     // the anomalous node path resolved in the tree
    std::vector<FightRec> fight;
    std::vector<FlightRec> flight;
    bool unavoidable = false;    // flight walked to the root with no candidate
    // Neither strategy produced a recommendation: the anomaly's cause lies
    // outside the configuration space captured by the knowledge tree.
    bool outside_config_space = false;
};

// Tunables for the consistency tests (minimum effect sizes). A per-node change
// counts only when the relative difference between two configurations exceeds
// `min_rel_diff`, so negligible deviations are not reported.
struct MitigatorConfig {
    double min_rel_diff = 0.10;  // minimum effect size (10%)
};

namespace detail {

// Relative difference between two non-negative quantities, symmetric and
// defined (0) when both are zero.
inline double rel_diff(double a, double b) {
    const double m = std::max(std::fabs(a), std::fabs(b));
    if (m == 0.0) return 0.0;
    return std::fabs(a - b) / m;
}

// Calls per run for `cfg` at node n (multiplicity); 0 if the config never
// reached n.
inline double multiplicity(const KNode* n, const std::string& cfg) {
    auto rit = n->runs.find(cfg);
    if (rit == n->runs.end() || rit->second <= 0) return 0.0;
    auto cit = n->cfg_count.find(cfg);
    const long long c = cit == n->cfg_count.end() ? 0 : cit->second;
    return static_cast<double>(c) / static_cast<double>(rit->second);
}

// Exclusive time per call for `cfg` at node n (intensity), divided by bytes per
// call when the node moves data, so nodes are compared on cost per unit of work
// rather than raw time; 0 if the config never reached n.
inline double intensity(const KNode* n, const std::string& cfg) {
    auto cit = n->cfg_count.find(cfg);
    const long long calls = cit == n->cfg_count.end() ? 0 : cit->second;
    if (calls <= 0) return 0.0;
    auto eit = n->cfg_excl.find(cfg);
    const long long excl = eit == n->cfg_excl.end() ? 0 : eit->second;
    auto sit = n->cfg_size.find(cfg);
    const long long bytes = sit == n->cfg_size.end() ? 0 : sit->second;
    if (bytes > 0) return static_cast<double>(excl) / static_cast<double>(bytes);
    return static_cast<double>(excl) / static_cast<double>(calls);
}

// The parameters in which two configurations differ (union of keys whose values
// are unequal or present in only one).
inline std::set<std::string> differing_params(const ParamMap& a,
                                               const ParamMap& b) {
    std::set<std::string> out;
    for (const auto& [k, v] : a) {
        auto it = b.find(k);
        if (it == b.end() || it->second != v) out.insert(k);
    }
    for (const auto& [k, v] : b)
        if (a.find(k) == a.end()) out.insert(k);
    return out;
}

// True when a and b differ in exactly the one parameter `p`.
inline bool differ_only_in(const ParamMap& a, const ParamMap& b,
                           const std::string& p) {
    const std::set<std::string> d = differing_params(a, b);
    return d.size() == 1 && *d.begin() == p;
}

// The set of child names a configuration takes at node b (children it reached).
inline std::set<std::string> taken_children(const KNode* b,
                                            const std::string& cfg) {
    std::set<std::string> out;
    for (const auto& c : b->children) {
        auto it = c->runs.find(cfg);
        if (it != c->runs.end() && it->second > 0) out.insert(c->name);
    }
    return out;
}

// Visit every node of the tree rooted at n, in pre-order.
template <class Fn>
inline void for_each_node(const KNode* n, Fn&& fn) {
    fn(n);
    for (const auto& c : n->children) for_each_node(c.get(), fn);
}

// Whether any run of `cfg` reaches a node named `name` anywhere in the tree.
inline bool reaches_name(const KNode* root, const std::string& name,
                        const std::string& cfg) {
    bool found = false;
    for_each_node(root, [&](const KNode* n) {
        if (found || n->name != name) return;
        auto it = n->runs.find(cfg);
        if (it != n->runs.end() && it->second > 0) found = true;
    });
    return found;
}

// A parameter P "explains" a branch point b when two configurations that differ
// only in P reach b and take a different set of children there -- i.e. changing
// P changes which path is taken at b. Only configuration-driven and mixed
// branch points are path-controlled; noise-driven ones are not.
inline bool param_explains_branch(const KNode* b, const std::string& p,
                                  const std::vector<std::string>& configs,
                                  const ConfigParams& params) {
    if (b->branch != BranchClass::ConfigDriven && b->branch != BranchClass::Mixed)
        return false;
    for (std::size_t i = 0; i < configs.size(); ++i) {
        auto ri = b->runs.find(configs[i]);
        if (ri == b->runs.end() || ri->second <= 0) continue;
        const auto pi = params.find(configs[i]);
        if (pi == params.end()) continue;
        for (std::size_t j = i + 1; j < configs.size(); ++j) {
            auto rj = b->runs.find(configs[j]);
            if (rj == b->runs.end() || rj->second <= 0) continue;
            const auto pj = params.find(configs[j]);
            if (pj == params.end()) continue;
            if (!differ_only_in(pi->second, pj->second, p)) continue;
            if (taken_children(b, configs[i]) != taken_children(b, configs[j]))
                return true;
        }
    }
    return false;
}

}  // namespace detail

// Resolve the path from the tree root to the anomalous node named by
// `path_names` (root name first, then each child's function name). Returns the
// chain of nodes root..v, or empty if the path does not exist.
inline std::vector<const KNode*> resolve_path(
    const KNode* root, const std::vector<std::string>& path_names) {
    std::vector<const KNode*> chain;
    if (path_names.empty() || root->name != path_names.front()) return chain;
    const KNode* cur = root;
    chain.push_back(cur);
    for (std::size_t i = 1; i < path_names.size(); ++i) {
        const KNode* next = nullptr;
        for (const auto& c : cur->children)
            if (c->name == path_names[i]) {
                next = c.get();
                break;
            }
        if (!next) return {};
        cur = next;
        chain.push_back(cur);
    }
    return chain;
}

// Build the impact block of every parameter over the knowledge tree: for each
// pair of configurations that differ in exactly one parameter, every node both
// reached (so both took the same path to it) whose multiplicity or, failing
// that, intensity differs by more than the minimum effect size is marked with
// that mechanism for the parameter. Blocks may overlap, since a node can be
// affected by several parameters at once.
inline std::map<std::string, ImpactBlock> build_impact_blocks(
    const KNode* root, const std::vector<std::string>& configs,
    const ConfigParams& params, const MitigatorConfig& cfg = {}) {
    std::map<std::string, ImpactBlock> blocks;
    for (std::size_t i = 0; i < configs.size(); ++i) {
        const auto pi = params.find(configs[i]);
        if (pi == params.end()) continue;
        for (std::size_t j = i + 1; j < configs.size(); ++j) {
            const auto pj = params.find(configs[j]);
            if (pj == params.end()) continue;
            const std::set<std::string> diff =
                detail::differing_params(pi->second, pj->second);
            if (diff.size() != 1) continue;  // differ only in one parameter
            const std::string& p = *diff.begin();
            const std::string& a = configs[i];
            const std::string& b = configs[j];
            detail::for_each_node(root, [&](const KNode* n) {
                auto ra = n->runs.find(a), rb = n->runs.find(b);
                if (ra == n->runs.end() || ra->second <= 0) return;
                if (rb == n->runs.end() || rb->second <= 0) return;
                ImpactType hit = ImpactType::None;
                if (detail::rel_diff(detail::multiplicity(n, a),
                                     detail::multiplicity(n, b)) >
                    cfg.min_rel_diff)
                    hit = ImpactType::Multiplicity;
                else if (detail::rel_diff(detail::intensity(n, a),
                                          detail::intensity(n, b)) >
                         cfg.min_rel_diff)
                    hit = ImpactType::Intensity;
                if (hit == ImpactType::None) return;
                ImpactBlock& blk = blocks[p];
                blk.param = p;
                // Multiplicity takes precedence if seen for any config pair.
                ImpactType& slot = blk.nodes[n];
                if (slot != ImpactType::Multiplicity) slot = hit;
            });
        }
    }
    return blocks;
}

// Mitigate one anomalous node. `path_names` names the node v by its chain of
// function names from the API-call root; `anomaly_config` is the configuration
// of the run v was flagged in; `configs` lists every profiled configuration and
// `params` their resolved parameter values (from the configuration table).
// Returns the fight and flight recommendations (see MitigationResult).
inline MitigationResult mitigate(const KNode* root,
                                const std::vector<std::string>& path_names,
                                const std::string& anomaly_config,
                                const std::vector<std::string>& configs,
                                const ConfigParams& params,
                                const MitigatorConfig& mcfg = {}) {
    MitigationResult res;
    const std::vector<const KNode*> path = resolve_path(root, path_names);
    if (path.empty()) return res;
    res.found_node = true;
    const KNode* v = path.back();

    // Branch points on the path from the root to v (every ancestor of v that is
    // a configuration-driven or mixed branch point). path[k] is a branch point
    // whose on-path child is path[k + 1].
    std::vector<std::size_t> path_branch_idx;
    for (std::size_t k = 0; k + 1 < path.size(); ++k)
        if (path[k]->branch == BranchClass::ConfigDriven ||
            path[k]->branch == BranchClass::Mixed)
            path_branch_idx.push_back(k);

    // ── Fight ────────────────────────────────────────────────────────────────
    const std::map<std::string, ImpactBlock> blocks =
        build_impact_blocks(root, configs, params, mcfg);
    for (const auto& [p, blk] : blocks) {
        if (blk.nodes.find(v) == blk.nodes.end()) continue;  // v not impacted
        // Discard parameters path-coupled with v: tuning them could change
        // whether v is reached at all.
        bool coupled_with_v = false;
        for (std::size_t k : path_branch_idx)
            if (detail::param_explains_branch(path[k], p, configs, params)) {
                coupled_with_v = true;
                break;
            }
        if (coupled_with_v) continue;
        FightRec rec;
        rec.param = p;
        rec.impact = blk.nodes.at(v);
        // A path side effect: the parameter explains a branch point elsewhere
        // in the call (not on the path to v).
        detail::for_each_node(root, [&](const KNode* n) {
            if (rec.path_side_effect) return;
            for (std::size_t k : path_branch_idx)
                if (path[k] == n) return;  // on the path to v: not a side effect
            if (detail::param_explains_branch(n, p, configs, params))
                rec.path_side_effect = true;
        });
        res.fight.push_back(std::move(rec));
    }
    std::sort(res.fight.begin(), res.fight.end(),
              [](const FightRec& a, const FightRec& b) {
                  return a.param < b.param;
              });

    // ── Flight ─────────────────────────────────────────────────────────────
    const auto anom_it = params.find(anomaly_config);
    const ParamMap anom_params =
        anom_it == params.end() ? ParamMap{} : anom_it->second;
    // Walk from v toward the root. At each configuration-driven or mixed branch
    // point, gather sibling configurations that avoid v; stop at the first
    // branch point that yields any candidate.
    for (std::size_t up = path.size(); up-- > 1;) {
        const KNode* b = path[up - 1];  // branch-point candidate
        const KNode* on_path_child = path[up];
        if (b->branch != BranchClass::ConfigDriven &&
            b->branch != BranchClass::Mixed)
            continue;  // noise-driven / not a branch point: skip
        std::set<std::string> seen;  // dedup candidate configs
        std::vector<FlightRec> here;
        for (const auto& sib : b->children) {
            if (sib.get() == on_path_child) continue;  // sibling only
            for (const std::string& cfg : configs) {
                if (seen.count(cfg)) continue;
                auto br = b->runs.find(cfg);
                auto sr = sib->runs.find(cfg);
                if (br == b->runs.end() || br->second <= 0) continue;
                if (sr == sib->runs.end() || sr->second <= 0) continue;
                // The configuration must take this sibling consistently: every
                // run of cfg that reached b went through this sibling.
                if (sr->second != br->second) continue;
                // Retain only if no run of cfg reaches any node named like v.
                if (detail::reaches_name(root, v->name, cfg)) continue;
                FlightRec rec;
                rec.config = cfg;
                rec.branch_point = b->name;
                rec.branch_depth = static_cast<int>(up - 1);
                rec.branch_class = b->branch;
                const auto cp = params.find(cfg);
                if (cp != params.end()) {
                    for (const std::string& dp :
                         detail::differing_params(anom_params, cp->second)) {
                        const auto cv = cp->second.find(dp);
                        rec.diff_params.emplace_back(
                            dp, cv == cp->second.end() ? std::string{}
                                                       : cv->second);
                        if (detail::param_explains_branch(b, dp, configs,
                                                          params))
                            rec.path_coupled_params.push_back(dp);
                    }
                }
                seen.insert(cfg);
                here.push_back(std::move(rec));
            }
        }
        if (!here.empty()) {
            // Prefer candidates that differ in the fewest parameters and, among
            // those, the ones whose differences are the branch's path-coupled
            // parameters.
            std::sort(here.begin(), here.end(),
                      [](const FlightRec& a, const FlightRec& c) {
                          if (a.diff_params.size() != c.diff_params.size())
                              return a.diff_params.size() < c.diff_params.size();
                          if (a.path_coupled_params.size() !=
                              c.path_coupled_params.size())
                              return a.path_coupled_params.size() >
                                     c.path_coupled_params.size();
                          return a.config < c.config;
                      });
            res.flight = std::move(here);
            break;
        }
    }
    // If every eligible branch point up to the root yielded no candidate, v is
    // unavoidable for this API call.
    if (res.flight.empty()) res.unavoidable = true;

    res.outside_config_space = res.fight.empty() && res.flight.empty();
    return res;
}

}  // namespace dftracer::utils::catalog

#endif  // DFTRACER_UTILS_UTILITIES_CATALOG_MITIGATOR_H
