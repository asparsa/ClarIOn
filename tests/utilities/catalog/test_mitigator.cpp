// Unit tests for the pure fight-or-flight Mitigator logic (Sec. IV-E), with no
// trace I/O: impact-block derivation, path-coupling, the fight recommendation
// (tune v's cost in place, discarding path-coupled parameters), and the flight
// recommendation (walk to the nearest configuration-driven / mixed branch point
// and switch onto a configuration whose runs avoid v).
//
// Trees are assembled directly with explicit per-configuration statistics
// (runs / call count / exclusive duration / bytes), the same way
// test_knowledge_tree.cpp builds trees by hand, so each scenario pins down one
// behavior precisely without depending on the merge/classify pipeline.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <dftracer/utils/utilities/catalog/mitigator.h>

#include <memory>
#include <string>
#include <vector>

using dftracer::utils::catalog::BranchClass;
using dftracer::utils::catalog::build_impact_blocks;
using dftracer::utils::catalog::ConfigParams;
using dftracer::utils::catalog::ImpactType;
using dftracer::utils::catalog::KNode;
using dftracer::utils::catalog::mitigate;
using dftracer::utils::catalog::MitigationResult;
using dftracer::utils::catalog::resolve_path;

namespace {

// Record one configuration's statistics at a node: how many runs reached it,
// the summed call count and exclusive duration over those runs, and the bytes
// moved (0 when the node does not transfer data).
void stat(KNode* n, const std::string& cfg, long long runs, long long count,
          long long excl, long long size = 0) {
    n->runs[cfg] = runs;
    n->cfg_count[cfg] = count;
    n->cfg_excl[cfg] = excl;
    n->cfg_size[cfg] = size;
}

}  // namespace

TEST_CASE("resolve_path walks function names from the root to v") {
    auto root = std::make_unique<KNode>();
    root->name = "A";
    KNode* mid = root->add_child("mid");
    mid->add_child("v");

    auto path = resolve_path(root.get(), {"A", "mid", "v"});
    REQUIRE(path.size() == 3);
    CHECK(path.front()->name == "A");
    CHECK(path.back()->name == "v");

    CHECK(resolve_path(root.get(), {"A", "nope"}).empty());
    CHECK(resolve_path(root.get(), {"wrong-root", "mid"}).empty());
}

TEST_CASE("fight returns an intensity parameter when v's cost moves with it") {
    // H5Dread -> readv, taken by both configs (no branch point). The two
    // configurations differ only in "compression"; readv has the same call
    // count per run (multiplicity equal) but a much smaller exclusive time per
    // call under gzip (intensity differs) -> compression is an intensity knob.
    auto root = std::make_unique<KNode>();
    root->name = "H5Dread";
    stat(root.get(), "none", 1, 1, 0);
    stat(root.get(), "gzip", 1, 1, 0);
    KNode* v = root->add_child("readv");
    stat(v, "none", 1, 10, 4000);  // intensity 400 / call
    stat(v, "gzip", 1, 10, 1000);  // intensity 100 / call

    ConfigParams params{{"none", {{"compression", "none"}}},
                        {"gzip", {{"compression", "gzip"}}}};
    std::vector<std::string> configs{"none", "gzip"};

    MitigationResult r =
        mitigate(root.get(), {"H5Dread", "readv"}, "none", configs, params);
    REQUIRE(r.found_node);
    REQUIRE(r.fight.size() == 1);
    CHECK(r.fight[0].param == "compression");
    CHECK(r.fight[0].impact == ImpactType::Intensity);
    CHECK_FALSE(r.fight[0].path_side_effect);
    // No branch point above v, so flight has nowhere to switch: v is
    // unavoidable, but a fight recommendation keeps it out of "outside config
    // space".
    CHECK(r.flight.empty());
    CHECK(r.unavoidable);
    CHECK_FALSE(r.outside_config_space);
}

TEST_CASE("fight recognizes a multiplicity parameter") {
    // Same shape, but now the parameter changes how many times readv is called
    // per run (multiplicity) rather than its per-call cost.
    auto root = std::make_unique<KNode>();
    root->name = "H5Dread";
    stat(root.get(), "c64", 1, 1, 0);
    stat(root.get(), "c256", 1, 1, 0);
    KNode* v = root->add_child("readv");
    stat(v, "c64", 1, 64, 6400);   // 64 calls/run
    stat(v, "c256", 1, 16, 1600);  // 16 calls/run, same per-call intensity 100

    ConfigParams params{{"c64", {{"chunk", "64"}}},
                        {"c256", {{"chunk", "256"}}}};
    std::vector<std::string> configs{"c64", "c256"};

    MitigationResult r =
        mitigate(root.get(), {"H5Dread", "readv"}, "c64", configs, params);
    REQUIRE(r.fight.size() == 1);
    CHECK(r.fight[0].param == "chunk");
    CHECK(r.fight[0].impact == ImpactType::Multiplicity);
}

TEST_CASE("flight switches onto a sibling configuration that avoids v") {
    // A is a configuration-driven branch point: cfgL takes child "p", cfgR
    // takes child "v" (the anomaly). Flight should recommend cfgL, which never
    // reaches a node named v.
    auto root = std::make_unique<KNode>();
    root->name = "A";
    root->branch = BranchClass::ConfigDriven;
    stat(root.get(), "cfgL", 2, 2, 0);
    stat(root.get(), "cfgR", 2, 2, 0);

    KNode* p = root->add_child("p");
    stat(p, "cfgL", 2, 2, 0);  // cfgL takes p in all its runs
    KNode* v = root->add_child("v");
    stat(v, "cfgR", 2, 2, 0);  // cfgR takes v in all its runs

    ConfigParams params{{"cfgL", {{"path", "left"}}},
                        {"cfgR", {{"path", "right"}}}};
    std::vector<std::string> configs{"cfgL", "cfgR"};

    MitigationResult r =
        mitigate(root.get(), {"A", "v"}, "cfgR", configs, params);
    REQUIRE(r.found_node);
    REQUIRE(r.flight.size() == 1);
    CHECK(r.flight[0].config == "cfgL");
    CHECK(r.flight[0].branch_point == "A");
    CHECK(r.flight[0].branch_depth == 0);
    CHECK(r.flight[0].branch_class == BranchClass::ConfigDriven);
    REQUIRE(r.flight[0].diff_params.size() == 1);
    CHECK(r.flight[0].diff_params[0].first == "path");
    CHECK(r.flight[0].diff_params[0].second == "left");
    // "path" explains the branch point, so it is reported as path-coupled.
    REQUIRE(r.flight[0].path_coupled_params.size() == 1);
    CHECK(r.flight[0].path_coupled_params[0] == "path");
    CHECK_FALSE(r.unavoidable);
}

TEST_CASE("flight reports v unavoidable when every alternative still reaches it") {
    // As above, but the "p" branch also calls a node named v, so cfgL does not
    // actually avoid v. With no fight knob either, the anomaly falls outside the
    // captured configuration space.
    auto root = std::make_unique<KNode>();
    root->name = "A";
    root->branch = BranchClass::ConfigDriven;
    stat(root.get(), "cfgL", 1, 1, 0);
    stat(root.get(), "cfgR", 1, 1, 0);

    KNode* p = root->add_child("p");
    stat(p, "cfgL", 1, 1, 0);
    KNode* p_v = p->add_child("v");  // cfgL reaches a v-named node too
    stat(p_v, "cfgL", 1, 1, 0);
    KNode* v = root->add_child("v");
    stat(v, "cfgR", 1, 1, 0);

    ConfigParams params{{"cfgL", {{"path", "left"}}},
                        {"cfgR", {{"path", "right"}}}};
    std::vector<std::string> configs{"cfgL", "cfgR"};

    MitigationResult r =
        mitigate(root.get(), {"A", "v"}, "cfgR", configs, params);
    REQUIRE(r.found_node);
    CHECK(r.flight.empty());
    CHECK(r.unavoidable);
    CHECK(r.fight.empty());
    CHECK(r.outside_config_space);
}

TEST_CASE("flight skips a noise-driven branch and switches higher up") {
    // Path A -> mid -> v. "mid" is a noise-driven branch point (not controlled
    // by configuration), so flight skips it and switches at A, which is
    // configuration-driven, onto cfgL's "alt" subtree.
    auto root = std::make_unique<KNode>();
    root->name = "A";
    root->branch = BranchClass::ConfigDriven;
    stat(root.get(), "cfgL", 1, 1, 0);
    stat(root.get(), "cfgR", 1, 1, 0);

    KNode* alt = root->add_child("alt");
    stat(alt, "cfgL", 1, 1, 0);
    KNode* mid = root->add_child("mid");
    mid->branch = BranchClass::NoiseDriven;
    stat(mid, "cfgR", 1, 1, 0);
    KNode* v = mid->add_child("v");
    stat(v, "cfgR", 1, 1, 0);

    ConfigParams params{{"cfgL", {{"path", "left"}}},
                        {"cfgR", {{"path", "right"}}}};
    std::vector<std::string> configs{"cfgL", "cfgR"};

    MitigationResult r =
        mitigate(root.get(), {"A", "mid", "v"}, "cfgR", configs, params);
    REQUIRE(r.flight.size() == 1);
    CHECK(r.flight[0].config == "cfgL");
    CHECK(r.flight[0].branch_point == "A");  // skipped the noise-driven "mid"
    CHECK(r.flight[0].branch_depth == 0);
}

TEST_CASE("fight discards a parameter that is path-coupled with v") {
    // R is a mixed branch point. "mode" both changes v's cost (it is in v's
    // impact block) and controls, for some runs, whether the path to v is taken
    // at all -- so tuning it could move the execution off v's path. Fight must
    // discard it, even though build_impact_blocks still lists v in mode's block.
    //
    // Configurations:
    //   c1 {mode=fast, io=1} -> mid -> v   (v, cheap)
    //   c3 {mode=slow, io=1} -> mid -> v   (v, expensive: mode changes v cost)
    //   c2 {mode=fast, io=2} -> mid -> w   (reaches mid, not v)
    //   c4 {mode=slow, io=2} -> other      (mode flips the branch away from mid)
    auto root = std::make_unique<KNode>();
    root->name = "R";
    root->branch = BranchClass::Mixed;
    stat(root.get(), "c1", 1, 1, 0);
    stat(root.get(), "c2", 1, 1, 0);
    stat(root.get(), "c3", 1, 1, 0);
    stat(root.get(), "c4", 1, 1, 0);

    KNode* mid = root->add_child("mid");
    mid->branch = BranchClass::ConfigDriven;
    stat(mid, "c1", 1, 1, 0);
    stat(mid, "c2", 1, 1, 0);
    stat(mid, "c3", 1, 1, 0);
    KNode* v = mid->add_child("v");
    stat(v, "c1", 1, 1, 100);  // exclusive time per call = 100
    stat(v, "c3", 1, 1, 400);  // mode changes v's intensity (400 per call)
    KNode* w = mid->add_child("w");
    stat(w, "c2", 1, 1, 0);

    KNode* other = root->add_child("other");
    stat(other, "c4", 1, 1, 0);

    ConfigParams params{{"c1", {{"mode", "fast"}, {"io", "1"}}},
                        {"c2", {{"mode", "fast"}, {"io", "2"}}},
                        {"c3", {{"mode", "slow"}, {"io", "1"}}},
                        {"c4", {{"mode", "slow"}, {"io", "2"}}}};
    std::vector<std::string> configs{"c1", "c2", "c3", "c4"};

    // "mode" does impact v (c1 vs c3 differ only in mode and both reach v).
    auto blocks = build_impact_blocks(root.get(), configs, params);
    REQUIRE(blocks.count("mode") == 1);
    CHECK(blocks["mode"].nodes.count(v) == 1);

    // ...but mode also explains the mixed branch at R (c2 vs c4 differ only in
    // mode and take different children), so fight discards it: no in-place knob
    // is safe for v on this path.
    MitigationResult r =
        mitigate(root.get(), {"R", "mid", "v"}, "c1", configs, params);
    REQUIRE(r.found_node);
    CHECK(r.fight.empty());
}

TEST_CASE("multiplicity takes precedence when both mechanisms move") {
    // readv changes both in calls-per-run and in per-call cost with the
    // parameter; multiplicity is reported as the mechanism.
    auto root = std::make_unique<KNode>();
    root->name = "H5Dread";
    stat(root.get(), "a", 1, 1, 0);
    stat(root.get(), "b", 1, 1, 0);
    KNode* v = root->add_child("readv");
    stat(v, "a", 1, 10, 1000);  // 10 calls/run, 100/call
    stat(v, "b", 1, 20, 4000);  // 20 calls/run, 200/call -- both differ

    ConfigParams params{{"a", {{"x", "0"}}}, {"b", {{"x", "1"}}}};
    std::vector<std::string> configs{"a", "b"};

    MitigationResult r =
        mitigate(root.get(), {"H5Dread", "readv"}, "a", configs, params);
    REQUIRE(r.fight.size() == 1);
    CHECK(r.fight[0].param == "x");
    CHECK(r.fight[0].impact == ImpactType::Multiplicity);
}

TEST_CASE("intensity is normalized by bytes: equal time-per-byte is not a knob") {
    // Both configs move data; the raw exclusive time differs (100 vs 400) but
    // so do the bytes (100 vs 400), so the time-per-byte is identical and the
    // parameter is NOT an intensity knob for v.
    auto root = std::make_unique<KNode>();
    root->name = "A";
    stat(root.get(), "a", 1, 1, 0);
    stat(root.get(), "b", 1, 1, 0);
    KNode* v = root->add_child("write");
    stat(v, "a", 1, 1, 100, 100);  // 1.0 per byte
    stat(v, "b", 1, 1, 400, 400);  // 1.0 per byte

    ConfigParams params{{"a", {{"buf", "s"}}}, {"b", {{"buf", "l"}}}};
    std::vector<std::string> configs{"a", "b"};

    auto blocks = build_impact_blocks(root.get(), configs, params);
    CHECK(blocks.count("buf") == 0);  // nothing moved beyond the effect size

    MitigationResult r =
        mitigate(root.get(), {"A", "write"}, "a", configs, params);
    CHECK(r.fight.empty());
}

TEST_CASE("intensity is normalized by bytes: different time-per-byte is a knob") {
    // Same bytes, different exclusive time -> the per-byte cost differs, so the
    // parameter is an intensity knob.
    auto root = std::make_unique<KNode>();
    root->name = "A";
    stat(root.get(), "a", 1, 1, 0);
    stat(root.get(), "b", 1, 1, 0);
    KNode* v = root->add_child("write");
    stat(v, "a", 1, 1, 100, 100);  // 1.0 per byte
    stat(v, "b", 1, 1, 400, 100);  // 4.0 per byte

    ConfigParams params{{"a", {{"buf", "s"}}}, {"b", {{"buf", "l"}}}};
    std::vector<std::string> configs{"a", "b"};

    MitigationResult r =
        mitigate(root.get(), {"A", "write"}, "a", configs, params);
    REQUIRE(r.fight.size() == 1);
    CHECK(r.fight[0].param == "buf");
    CHECK(r.fight[0].impact == ImpactType::Intensity);
}

TEST_CASE("a change below the minimum effect size is not reported") {
    // v's per-call cost moves by under 10% between the two configs: negligible,
    // so no fight knob is reported.
    auto root = std::make_unique<KNode>();
    root->name = "A";
    stat(root.get(), "a", 1, 1, 0);
    stat(root.get(), "b", 1, 1, 0);
    KNode* v = root->add_child("read");
    stat(v, "a", 1, 1, 100);
    stat(v, "b", 1, 1, 105);  // ~5% -- below the default 10% effect size

    ConfigParams params{{"a", {{"p", "0"}}}, {"b", {{"p", "1"}}}};
    std::vector<std::string> configs{"a", "b"};

    MitigationResult r =
        mitigate(root.get(), {"A", "read"}, "a", configs, params);
    CHECK(r.fight.empty());
}

TEST_CASE("fight flags a path side effect for a knob that steers another branch") {
    // R is not a branch, so both configs reach v (where "p" is an intensity
    // knob) and also reach "ob", a configuration-driven branch that "p" steers.
    // Tuning p is safe for v's path but also changes the "ob" subtree -> the
    // fight recommendation carries a path side effect.
    auto root = std::make_unique<KNode>();
    root->name = "R";
    root->branch = BranchClass::None;
    stat(root.get(), "c1", 1, 1, 0);
    stat(root.get(), "c2", 1, 1, 0);

    KNode* v = root->add_child("v");
    stat(v, "c1", 1, 1, 100);
    stat(v, "c2", 1, 1, 400);  // p changes v's intensity

    KNode* ob = root->add_child("ob");
    ob->branch = BranchClass::ConfigDriven;
    stat(ob, "c1", 1, 1, 0);
    stat(ob, "c2", 1, 1, 0);
    KNode* oa = ob->add_child("ob_a");
    stat(oa, "c1", 1, 1, 0);  // c1 steers ob to ob_a
    KNode* obb = ob->add_child("ob_b");
    stat(obb, "c2", 1, 1, 0);  // c2 steers ob to ob_b

    ConfigParams params{{"c1", {{"p", "x"}}}, {"c2", {{"p", "y"}}}};
    std::vector<std::string> configs{"c1", "c2"};

    MitigationResult r =
        mitigate(root.get(), {"R", "v"}, "c1", configs, params);
    REQUIRE(r.fight.size() == 1);
    CHECK(r.fight[0].param == "p");
    CHECK(r.fight[0].impact == ImpactType::Intensity);
    CHECK(r.fight[0].path_side_effect);  // p also steers the "ob" branch
}

TEST_CASE("flight prefers the candidate that differs in the fewest parameters") {
    // A is configuration-driven: the anomaly cfgV takes v; cfgP1 and cfgP2 both
    // take sibling "p" and avoid v. cfgP1 differs from the anomaly in one
    // parameter, cfgP2 in two -- cfgP1 is ranked first.
    auto root = std::make_unique<KNode>();
    root->name = "A";
    root->branch = BranchClass::ConfigDriven;
    stat(root.get(), "cfgV", 1, 1, 0);
    stat(root.get(), "cfgP1", 1, 1, 0);
    stat(root.get(), "cfgP2", 1, 1, 0);

    KNode* v = root->add_child("v");
    stat(v, "cfgV", 1, 1, 0);
    KNode* p = root->add_child("p");
    stat(p, "cfgP1", 1, 1, 0);
    stat(p, "cfgP2", 1, 1, 0);

    ConfigParams params{{"cfgV", {{"a", "1"}, {"b", "1"}}},
                        {"cfgP1", {{"a", "2"}, {"b", "1"}}},   // differs in a
                        {"cfgP2", {{"a", "2"}, {"b", "2"}}}};  // differs in a, b
    std::vector<std::string> configs{"cfgV", "cfgP1", "cfgP2"};

    MitigationResult r =
        mitigate(root.get(), {"A", "v"}, "cfgV", configs, params);
    REQUIRE(r.flight.size() == 2);
    CHECK(r.flight[0].config == "cfgP1");  // one differing parameter -> first
    CHECK(r.flight[0].diff_params.size() == 1);
    CHECK(r.flight[1].config == "cfgP2");  // two differing parameters
    // "a" explains the branch at A (flipping it changes v vs p), so it is the
    // path-coupled parameter in cfgP1's recommendation.
    REQUIRE(r.flight[0].path_coupled_params.size() == 1);
    CHECK(r.flight[0].path_coupled_params[0] == "a");
}

TEST_CASE("flight walks past a branch with no valid candidate to a higher one") {
    // Path R -> mid -> v. At "mid" the only sibling ("w") still reaches a node
    // named v, so it is rejected; the walk continues to R, where "alt" (cfgL)
    // genuinely avoids v.
    auto root = std::make_unique<KNode>();
    root->name = "R";
    root->branch = BranchClass::ConfigDriven;
    stat(root.get(), "cfgR", 1, 1, 0);
    stat(root.get(), "cfgW", 1, 1, 0);
    stat(root.get(), "cfgL", 1, 1, 0);

    KNode* mid = root->add_child("mid");
    mid->branch = BranchClass::ConfigDriven;
    stat(mid, "cfgR", 1, 1, 0);
    stat(mid, "cfgW", 1, 1, 0);  // cfgR and cfgW both take mid
    KNode* v = mid->add_child("v");
    stat(v, "cfgR", 1, 1, 0);
    KNode* w = mid->add_child("w");
    stat(w, "cfgW", 1, 1, 0);
    KNode* w_v = w->add_child("v");  // "w" still reaches a v-named node
    stat(w_v, "cfgW", 1, 1, 0);

    KNode* alt = root->add_child("alt");
    stat(alt, "cfgL", 1, 1, 0);  // cfgL avoids v entirely

    ConfigParams params{{"cfgR", {{"path", "r"}}},
                        {"cfgW", {{"path", "w"}}},
                        {"cfgL", {{"path", "l"}}}};
    std::vector<std::string> configs{"cfgR", "cfgW", "cfgL"};

    MitigationResult r =
        mitigate(root.get(), {"R", "mid", "v"}, "cfgR", configs, params);
    REQUIRE(r.flight.size() == 1);
    CHECK(r.flight[0].config == "cfgL");
    CHECK(r.flight[0].branch_point == "R");  // skipped "mid": no valid candidate
    CHECK(r.flight[0].branch_depth == 0);
}

TEST_CASE("mitigate reports no node for a path that is not in the tree") {
    auto root = std::make_unique<KNode>();
    root->name = "A";
    root->add_child("x");

    MitigationResult r = mitigate(root.get(), {"A", "nope"}, "cfg", {"cfg"}, {});
    CHECK_FALSE(r.found_node);
    CHECK(r.fight.empty());
    CHECK(r.flight.empty());
}
