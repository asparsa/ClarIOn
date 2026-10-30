// Unit tests for the pure knowledge-tree logic (no trace I/O): structural
// hashing, top-down merge-by-name with tagging of appended (divergent) nodes,
// branch-point classification, divergence-table derivation, and serialization.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <dftracer/utils/utilities/catalog/knowledge_tree.h>

#include <memory>
#include <string>
#include <vector>

using dftracer::utils::catalog::BranchClass;
using dftracer::utils::catalog::classify_branches;
using dftracer::utils::catalog::collect_divergences;
using dftracer::utils::catalog::compute_hash;
using dftracer::utils::catalog::DivergenceRow;
using dftracer::utils::catalog::KNode;
using dftracer::utils::catalog::merge_run;
using dftracer::utils::catalog::serialize_knowledge;
using dftracer::utils::catalog::strip_addr;

namespace {

// Build a small call tree: root "A" (dur 10) with leaf children named by
// `kids` (each dur 2). Matches the shape the reconstructor produces.
std::unique_ptr<KNode> make_tree(const std::string& root,
                                 const std::vector<std::string>& kids) {
    auto n = std::make_unique<KNode>();
    n->name = root;
    n->count = 1;
    n->dur = 10;
    for (const auto& k : kids) {
        KNode* c = n->add_child(k);
        c->count = 1;
        c->dur = 2;
    }
    return n;
}

// Seed an empty knowledge root for an API call, ready to merge runs into.
std::unique_ptr<KNode> empty_root(const std::string& name) {
    auto n = std::make_unique<KNode>();
    n->name = name;
    return n;
}

}  // namespace

TEST_CASE("strip_addr removes a trailing :0x<hex> suffix") {
    CHECK(strip_addr("H5Dwrite:0xd89d0") == "H5Dwrite");
    CHECK(strip_addr("H5D__write_api_common.constprop.0:0xd4cf0") ==
          "H5D__write_api_common.constprop.0");
    CHECK(strip_addr("plain_name") == "plain_name");
    CHECK(strip_addr("has:colon:but:no:addr") == "has:colon:but:no:addr");
    // ":0x" with no hex digits after it is not an address suffix.
    CHECK(strip_addr("weird:0x") == "weird:0x");
}

TEST_CASE("identical runs produce no tags and accumulate counts") {
    auto k = empty_root("A");
    auto r1 = make_tree("A", {"x", "y"});
    auto r2 = make_tree("A", {"x", "y"});

    int next_tag = 0;
    merge_run(k.get(), r1.get(), "cfg1", /*baseline=*/true, 1, next_tag);
    merge_run(k.get(), r2.get(), "cfg1", /*baseline=*/false, 1, next_tag);

    CHECK(next_tag == 0);  // no divergence
    CHECK(k->tag == -1);
    CHECK(k->children.size() == 2);
    CHECK(k->count == 2);  // two runs folded in
    // Two runs of one config reached the root.
    CHECK(k->runs["cfg1"] == 2);

    classify_branches(k.get());
    CHECK(k->branch == BranchClass::None);  // both runs took the same children

    std::vector<DivergenceRow> rows;
    collect_divergences(k.get(), "A", rows);
    CHECK(rows.empty());
}

TEST_CASE("a child only the second run has is tagged and appended") {
    auto k = empty_root("A");
    auto base = make_tree("A", {"x", "y"});
    auto variant = make_tree("A", {"x", "y", "z"});

    int next_tag = 0;
    merge_run(k.get(), base.get(), "cfg1", /*baseline=*/true, 1, next_tag);
    merge_run(k.get(), variant.get(), "cfg2", /*baseline=*/false, 7, next_tag);

    CHECK(next_tag == 1);
    CHECK(k->children.size() == 3);  // adopted "z"

    // The appended node "z" carries the tag (not the parent).
    CHECK(k->tag == -1);
    KNode* z = k->child_by_name("z");
    REQUIRE(z != nullptr);
    CHECK(z->tag == 0);
    CHECK(z->runs["cfg2"] == 7);  // multiplicity carried

    classify_branches(k.get());
    // cfg1 took {x;y}, cfg2 took {x;y;z}: two signatures, each config
    // consistent within itself -> configuration-driven branch point at root.
    CHECK(k->branch == BranchClass::ConfigDriven);

    std::vector<DivergenceRow> rows;
    collect_divergences(k.get(), "A", rows);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].tag_id == 0);
    CHECK(rows[0].api_call == "A");
    CHECK(rows[0].node == "z");
    CHECK(rows[0].depth == 1);
    CHECK(rows[0].parent_branch == BranchClass::ConfigDriven);
    CHECK(rows[0].num_runs == 7);
    REQUIRE(rows[0].configs.size() == 1);
    CHECK(*rows[0].configs.begin() == "cfg2");
}

TEST_CASE("within-config split classifies the branch point as noise-driven") {
    auto k = empty_root("A");
    auto a = make_tree("A", {"x"});
    auto b = make_tree("A", {"y"});

    int next_tag = 0;
    // Same configuration, two runs that take different children.
    merge_run(k.get(), a.get(), "cfg1", /*baseline=*/true, 1, next_tag);
    merge_run(k.get(), b.get(), "cfg1", /*baseline=*/false, 1, next_tag);

    CHECK(next_tag == 1);  // "y" appended and tagged
    classify_branches(k.get());
    CHECK(k->branch == BranchClass::NoiseDriven);
}

TEST_CASE("divergence deeper down tags the inner appended node") {
    auto k = empty_root("A");

    auto base = std::make_unique<KNode>();
    base->name = "A";
    base->count = 1;
    base->dur = 10;
    base->add_child("x")->count = 1;
    base->children.front()->add_child("p");

    auto variant = std::make_unique<KNode>();
    variant->name = "A";
    variant->count = 1;
    variant->dur = 10;
    variant->add_child("x")->count = 1;
    variant->children.front()->add_child("q");

    int next_tag = 0;
    merge_run(k.get(), base.get(), "cfg1", /*baseline=*/true, 1, next_tag);
    merge_run(k.get(), variant.get(), "cfg2", /*baseline=*/false, 1, next_tag);

    CHECK(k->tag == -1);              // root child sets agree ({x} == {x})
    KNode* x = k->child_by_name("x");
    REQUIRE(x != nullptr);
    CHECK(x->tag == -1);             // x itself is present in both
    CHECK(x->children.size() == 2);  // x adopted q alongside p
    KNode* q = x->child_by_name("q");
    REQUIRE(q != nullptr);
    CHECK(q->tag == 0);             // the appended node q carries the tag

    classify_branches(k.get());
    CHECK(x->branch == BranchClass::ConfigDriven);  // x is the branch point

    std::vector<DivergenceRow> rows;
    collect_divergences(k.get(), "A", rows);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].node == "q");
    CHECK(rows[0].depth == 2);
}

TEST_CASE("serialize_knowledge emits tag and branch only where they apply") {
    auto k = empty_root("A");
    auto base = make_tree("A", {"x"});
    auto variant = make_tree("A", {"y"});
    int next_tag = 0;
    merge_run(k.get(), base.get(), "cfg1", /*baseline=*/true, 1, next_tag);
    merge_run(k.get(), variant.get(), "cfg2", /*baseline=*/false, 1, next_tag);
    compute_hash(k.get());
    classify_branches(k.get());

    std::vector<KNode*> roots{k.get()};
    const std::string json = serialize_knowledge(roots);

    CHECK(json.front() == '[');
    CHECK(json.find("\"ph\":\"X\"") != std::string::npos);
    CHECK(json.find("\"name\":\"A\"") != std::string::npos);
    // The appended child "y" is tagged; exactly one tag field in the document.
    CHECK(json.find("\"tag\":0") != std::string::npos);
    std::size_t tags = 0, pos = 0;
    while ((pos = json.find("\"tag\":", pos)) != std::string::npos) {
        ++tags;
        pos += 6;
    }
    CHECK(tags == 1);
    // The root is a (configuration-driven) branch point.
    CHECK(json.find("\"branch\":\"config-driven\"") != std::string::npos);
    // Every node carries a per-configuration exclusive-duration histogram.
    CHECK(json.find("\"excl_hist\":") != std::string::npos);
}
