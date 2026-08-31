// Synthesizes call-tree traces with deliberately injected anomalies (both
// Performance and System kinds), runs clarion_calltree --detect-anomaly on
// them, parses the resulting <output>.anomalies.txt report, and checks
// detection accuracy: how many injected anomalies were found, whether each
// one was captured with the right name/depth/ancestor, and whether any
// unexpected (false-positive) rows were reported.
//
// The trace synthesizer (synthesize_trace, below) is parameterized on:
//   - how many anomalies to inject (the size of the `requests` vector),
//   - the kind of each one (AnomalyKind::kPerf / kSys),
//   - the depth at which each one occurs (AnomalyRequest::depth, root's
//     direct children == depth 1),
//   - the height of the surrounding "normal" tree (tree_height): each
//     anomaly's root is padded with filler nesting so the tree reaches at
//     least this depth even when the anomaly itself sits shallower.
// Each requested anomaly gets its own independent root tree (named
// "root_<i>"), so anomalies never interact with each other and the ground
// truth is trivial to state. A fixed "stable_op" root is always included as
// a negative control (repeated identically, never merges into an anomaly).
//
// The fixed TEST_CASEs below cover a spread of these parameters as a
// regression suite. For ad-hoc manual runs, one more TEST_CASE
// ("configurable via CLI") reads its config from custom command-line flags
// (parsed out of argv before doctest sees it, see parse_custom_args below).
// Passing any of them automatically runs just that one case -- no need to
// also know about doctest's own --test-case filter:
//   --count N            number of anomalies to inject (default 2)
//   --depth N            depth of every injected anomaly (default 2)
//   --tree_height N       minimum height of the surrounding tree (default 3)
//   --performance_only    inject only Performance anomalies
//   --system_only         inject only System anomalies
// e.g.: ./binaries_test_clarion_calltree --depth 30 --performance_only

#define DOCTEST_CONFIG_IMPLEMENT
#include <dftracer/utils/core/common/filesystem.h>
#include <doctest/doctest.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <testing_utilities.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

std::string find_binary() {
    const char* env_path = std::getenv("CLARION_CALLTREE_PATH");
    if (env_path && ::access(env_path, X_OK) == 0) return env_path;
    for (const auto& p :
         {"./clarion_calltree", "../clarion_calltree",
          "../../clarion_calltree", "../bin/clarion_calltree",
          "../../bin/clarion_calltree"}) {
        if (::access(p, X_OK) == 0) return p;
    }
    return "";
}

// Runs `binary` with `args`, discarding its stdout/stderr (clarion_calltree
// prints its own dftracer-core I/O-backend logging and "Output file:"/
// "Anomaly report:" lines, which are noise here — the tests only care about
// the exit code and the files it produces on disk).
int run_process(const std::string& binary,
                const std::vector<std::string>& args) {
    pid_t pid = ::fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        const int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
            ::close(devnull);
        }
        std::vector<const char*> argv;
        argv.push_back(binary.c_str());
        for (const auto& a : args) argv.push_back(a.c_str());
        argv.push_back(nullptr);
        ::execv(binary.c_str(), const_cast<char* const*>(argv.data()));
        ::_exit(127);
    }
    int status = 0;
    ::waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

bool write_file(const std::string& path, const std::string& content) {
    std::ofstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    f << content;
    return f.good();
}

std::string read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    return std::string(std::istreambuf_iterator<char>(f),
                       std::istreambuf_iterator<char>());
}

// Config for the "configurable via CLI" test case, populated by
// parse_custom_args() from flags that doctest itself doesn't know about
// (e.g. --depth 30 --performance_only). Left at these defaults, the test
// case behaves as an ordinary fixed regression case.
struct CliConfig {
    int count = 2;
    int depth = 2;
    int tree_height = 3;
    bool performance_only = false;
    bool system_only = false;
};
CliConfig g_cli;

// Strips recognized custom flags out of argv (compacting in place, updating
// argc) so the remainder can be handed to doctest::Context unmodified.
// Unrecognized args (including doctest's own, e.g. --test-case=...) are left
// untouched. Returns true if at least one custom flag was found.
bool parse_custom_args(int& argc, char** argv) {
    bool any = false;
    std::vector<char*> kept;
    kept.push_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--depth" && i + 1 < argc) {
            g_cli.depth = std::atoi(argv[++i]);
            any = true;
        } else if (a == "--count" && i + 1 < argc) {
            g_cli.count = std::atoi(argv[++i]);
            any = true;
        } else if (a == "--tree_height" && i + 1 < argc) {
            g_cli.tree_height = std::atoi(argv[++i]);
            any = true;
        } else if (a == "--performance_only") {
            g_cli.performance_only = true;
            any = true;
        } else if (a == "--system_only") {
            g_cli.system_only = true;
            any = true;
        } else {
            kept.push_back(argv[i]);
        }
    }
    argc = static_cast<int>(kept.size());
    for (int i = 0; i < argc; ++i) argv[i] = kept[i];
    return any;
}

std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> out;
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line)) out.push_back(line);
    return out;
}

// Splits on runs of 2+ spaces (the report's column separator), keeping any
// single embedded space (e.g. "[50, 150]") as part of one field.
std::vector<std::string> split_columns(const std::string& line) {
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && line[i] == ' ') ++i;
        if (i >= line.size()) break;
        std::size_t start = i;
        while (i < line.size()) {
            if (line[i] == ' ' && i + 1 < line.size() && line[i + 1] == ' ')
                break;
            ++i;
        }
        out.push_back(line.substr(start, i - start));
        while (i < line.size() && line[i] == ' ') ++i;
    }
    return out;
}

struct Table {
    std::vector<std::string> headers;
    std::vector<std::vector<std::string>> rows;

    std::string cell(const std::vector<std::string>& row,
                     const std::string& header) const {
        for (std::size_t i = 0; i < headers.size(); ++i)
            if (headers[i] == header) return i < row.size() ? row[i] : "";
        return "";
    }
};

// Parses one "=== <marker> (n) ===" section (Performance/System Anomalies)
// out of the anomaly report's lines, starting the scan at `line_marker`
// (e.g. "=== Performance Anomalies").
Table parse_section(const std::vector<std::string>& lines,
                    const std::string& line_marker) {
    Table t;
    std::size_t i = 0;
    for (; i < lines.size(); ++i)
        if (lines[i].rfind(line_marker, 0) == 0) break;
    if (i == lines.size()) return t;
    ++i;
    if (i >= lines.size() || lines[i] == "(none)") return t;
    t.headers = split_columns(lines[i]);
    ++i;
    if (i < lines.size() && lines[i].find("---") != std::string::npos) ++i;
    for (; i < lines.size(); ++i) {
        if (lines[i].empty() || lines[i].rfind("===", 0) == 0) break;
        t.rows.push_back(split_columns(lines[i]));
    }
    return t;
}

// ── Parameterized synthetic trace generator ─────────────────────────────────

enum class AnomalyKind { kPerf, kSys };

const char* to_string(AnomalyKind k) {
    return k == AnomalyKind::kPerf ? "perf" : "sys";
}

struct AnomalyRequest {
    AnomalyKind kind;
    int depth;  // >= 1; root's direct children are depth 1
};

struct Expected {
    std::string kind;  // "perf" or "sys"
    std::string name;
    std::string ancestor;
    int depth;
};

struct SynthesizedTrace {
    std::string json;
    std::vector<Expected> expected;
};

constexpr const char* kStableOpName = "stable_op";
constexpr long long kMargin = 1000;

void emit_event(std::ostringstream& out, const std::string& name,
                long long ts, long long dur) {
    out << "{\"name\":\"" << name
        << "\",\"cat\":\"X\",\"pid\":1,\"tid\":1,\"ts\":" << ts
        << ",\"dur\":" << dur << ",\"ph\":\"X\",\"args\":{}},\n";
}

// Emits `levels` nested single-child wrapper nodes inside [ts, ts+dur),
// named `prefix + "_L" + level` (level 1 = shallowest, a direct child of
// whatever contains [ts, ts+dur)). Returns the sub-range available for
// content placed inside the innermost wrapper (or the original range
// unchanged if levels == 0).
std::pair<long long, long long> emit_spine(std::ostringstream& out,
                                           const std::string& prefix,
                                           long long ts, long long dur,
                                           int levels) {
    long long cur_ts = ts, cur_dur = dur;
    for (int lvl = 1; lvl <= levels; ++lvl) {
        emit_event(out, prefix + "_L" + std::to_string(lvl), cur_ts, cur_dur);
        cur_ts += kMargin;
        cur_dur -= 2 * kMargin;
    }
    return {cur_ts, cur_dur};
}

// Builds one root tree containing a single injected anomaly at
// `req.depth`, padded with filler nesting so the tree reaches at least
// `tree_height`. Appends events to `out` and returns the ground-truth
// Expected entry. `root_ts` is the start of this root's private time range;
// `root_dur` must be large enough for the requested depth (the caller sizes
// it).
Expected build_anomaly_root(std::ostringstream& out, int root_index,
                            int tree_height, const AnomalyRequest& req,
                            long long root_ts, long long root_dur) {
    const std::string root_name = "root_" + std::to_string(root_index);
    emit_event(out, root_name, root_ts, root_dur);

    const int depth = std::max(1, req.depth);
    const int effective_height = std::max(tree_height, depth);

    auto [container_ts, container_dur] = emit_spine(
        out, root_name, root_ts + kMargin, root_dur - 2 * kMargin, depth - 1);

    const std::string node_name = "op_" + std::to_string(root_index);
    Expected expected{to_string(req.kind), node_name, root_name, depth};

    // The anomaly's own events use small fixed durations, independent of
    // the (depth/height-scaled) container size: only the *nesting* needs to
    // scale with depth, not the leaf durations, so this stays safely inside
    // the container regardless of how large container_dur is.
    long long cursor = container_ts;
    if (req.kind == AnomalyKind::kPerf) {
        constexpr long long kBase = 200;
        // 3 identical baseline occurrences (clarion_calltree's default
        // --anomaly-min-samples is 3, so the node needs at least that many
        // total samples before detection runs at all), then a spike well
        // outside any reasonable %-deviation threshold.
        for (int i = 0; i < 3; ++i) {
            emit_event(out, node_name, cursor, kBase);
            cursor += kBase + kMargin;
        }
        emit_event(out, node_name, cursor, kBase * 50);
        cursor += kBase * 50 + kMargin;
    } else {
        // One leaf occurrence, then one occurrence with an extra nested
        // child: same name, different subtree shape.
        constexpr long long kBase = 200;
        constexpr long long kOcc2Dur = 300;
        emit_event(out, node_name, cursor, kBase);
        cursor += kBase + kMargin;
        const long long occ2_ts = cursor;
        emit_event(out, node_name, occ2_ts, kOcc2Dur);
        emit_event(out, "extra_child_" + std::to_string(root_index),
                  occ2_ts + 50, 100);
        cursor = occ2_ts + kOcc2Dur + kMargin;
    }

    const int remaining_levels = effective_height - depth;
    if (remaining_levels > 0) {
        const long long filler_ts = cursor;
        const long long filler_dur = (container_ts + container_dur) - filler_ts;
        emit_spine(out, root_name + "_filler", filler_ts, filler_dur,
                  remaining_levels);
    }

    return expected;
}

// tree_height: minimum nesting depth of the "normal" skeleton beneath each
// anomaly (each request's own depth still wins if it's deeper). requests:
// one entry per anomaly to inject, each becoming its own root so anomalies
// never interact; the vector's length is "the number of anomalies".
SynthesizedTrace synthesize_trace(int tree_height,
                                  const std::vector<AnomalyRequest>& requests) {
    std::ostringstream j;
    j << "[\n";

    long long next_root_ts = 0;
    auto alloc_root_dur = [](int effective_height) {
        return static_cast<long long>(effective_height + 4) * 2000000LL;
    };

    // Fixed negative control: repeated identically, must never be flagged.
    {
        const long long dur = alloc_root_dur(std::max(tree_height, 1));
        emit_event(j, "root_stable", next_root_ts, dur);
        long long cursor = next_root_ts + kMargin;
        for (int i = 0; i < 4; ++i) {
            emit_event(j, kStableOpName, cursor, 20);
            cursor += 20 + kMargin;
        }
        next_root_ts += dur + kMargin;
    }

    std::vector<Expected> expected;
    expected.reserve(requests.size());
    for (std::size_t i = 0; i < requests.size(); ++i) {
        const AnomalyRequest& req = requests[i];
        const int effective_height =
            std::max(tree_height, std::max(1, req.depth));
        const long long dur = alloc_root_dur(effective_height);
        expected.push_back(build_anomaly_root(
            j, static_cast<int>(i), tree_height, req, next_root_ts, dur));
        next_root_ts += dur + kMargin;
    }

    std::string s = j.str();
    s.resize(s.size() - 2);  // drop trailing ",\n"
    s += "\n]\n";
    return {std::move(s), std::move(expected)};
}

// Runs clarion_calltree --detect-anomaly on `trace`, parses the resulting
// report, matches rows against `expected` by (kind, name, ancestor, depth),
// and asserts perfect detection with no false positives. Reports the
// accuracy breakdown via MESSAGE either way.
void run_and_check(const std::string& bin, const std::string& env_dir,
                   const SynthesizedTrace& synth,
                   const std::string& anomaly_threshold = "50") {
    std::string trace = env_dir + "/trace.pfw";
    REQUIRE(write_file(trace, synth.json));

    std::string out = env_dir + "/ct.txt";
    int rc = run_process(bin, {trace, "-a", "--detect-anomaly",
                               "--anomaly-threshold", anomaly_threshold, "-o",
                               out});
    CHECK(rc == 0);

    std::string report_path = env_dir + "/ct.anomalies.txt";
    REQUIRE(fs::exists(report_path));
    std::string report = read_file(report_path);
    REQUIRE(!report.empty());
    auto lines = split_lines(report);

    Table perf = parse_section(lines, "=== Performance Anomalies");
    Table sys = parse_section(lines, "=== System Anomalies");

    std::vector<bool> matched(synth.expected.size(), false);
    int false_positives = 0;

    auto match_rows = [&](const Table& t, const char* kind) {
        for (const auto& row : t.rows) {
            const std::string name = t.cell(row, "function");
            const std::string ancestor = t.cell(row, "ancestor");
            const int depth = std::stoi(t.cell(row, "depth"));
            bool row_matched = false;
            for (std::size_t i = 0; i < synth.expected.size(); ++i) {
                if (matched[i]) continue;
                const Expected& e = synth.expected[i];
                if (e.kind == kind && e.name == name &&
                    e.ancestor == ancestor && e.depth == depth) {
                    matched[i] = true;
                    row_matched = true;
                    break;
                }
            }
            if (!row_matched) {
                ++false_positives;
                MESSAGE("unexpected anomaly row: kind=", std::string(kind),
                       " name=", name, " ancestor=", ancestor,
                       " depth=", depth);
            }
            CHECK(name != kStableOpName);
        }
    };
    match_rows(perf, "perf");
    match_rows(sys, "sys");

    int true_positives = 0;
    for (std::size_t i = 0; i < synth.expected.size(); ++i) {
        if (matched[i]) {
            ++true_positives;
        } else {
            MESSAGE("missed injected anomaly: kind=", synth.expected[i].kind,
                   " name=", synth.expected[i].name,
                   " ancestor=", synth.expected[i].ancestor,
                   " depth=", synth.expected[i].depth);
        }
    }
    const int false_negatives =
        static_cast<int>(synth.expected.size()) - true_positives;
    const double recall = synth.expected.empty()
                              ? 1.0
                              : static_cast<double>(true_positives) /
                                    static_cast<double>(synth.expected.size());
    const int reported_total =
        static_cast<int>(perf.rows.size() + sys.rows.size());
    const double precision =
        reported_total > 0 ? static_cast<double>(true_positives) /
                                 static_cast<double>(reported_total)
                           : 1.0;

    MESSAGE("injected=", synth.expected.size(), " reported=", reported_total,
           " true_positives=", true_positives,
           " false_negatives=", false_negatives,
           " false_positives=", false_positives, " recall=", recall,
           " precision=", precision);

    CHECK(true_positives == static_cast<int>(synth.expected.size()));
    CHECK(false_negatives == 0);
    CHECK(false_positives == 0);
    CHECK(recall == doctest::Approx(1.0));
    CHECK(precision == doctest::Approx(1.0));
}

// ── FP/FN probes for the Performance Anomaly detector ───────────────────────
//
// Builds a single root containing one same-named child node repeated with
// exactly the given `durations`, in order, spaced far enough apart to nest
// cleanly. Unlike synthesize_trace (which builds whole trees with ground
// truth for the accuracy test above), this isolates the running-mean check
// to a single node so individual occurrence-by-occurrence behavior can be
// probed directly: does step N get flagged given only steps [0, N) as prior
// history?
std::string build_perf_sequence_trace(const std::string& root_name,
                                      const std::string& node_name,
                                      const std::vector<long long>& durations) {
    std::ostringstream j;
    j << "[\n";
    long long span = 4 * kMargin;
    for (long long d : durations) span += d + kMargin;
    emit_event(j, root_name, 0, span);
    long long cursor = kMargin;
    for (long long d : durations) {
        emit_event(j, node_name, cursor, d);
        cursor += d + kMargin;
    }
    std::string s = j.str();
    s.resize(s.size() - 2);
    s += "\n]\n";
    return s;
}

// Runs clarion_calltree over build_perf_sequence_trace's output and returns
// the parsed Performance Anomalies table (all rows -- there's only ever one
// node name/ancestor in these traces, so no further filtering is needed).
Table run_perf_sequence(const std::string& bin, const std::string& env_dir,
                        const std::string& root_name,
                        const std::string& node_name,
                        const std::vector<long long>& durations,
                        const std::string& threshold = "50",
                        const std::string& min_samples = "3",
                        const std::string& min_dur = "100") {
    std::string trace = env_dir + "/trace.pfw";
    REQUIRE(write_file(
        trace, build_perf_sequence_trace(root_name, node_name, durations)));
    std::string out = env_dir + "/ct.txt";
    int rc = run_process(bin, {trace, "-a", "--detect-anomaly",
                               "--anomaly-threshold", threshold,
                               "--anomaly-min-samples", min_samples,
                               "--anomaly-min-dur", min_dur, "-o", out});
    CHECK(rc == 0);
    std::string report = read_file(env_dir + "/ct.anomalies.txt");
    return parse_section(split_lines(report), "=== Performance Anomalies");
}

struct AccuracyResult {
    int injected = 0;
    int reported = 0;
    int true_positives = 0;
    int false_negatives = 0;
    int false_positives = 0;
};

// Matches reported anomaly rows against ground truth by (kind, name,
// ancestor, depth) -- the same matching rule run_and_check uses, factored
// out here so it can be applied across many trials without a per-trial
// doctest assertion (used by the randomized stress test below, where one
// bad trial shouldn't abort the other 99).
AccuracyResult score_against(const std::vector<Expected>& expected,
                             const Table& perf, const Table& sys) {
    AccuracyResult r;
    r.injected = static_cast<int>(expected.size());
    std::vector<bool> matched(expected.size(), false);
    auto match_rows = [&](const Table& t, const char* kind) {
        for (const auto& row : t.rows) {
            const std::string name = t.cell(row, "function");
            const std::string ancestor = t.cell(row, "ancestor");
            const int depth = std::stoi(t.cell(row, "depth"));
            bool row_matched = false;
            for (std::size_t i = 0; i < expected.size(); ++i) {
                if (matched[i]) continue;
                const Expected& e = expected[i];
                if (e.kind == kind && e.name == name &&
                    e.ancestor == ancestor && e.depth == depth) {
                    matched[i] = true;
                    row_matched = true;
                    break;
                }
            }
            if (!row_matched) ++r.false_positives;
        }
    };
    match_rows(perf, "perf");
    match_rows(sys, "sys");
    for (bool m : matched)
        if (m) ++r.true_positives;
    r.false_negatives = r.injected - r.true_positives;
    r.reported = static_cast<int>(perf.rows.size() + sys.rows.size());
    return r;
}

// Runs `synth` through clarion_calltree and scores the result.
AccuracyResult run_and_score(const std::string& bin, const std::string& env_dir,
                             const SynthesizedTrace& synth) {
    std::string trace = env_dir + "/trace.pfw";
    if (!write_file(trace, synth.json)) return {};
    std::string out = env_dir + "/ct.txt";
    int rc = run_process(
        bin, {trace, "-a", "--detect-anomaly", "--anomaly-threshold", "50",
              "-o", out});
    if (rc != 0) return {};
    std::string report = read_file(env_dir + "/ct.anomalies.txt");
    auto lines = split_lines(report);
    Table perf = parse_section(lines, "=== Performance Anomalies");
    Table sys = parse_section(lines, "=== System Anomalies");
    return score_against(synth.expected, perf, sys);
}

}  // namespace

TEST_SUITE("ClarionCallTreeAnomalyDetector") {
    TEST_CASE("binary exists") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: clarion_calltree binary not found");
            return;
        }
        CHECK(!bin.empty());
    }

    TEST_CASE("no --detect-anomaly produces no report file") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        auto synth = synthesize_trace(1, {{AnomalyKind::kPerf, 1}});
        std::string trace = env.get_dir() + "/trace.pfw";
        REQUIRE(write_file(trace, synth.json));

        std::string out = env.get_dir() + "/ct.txt";
        int rc = run_process(bin, {trace, "-a", "-o", out});
        CHECK(rc == 0);
        REQUIRE(fs::exists(out));
        CHECK_FALSE(fs::exists(env.get_dir() + "/ct.anomalies.txt"));
    }

    TEST_CASE("two anomalies of each kind at depths 1 and 2") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        auto synth = synthesize_trace(2, {{AnomalyKind::kPerf, 1},
                                          {AnomalyKind::kSys, 1},
                                          {AnomalyKind::kPerf, 2},
                                          {AnomalyKind::kSys, 2}});
        run_and_check(bin, env.get_dir(), synth);
    }

    TEST_CASE("adjustable count: many anomalies at varying depths") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        auto synth = synthesize_trace(
            1, {{AnomalyKind::kPerf, 1},
                {AnomalyKind::kPerf, 3},
                {AnomalyKind::kPerf, 5},
                {AnomalyKind::kSys, 2},
                {AnomalyKind::kSys, 4},
                {AnomalyKind::kSys, 6}});
        run_and_check(bin, env.get_dir(), synth);
    }

    TEST_CASE("adjustable tree height: shallow anomaly in a tall tree") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        // tree_height (10) far exceeds the anomalies' own depth (1): the
        // filler skeleton must not confuse detection or ancestor tracking.
        auto synth = synthesize_trace(
            10, {{AnomalyKind::kPerf, 1}, {AnomalyKind::kSys, 1}});
        run_and_check(bin, env.get_dir(), synth);
    }

    TEST_CASE("adjustable kind: all system anomalies") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        auto synth = synthesize_trace(3, {{AnomalyKind::kSys, 1},
                                          {AnomalyKind::kSys, 2},
                                          {AnomalyKind::kSys, 3}});
        run_and_check(bin, env.get_dir(), synth);
    }

    TEST_CASE("configurable via CLI") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());

        const int count = std::max(1, g_cli.count);
        const int depth = std::max(1, g_cli.depth);
        const int tree_height = std::max(1, g_cli.tree_height);

        std::vector<AnomalyRequest> requests;
        requests.reserve(count);
        for (int i = 0; i < count; ++i) {
            AnomalyKind kind;
            if (g_cli.performance_only) {
                kind = AnomalyKind::kPerf;
            } else if (g_cli.system_only) {
                kind = AnomalyKind::kSys;
            } else {
                kind = (i % 2 == 0) ? AnomalyKind::kPerf : AnomalyKind::kSys;
            }
            requests.push_back({kind, depth});
        }

        MESSAGE("CLI config: --count=", count, " --depth=", depth,
               " --tree_height=", tree_height,
               " --performance_only=", g_cli.performance_only,
               " --system_only=", g_cli.system_only);

        auto synth = synthesize_trace(tree_height, requests);
        run_and_check(bin, env.get_dir(), synth);
    }

    TEST_CASE("stress: 100 randomized graph/anomaly configurations") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }

        // Fixed seed: randomized inputs, but reproducible across runs and
        // machines -- a failure here should be re-runnable, not a flake.
        std::mt19937 rng(20260827);
        std::uniform_int_distribution<int> height_dist(1, 12);
        std::uniform_int_distribution<int> count_dist(1, 6);
        std::uniform_int_distribution<int> depth_dist(1, 15);
        std::uniform_int_distribution<int> kind_dist(0, 1);

        constexpr int kTrials = 100;
        AccuracyResult total;
        int perfect_trials = 0;
        int perf_injected = 0, sys_injected = 0;
        int min_height = height_dist.max(), max_height = height_dist.min();
        int min_depth = depth_dist.max(), max_depth = depth_dist.min();
        int deeper_than_tree = 0;  // depth > tree_height (filler-padded case)

        for (int trial = 0; trial < kTrials; ++trial) {
            const int tree_height = height_dist(rng);
            const int count = count_dist(rng);
            min_height = std::min(min_height, tree_height);
            max_height = std::max(max_height, tree_height);

            std::vector<AnomalyRequest> requests;
            requests.reserve(count);
            for (int i = 0; i < count; ++i) {
                const AnomalyKind kind = kind_dist(rng) == 0
                                            ? AnomalyKind::kPerf
                                            : AnomalyKind::kSys;
                const int depth = depth_dist(rng);
                requests.push_back({kind, depth});
                (kind == AnomalyKind::kPerf ? perf_injected : sys_injected)++;
                min_depth = std::min(min_depth, depth);
                max_depth = std::max(max_depth, depth);
                if (depth > tree_height) ++deeper_than_tree;
            }

            dft_utils_test::TestEnvironment env(1);
            REQUIRE(env.is_valid());
            auto synth = synthesize_trace(tree_height, requests);
            AccuracyResult r = run_and_score(bin, env.get_dir(), synth);

            total.injected += r.injected;
            total.reported += r.reported;
            total.true_positives += r.true_positives;
            total.false_negatives += r.false_negatives;
            total.false_positives += r.false_positives;

            const bool is_perfect =
                r.false_negatives == 0 && r.false_positives == 0;
            if (is_perfect) {
                ++perfect_trials;
            } else {
                MESSAGE("trial ", trial, " mismatch: tree_height=",
                       tree_height, " count=", count, " injected=",
                       r.injected, " reported=", r.reported, " tp=",
                       r.true_positives, " fn=", r.false_negatives, " fp=",
                       r.false_positives);
            }
        }

        MESSAGE("coverage: tree_height=[", min_height, ",", max_height,
               "] depth=[", min_depth, ",", max_depth, "] perf_injected=",
               perf_injected, " sys_injected=", sys_injected,
               " depth_exceeds_tree_height_count=", deeper_than_tree);

        const double recall =
            total.injected > 0 ? static_cast<double>(total.true_positives) /
                                     static_cast<double>(total.injected)
                              : 1.0;
        const double precision =
            total.reported > 0 ? static_cast<double>(total.true_positives) /
                                     static_cast<double>(total.reported)
                               : 1.0;

        MESSAGE(kTrials, " trials, ", perfect_trials,
               " perfect | injected=", total.injected, " reported=",
               total.reported, " true_positives=", total.true_positives,
               " false_negatives=", total.false_negatives,
               " false_positives=", total.false_positives, " recall=",
               recall, " precision=", precision);

        CHECK(perfect_trials == kTrials);
        CHECK(total.false_negatives == 0);
        CHECK(total.false_positives == 0);
        CHECK(recall == doctest::Approx(1.0));
        CHECK(precision == doctest::Approx(1.0));
    }
}

// Probes specific false-positive / false-negative failure modes of the
// Performance Anomaly detector's median-of-the-complete-sample-set
// approach, isolated to a single repeated node (see
// build_perf_sequence_trace). Detection only runs once all occurrences of a
// node have been collected, so there's no "warm-up" period during
// ingestion the way a running-mean design would have -- --anomaly-min-samples
// now guards a node never having enough *total* occurrences to establish a
// meaningful baseline at all, not "too early in the stream".
TEST_SUITE("ClarionCallTreeAnomalyDetectorFalsePosNeg") {
    TEST_CASE(
        "min samples: too few total occurrences stays quiet by default") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        // Only 2 total occurrences; the default --anomaly-min-samples (3)
        // means there's never enough data to establish a baseline, so
        // nothing is flagged regardless of how different the two values
        // are.
        auto t = run_perf_sequence(bin, env.get_dir(), "root_fp1", "op",
                                   {200, 400});
        MESSAGE("flagged rows: ", t.rows.size());
        CHECK(t.rows.empty());
    }

    TEST_CASE(
        "min samples disabled: a lone 2-point comparison still doesn't "
        "arbitrarily blame either side") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        // Same 200 -> 400 pair, but with --anomaly-min-samples dropped to 1
        // so the 2-occurrence baseline is no longer rejected outright. The
        // old running-mean design had a real false-positive bug here: it
        // treated whichever value arrived *first* as ground truth and
        // flagged the second purely for being different (see the "FP
        // reproduced" case this test replaces, from before the redesign).
        // The batch/median design has no such bias -- the median of exactly
        // two values is their average (300), and both 200 and 400 sit
        // equally (+-33%) either side of it, so neither one alone is
        // "the anomaly" and, under the default 50% threshold, neither gets
        // flagged. This isn't a gap: with only two data points and no other
        // information, correctly refusing to blame one of them arbitrarily
        // is the right call.
        auto t = run_perf_sequence(bin, env.get_dir(), "root_fp2", "op",
                                   {200, 400}, "50", "1");
        MESSAGE("flagged rows: ", t.rows.size());
        CHECK(t.rows.empty());
    }

    TEST_CASE(
        "true positive: spike is detected once enough total samples "
        "exist") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        // 3 identical baseline occurrences plus one spike: the median of
        // all 4 (200) is unmoved by the single outlier, so the spike is
        // clearly flagged against it while the 3 baseline points are not.
        auto t = run_perf_sequence(bin, env.get_dir(), "root_tp", "op",
                                   {200, 200, 200, 400});
        REQUIRE(t.rows.size() == 1);
        CHECK(t.cell(t.rows[0], "count") == "4");
        CHECK(t.cell(t.rows[0], "observed") == "400");
    }

    TEST_CASE(
        "threshold boundary: exactly at the threshold is not flagged "
        "(inclusive)") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        // mean=200, +50% threshold -> high=300 exactly; 300 must not tip
        // over into "flagged" (the check is observed > high, strictly).
        auto t = run_perf_sequence(bin, env.get_dir(), "root_boundary_at",
                                   "op", {200, 200, 200, 300});
        MESSAGE("flagged rows: ", t.rows.size());
        CHECK(t.rows.empty());
    }

    TEST_CASE("threshold boundary: just past the threshold is flagged") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        auto t = run_perf_sequence(bin, env.get_dir(), "root_boundary_over",
                                   "op", {200, 200, 200, 301});
        REQUIRE(t.rows.size() == 1);
        CHECK(t.cell(t.rows[0], "observed") == "301");
    }

    TEST_CASE(
        "FN: gradual drift evades detection despite large total change "
        "(boiling-frog blind spot)") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        // The median of this whole 13-sample set is 387 (the middle value),
        // and every single sample -- including the very first (200) and
        // very last (521, 2.6x the original baseline) -- sits within 50% of
        // that one median. So even with the *complete* distribution
        // available up front, nothing is ever flagged: this is a known,
        // real limitation of comparing against a single global baseline --
        // a gradual, monotonic drift can widen a node's own range without
        // any individual sample ever standing far enough from the middle of
        // it, regardless of --anomaly-threshold or --anomaly-min-samples.
        // Catching this specific shape would need an order-aware check
        // (e.g. trend/changepoint detection), not a distribution-based one.
        std::vector<long long> durations = {200, 200, 200, 294, 328, 359,
                                            387, 413, 437, 460, 481, 502,
                                            521};
        auto t = run_perf_sequence(bin, env.get_dir(), "root_drift", "op",
                                   durations);
        MESSAGE("flagged rows: ", t.rows.size(),
               " final/original duration ratio: ",
               static_cast<double>(durations.back()) / durations.front());
        CHECK(t.rows.empty());
    }

    TEST_CASE(
        "min duration: sub-threshold durations are ignored by default") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        // Trace timestamps are microsecond-resolution, so a 50 -> 5000 jump
        // at this scale is still well inside measurement noise, not a real
        // regression; the default --anomaly-min-dur (100) must keep it
        // quiet even though it's a massive %-deviation by any threshold.
        auto t = run_perf_sequence(bin, env.get_dir(), "root_mindur1", "op",
                                   {50, 50, 50, 5000});
        MESSAGE("flagged rows: ", t.rows.size());
        CHECK(t.rows.empty());
    }

    TEST_CASE(
        "min duration: adjustable via --anomaly-min-dur") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        // Same 50 -> 5000 sequence as above, but with --anomaly-min-dur
        // lowered to 10: now the baseline mean (50) clears the floor, so
        // the spike is checked (and flagged) like any other.
        auto t = run_perf_sequence(bin, env.get_dir(), "root_mindur2", "op",
                                   {50, 50, 50, 5000}, "50", "3", "10");
        REQUIRE(t.rows.size() == 1);
        CHECK(t.cell(t.rows[0], "observed") == "5000");
    }

    TEST_CASE(
        "suppression: a descendant anomaly nested inside a flagged parent "
        "is not reported") {
        std::string bin = find_binary();
        if (bin.empty()) {
            MESSAGE("skipping: binary not found");
            return;
        }
        dft_utils_test::TestEnvironment env(1);
        REQUIRE(env.is_valid());
        // 4 "outer" occurrences under one root, each wrapping 3 "inner"
        // calls (dur 200 each). The first 3 outer occurrences are entirely
        // quiet. The 4th nests its own 3-baseline-then-spike "inner"
        // sequence (200, 200, 200, 5000 -- enough to trip the detector on
        // "inner" by itself), and since duration here is inclusive, that
        // same spike also balloons outer's own total duration far past its
        // baseline, tripping the detector on "outer" too. Both genuinely
        // qualify on their own; once "outer" is flagged, the nested "inner"
        // finding (its descendant) must be suppressed from the report --
        // otherwise every performance anomaly would also be double (or
        // triply, or...) reported up its whole ancestor chain, since an
        // inclusive-duration spike always propagates upward.
        std::ostringstream j;
        j << "[\n";
        const std::string root_name = "root_suppress";
        const std::string outer_name = "outer";
        const std::string inner_name = "inner";
        constexpr long long kInnerBase = 200;
        constexpr long long kInnerSpike = 5000;

        long long cursor = kMargin;
        std::vector<std::pair<long long, long long>> outer_spans;

        auto emit_outer = [&](const std::vector<long long>& inner_durs) {
            const long long start = cursor;
            long long t = start;
            for (long long d : inner_durs) {
                emit_event(j, inner_name, t, d);
                t += d;
            }
            const long long dur = t - start;
            outer_spans.push_back({start, dur});
            cursor = start + dur + kMargin;
        };
        for (int i = 0; i < 3; ++i)
            emit_outer({kInnerBase, kInnerBase, kInnerBase});
        emit_outer({kInnerBase, kInnerBase, kInnerBase, kInnerSpike});

        const long long root_dur = cursor;
        emit_event(j, root_name, 0, root_dur);
        for (const auto& [ts, dur] : outer_spans) emit_event(j, outer_name, ts, dur);

        std::string s = j.str();
        s.resize(s.size() - 2);
        s += "\n]\n";

        std::string trace = env.get_dir() + "/trace.pfw";
        REQUIRE(write_file(trace, s));
        std::string out = env.get_dir() + "/ct.txt";
        int rc = run_process(bin, {trace, "-a", "--detect-anomaly",
                                   "--anomaly-threshold", "50", "-o", out});
        CHECK(rc == 0);

        std::string report = read_file(env.get_dir() + "/ct.anomalies.txt");
        auto lines = split_lines(report);
        Table perf = parse_section(lines, "=== Performance Anomalies");

        bool outer_flagged = false, inner_flagged = false;
        for (const auto& row : perf.rows) {
            const std::string name = perf.cell(row, "function");
            if (name == outer_name) outer_flagged = true;
            if (name == inner_name) inner_flagged = true;
        }
        MESSAGE("rows: ", perf.rows.size(), " outer_flagged=", outer_flagged,
               " inner_flagged=", inner_flagged);
        CHECK(outer_flagged);
        CHECK_FALSE(inner_flagged);
    }
}

int main(int argc, char** argv) {
    const bool custom_flag_given = parse_custom_args(argc, argv);
    doctest::Context context(argc, argv);
    // Custom flags (--depth, --count, --tree_height, --performance_only,
    // --system_only) only affect the "configurable via CLI" test case, so
    // giving one implies you only want that case to run -- no need to also
    // know about or pass doctest's own --test-case filter.
    if (custom_flag_given) context.setOption("test-case", "configurable via CLI");
    const int res = context.run();
    if (context.shouldExit()) return res;
    return res;
}
