// Integration test for `clarion_catalog knowledge`: writes two configuration
// subdirectories (one run each, the second with an extra child), runs the
// built binary, and checks that it tags the divergence in
// divergences_table.csv, lists both configurations in configuration_table.csv,
// and produces a non-empty knowledge_tree.pfw.gz. Mirrors the process-spawning
// pattern in test_clarion_calltree.cpp.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string find_binary() {
    const char* env_path = std::getenv("CLARION_CATALOG_PATH");
    if (env_path && ::access(env_path, X_OK) == 0) return env_path;
    for (const auto& p :
         {"./clarion_catalog", "../clarion_catalog", "../../clarion_catalog",
          "../bin/clarion_catalog", "../../bin/clarion_catalog"}) {
        if (::access(p, X_OK) == 0) return p;
    }
    return "";
}

// Run `binary args...`, redirecting stdout to `out_path` (when non-empty) and
// stderr to /dev/null. Returns the process exit code.
int run_process_to(const std::string& binary,
                   const std::vector<std::string>& args,
                   const std::string& out_path) {
    pid_t pid = ::fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        const int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDERR_FILENO);
            if (out_path.empty()) ::dup2(devnull, STDOUT_FILENO);
        }
        if (!out_path.empty()) {
            const int fd =
                ::open(out_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                ::dup2(fd, STDOUT_FILENO);
                ::close(fd);
            }
        }
        if (devnull >= 0) ::close(devnull);
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

int run_process(const std::string& binary,
                const std::vector<std::string>& args) {
    return run_process_to(binary, args, "");
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

long file_size(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return -1;
    return static_cast<long>(st.st_size);
}

// One subtree dump: root "A:0x1" with the given leaf children, each at depth 1.
std::string make_dump(const std::vector<std::string>& kids) {
    std::ostringstream os;
    os << "[\n";
    os << "{\"name\":\"A\",\"cat\":\"find\",\"pid\":0,\"tid\":0,\"ph\":\"M\"}\n";
    os << "{\"id\":0,\"name\":\"A:0x1\",\"cat\":\"h5d\",\"pid\":0,\"tid\":0,"
          "\"ts\":0,\"dur\":10,\"ph\":\"X\",\"args\":{\"count\":1,\"depth\":0}}\n";
    int ts = 0;
    for (const auto& k : kids) {
        os << "{\"id\":0,\"name\":\"" << k
           << "\",\"cat\":\"h5d\",\"pid\":0,\"tid\":0,\"ts\":" << ts
           << ",\"dur\":2,\"ph\":\"X\",\"args\":{\"count\":1,\"depth\":1}}\n";
        ts += 2;
    }
    os << "]\n";
    return os.str();
}

}  // namespace

TEST_CASE("knowledge tags a divergent child and writes the catalog tables") {
    const std::string bin = find_binary();
    REQUIRE_MESSAGE(!bin.empty(), "clarion_catalog binary not found");

    const std::string dir = "clarion_catalog_knowledge_test";
    const std::string in = dir + "/in";
    const std::string out = dir + "/out";
    const std::string cfg_a = in + "/cfgA";
    const std::string cfg_b = in + "/cfgB";
    ::mkdir(dir.c_str(), 0777);
    ::mkdir(in.c_str(), 0777);
    ::mkdir(cfg_a.c_str(), 0777);
    ::mkdir(cfg_b.c_str(), 0777);

    // Two configurations, one run each. cfgA sorts first and defines the
    // untagged baseline skeleton of API call "A"; cfgB adds the child "z:0x4",
    // which is tagged and appended. Node names have their ":0x<addr>" suffix
    // stripped on the way in, so the tables report the bare names "A" and "z".
    REQUIRE(write_file(cfg_a + "/run.pfw", make_dump({"x:0x2", "y:0x3"})));
    REQUIRE(
        write_file(cfg_b + "/run.pfw", make_dump({"x:0x2", "y:0x3", "z:0x4"})));

    const int rc = run_process(
        bin, {"knowledge", "-i", in, "--knowledge-output", out});
    CHECK(rc == 0);

    const std::string div = read_file(out + "/divergences_table.csv");
    REQUIRE_FALSE(div.empty());
    CHECK(div.find("tag_id,api_call,node,depth,branch_class,num_runs,configs") !=
          std::string::npos);
    // tag 0, API call "A", tagged node "z" at depth 1, under a
    // configuration-driven branch point, reached by one run of cfgB.
    CHECK(div.find("0,A,z,1,config-driven,1,cfgB,") != std::string::npos);

    const std::string cfg = read_file(out + "/configuration_table.csv");
    REQUIRE_FALSE(cfg.empty());
    CHECK(cfg.find("config,num_runs,api_calls,params") != std::string::npos);
    // Both configurations are listed, each with one run covering API call "A".
    CHECK(cfg.find("cfgA,1,A,") != std::string::npos);
    CHECK(cfg.find("cfgB,1,A,") != std::string::npos);

    // The knowledge tree is a non-empty gzip file.
    const long sz = file_size(out + "/knowledge_tree.pfw.gz");
    CHECK(sz > 0);
}

TEST_CASE("knowledge --mitigate recommends flight around a divergent node") {
    const std::string bin = find_binary();
    REQUIRE_MESSAGE(!bin.empty(), "clarion_catalog binary not found");

    const std::string dir = "clarion_catalog_mitigate_test";
    const std::string in = dir + "/in";
    const std::string out = dir + "/out";
    const std::string cfg_a = in + "/cfgA";
    const std::string cfg_b = in + "/cfgB";
    ::mkdir(dir.c_str(), 0777);
    ::mkdir(in.c_str(), 0777);
    ::mkdir(cfg_a.c_str(), 0777);
    ::mkdir(cfg_b.c_str(), 0777);

    // cfgA takes {x,y}; cfgB additionally calls the divergent node z. The two
    // configurations differ only in the parameter "mode", so "mode" explains
    // the configuration-driven branch at the root.
    REQUIRE(write_file(cfg_a + "/run.pfw", make_dump({"x:0x2", "y:0x3"})));
    REQUIRE(
        write_file(cfg_b + "/run.pfw", make_dump({"x:0x2", "y:0x3", "z:0x4"})));
    REQUIRE(write_file(dir + "/params.yaml",
                       "params:\n"
                       "  cfgA:\n    mode: a\n"
                       "  cfgB:\n    mode: b\n"));

    // Mitigate the anomalous node A/z observed in cfgB. cfgA never reaches a
    // node named z, so flight should recommend switching to it.
    const std::string log = dir + "/mitigate.out";
    const int rc = run_process_to(
        bin,
        {"knowledge", "-i", in, "--knowledge-output", out, "--params",
         dir + "/params.yaml", "--mitigate", "A/z", "--mitigate-config",
         "cfgB"},
        log);
    CHECK(rc == 0);

    const std::string text = read_file(log);
    REQUIRE_FALSE(text.empty());
    CHECK(text.find("Mitigation for A/z") != std::string::npos);
    CHECK(text.find("Flight") != std::string::npos);
    // cfgA is the alternative that avoids z, reached by changing mode.
    CHECK(text.find("cfgA") != std::string::npos);
    CHECK(text.find("mode=a") != std::string::npos);

    // The resolved parameter now appears in the configuration table too.
    const std::string cfg = read_file(out + "/configuration_table.csv");
    CHECK(cfg.find("mode=a") != std::string::npos);
    CHECK(cfg.find("mode=b") != std::string::npos);
}
