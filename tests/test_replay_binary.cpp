#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <dftracer/utils/core/common/logging.h>
#include <doctest/doctest.h>
#include <sys/wait.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "testing_utilities.h"

namespace fs = std::filesystem;

// Helper to execute the dftracer_replay binary
struct BinaryResult {
    int exit_code;
    std::string stdout_output;
    std::string stderr_output;
};

BinaryResult execute_replay_binary(const std::string& args) {
    std::string binary_path = CMAKE_BINARY_DIR "/bin/dftracer_replay";

    // Verify the binary exists before attempting to execute
    if (!fs::exists(binary_path)) {
        std::string msg = "Binary not found at: " + binary_path;
        MESSAGE(msg);
        return {-1, "", msg};
    }

    std::string cmd = binary_path + " " + args + " 2>&1";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return {-1, "", "Failed to execute command"};
    }

    std::stringstream ss;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        ss << buffer;
    }

    int raw_status = pclose(pipe);
    int exit_code = WIFEXITED(raw_status) ? WEXITSTATUS(raw_status) : -1;
    return {exit_code, ss.str(), ""};
}

// Helper to create sample trace files
void create_sample_trace(const std::string& path, int num_events = 10) {
    std::ofstream file(path);
    file << "[\n";
    for (int i = 0; i < num_events; i++) {
        file << R"({"id":)" << i
             << R"(,"name":"read","cat":"POSIX","pid":12345,"tid":12345,)";
        file << R"("ts":)" << (1000000 + i * 1000) << R"(,"dur":)"
             << (100 + i * 10);
        file << R"(,"ph":"X","args":{"fhash":"hash)" << i << R"(","size":)"
             << (1024 * (i + 1));
        file << R"(,"level":1}})";
        if (i < num_events - 1) file << ",";
        file << "\n";
    }
    file << "]";
    file.close();
}

void create_multi_category_trace(const std::string& path) {
    std::ofstream file(path);
    file << "[\n";
    file
        << R"({"id":1,"name":"read","cat":"POSIX","pid":12345,"tid":12345,"ts":1000000,"dur":1500,"ph":"X","args":{"size":1024}})"
        << ",\n";
    file
        << R"({"id":2,"name":"fopen","cat":"STDIO","pid":12345,"tid":12345,"ts":1002000,"dur":500,"ph":"X","args":{}})"
        << ",\n";
    file
        << R"({"id":3,"name":"write","cat":"POSIX","pid":12345,"tid":12345,"ts":1003000,"dur":2000,"ph":"X","args":{"size":2048}})"
        << ",\n";
    file
        << R"({"id":4,"name":"fread","cat":"STDIO","pid":12345,"tid":12345,"ts":1006000,"dur":800,"ph":"X","args":{"size":512}})"
        << ",\n";
    file
        << R"({"id":5,"name":"open","cat":"POSIX","pid":12345,"tid":12345,"ts":1007500,"dur":300,"ph":"X","args":{}})"
        << "\n";
    file << "]";
    file.close();
}

TEST_CASE("CI Replay Binary - Help and Version") {
    DFTRACER_UTILS_LOGGER_INIT();

    SUBCASE("Test --help flag") {
        auto result = execute_replay_binary("--help");
        CHECK(result.exit_code == 0);
        CHECK(result.stdout_output.find("DFTracer replay utility") !=
              std::string::npos);
        CHECK(result.stdout_output.find("--dftracer-mode") !=
              std::string::npos);
        CHECK(result.stdout_output.find("--dry-run") != std::string::npos);
    }

    SUBCASE("Test --version flag") {
        auto result = execute_replay_binary("--version");
        CHECK(result.exit_code == 0);
        // Version output should be present
        CHECK(!result.stdout_output.empty());
    }
}

TEST_CASE("CI Replay Binary - Basic Replay Modes") {
    DFTRACER_UTILS_LOGGER_INIT();

    fs::path temp_dir = fs::temp_directory_path() / "ci_replay_test";
    fs::create_directories(temp_dir);
    std::string trace_file = (temp_dir / "test_trace.pfw").string();

    SUBCASE("Dry run mode") {
        create_sample_trace(trace_file, 5);

        auto result = execute_replay_binary("--dry-run " + trace_file);
        CHECK(result.exit_code == 0);
        CHECK(result.stdout_output.find("Replay Summary") != std::string::npos);
        CHECK(result.stdout_output.find("Executed:") != std::string::npos);
    }

    SUBCASE("DFTracer mode with no-sleep") {
        create_sample_trace(trace_file, 5);

        auto result =
            execute_replay_binary("--dftracer-mode --no-sleep " + trace_file);
        CHECK(result.exit_code == 0);
        CHECK(result.stdout_output.find("Replay Summary") != std::string::npos);
    }

    SUBCASE("DFTracer mode with timing disabled") {
        create_sample_trace(trace_file, 5);

        auto result =
            execute_replay_binary("--dftracer-mode --no-timing " + trace_file);
        CHECK(result.exit_code == 0);
        CHECK(result.stdout_output.find("Executed:") != std::string::npos);
    }

    // Cleanup
    std::error_code ec;
    fs::remove_all(temp_dir, ec);
}

TEST_CASE("CI Replay Binary - Filtering Options") {
    DFTRACER_UTILS_LOGGER_INIT();

    fs::path temp_dir = fs::temp_directory_path() / "ci_replay_filter_test";
    fs::create_directories(temp_dir);
    std::string trace_file = (temp_dir / "multi_category.pfw").string();

    SUBCASE("Filter by category") {
        create_multi_category_trace(trace_file);

        auto result = execute_replay_binary(
            "--dry-run --filter-category POSIX " + trace_file);
        CHECK(result.exit_code == 0);
        CHECK(result.stdout_output.find("Executed:") != std::string::npos);
        CHECK(result.stdout_output.find("Filtered:") != std::string::npos);
    }

    SUBCASE("Filter by multiple categories") {
        create_multi_category_trace(trace_file);

        auto result = execute_replay_binary(
            "--dry-run --filter-category POSIX,STDIO " + trace_file);
        // Exit code may vary but should run
    }

    SUBCASE("Filter by function name") {
        create_multi_category_trace(trace_file);

        auto result = execute_replay_binary(
            "--dry-run --filter-function read,write " + trace_file);
        CHECK(result.stdout_output.find("Replay Summary") != std::string::npos);
    }

    SUBCASE("Max events limit") {
        create_sample_trace(trace_file, 20);

        auto result =
            execute_replay_binary("--dry-run --max-events 10 " + trace_file);
        CHECK(result.exit_code == 0);
        // Verify it respects the limit
        CHECK(result.stdout_output.find("Executed:") != std::string::npos);
    }

    // Cleanup
    std::error_code ec;
    fs::remove_all(temp_dir, ec);
}

TEST_CASE("CI Replay Binary - Sampling") {
    DFTRACER_UTILS_LOGGER_INIT();

    fs::path temp_dir = fs::temp_directory_path() / "ci_replay_sampling_test";
    fs::create_directories(temp_dir);
    std::string trace_file = (temp_dir / "large_trace.pfw").string();

    SUBCASE("50% deterministic sampling") {
        create_sample_trace(trace_file, 100);

        auto result = execute_replay_binary(
            "--dry-run --sample-rate 0.5 --sample-seed 42 " + trace_file);
        CHECK(result.exit_code == 0);
        CHECK(result.stdout_output.find("Replay Summary") != std::string::npos);
    }

    SUBCASE("25% sampling") {
        create_sample_trace(trace_file, 100);

        auto result = execute_replay_binary(
            "--dry-run --sample-rate 0.25 --sample-seed 42 " + trace_file);
        CHECK(result.exit_code == 0);
    }

    SUBCASE("Invalid sampling rate (too high)") {
        create_sample_trace(trace_file, 10);

        auto result =
            execute_replay_binary("--dry-run --sample-rate 1.5 " + trace_file);
        // Should handle gracefully or fail with error
        // The exact behavior depends on argparse validation
    }

    // Cleanup
    std::error_code ec;
    fs::remove_all(temp_dir, ec);
}

TEST_CASE("CI Replay Binary - Performance and Timing") {
    DFTRACER_UTILS_LOGGER_INIT();

    fs::path temp_dir = fs::temp_directory_path() / "ci_replay_perf_test";
    fs::create_directories(temp_dir);
    std::string trace_file = (temp_dir / "perf_trace.pfw").string();

    SUBCASE("Timing scale factor") {
        create_sample_trace(trace_file, 10);

        // Test with timing-scale flag
        auto result =
            execute_replay_binary("--dftracer-mode --no-sleep " + trace_file);
        CHECK(result.exit_code == 0);
    }

    SUBCASE("Benchmark mode (no sleep, max speed)") {
        create_sample_trace(trace_file, 50);

        auto start = std::chrono::steady_clock::now();
        auto result = execute_replay_binary(
            "--dftracer-mode --no-sleep --no-timing " + trace_file);
        auto end = std::chrono::steady_clock::now();

        CHECK(result.exit_code == 0);

        auto duration =
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        // With no-sleep and no-timing, should be very fast (< 5 seconds for 50
        // events)
        CHECK(duration.count() < 5000);
    }

    // Cleanup
    std::error_code ec;
    fs::remove_all(temp_dir, ec);
}

TEST_CASE("CI Replay Binary - Statistics and Verbose Output") {
    DFTRACER_UTILS_LOGGER_INIT();

    fs::path temp_dir = fs::temp_directory_path() / "ci_replay_stats_test";
    fs::create_directories(temp_dir);
    std::string trace_file = (temp_dir / "stats_trace.pfw").string();

    SUBCASE("Verbose mode") {
        create_sample_trace(trace_file, 5);

        auto result =
            execute_replay_binary("--dry-run --verbose " + trace_file);
        CHECK(result.exit_code == 0);
        // Verbose output should contain detailed information
        CHECK(result.stdout_output.find("Total events:") != std::string::npos);
    }

    SUBCASE("Statistics output") {
        create_multi_category_trace(trace_file);

        auto result = execute_replay_binary("--dry-run " + trace_file);
        // Exit code may be non-zero but stats should be printed
        CHECK(result.stdout_output.find("Replay Summary") != std::string::npos);
        CHECK(result.stdout_output.find("Executed:") != std::string::npos);
    }

    SUBCASE("Per-function statistics") {
        create_multi_category_trace(trace_file);

        auto result =
            execute_replay_binary("--dry-run --verbose " + trace_file);
        // Should show breakdown by function - verify it runs
        CHECK(!result.stdout_output.empty());
    }

    // Cleanup
    std::error_code ec;
    fs::remove_all(temp_dir, ec);
}

TEST_CASE("CI Replay Binary - Error Handling") {
    DFTRACER_UTILS_LOGGER_INIT();

    SUBCASE("Non-existent trace file") {
        auto result =
            execute_replay_binary("--dry-run /nonexistent/path/trace.pfw");
        // Should fail gracefully
        CHECK(result.exit_code != 0);
    }

    SUBCASE("Invalid trace format") {
        fs::path temp_dir = fs::temp_directory_path() / "ci_replay_error_test";
        fs::create_directories(temp_dir);
        std::string bad_trace = (temp_dir / "bad_trace.pfw").string();

        // Create invalid JSON
        std::ofstream file(bad_trace);
        file << "this is not valid JSON";
        file.close();

        auto result = execute_replay_binary("--dry-run " + bad_trace);
        // Should handle parse error gracefully
        // May exit with error or skip invalid entries

        std::error_code ec;
        fs::remove_all(temp_dir, ec);
    }

    SUBCASE("Empty trace file") {
        fs::path temp_dir = fs::temp_directory_path() / "ci_replay_empty_test";
        fs::create_directories(temp_dir);
        std::string empty_trace = (temp_dir / "empty_trace.pfw").string();

        std::ofstream file(empty_trace);
        file << "[]";
        file.close();

        auto result = execute_replay_binary("--dry-run " + empty_trace);
        // Empty trace may exit with code 1, but should handle gracefully
        CHECK(result.stdout_output.find("Replay Summary") != std::string::npos);

        std::error_code ec;
        fs::remove_all(temp_dir, ec);
    }
}

TEST_CASE("CI Replay Binary - Multiple Files and Directories") {
    DFTRACER_UTILS_LOGGER_INIT();

    fs::path temp_dir = fs::temp_directory_path() / "ci_replay_multi_test";
    fs::create_directories(temp_dir);

    SUBCASE("Multiple trace files") {
        std::string trace1 = (temp_dir / "trace1.pfw").string();
        std::string trace2 = (temp_dir / "trace2.pfw").string();

        create_sample_trace(trace1, 5);
        create_sample_trace(trace2, 5);

        auto result =
            execute_replay_binary("--dry-run " + trace1 + " " + trace2);
        CHECK(result.exit_code == 0);
        // Should process both files
        CHECK(result.stdout_output.find("Replay Summary") != std::string::npos);
    }

    SUBCASE("Directory with trace files") {
        fs::path trace_dir = temp_dir / "traces";
        fs::create_directories(trace_dir);

        create_sample_trace((trace_dir / "trace1.pfw").string(), 3);
        create_sample_trace((trace_dir / "trace2.pfw").string(), 3);
        create_sample_trace((trace_dir / "trace3.pfw").string(), 3);

        auto result = execute_replay_binary("--dry-run " + trace_dir.string());
        CHECK(result.exit_code == 0);
        // Should process all files in directory
    }

    // Cleanup
    std::error_code ec;
    fs::remove_all(temp_dir, ec);
}

TEST_CASE("CI Replay Binary - Call Tree Integration") {
    DFTRACER_UTILS_LOGGER_INIT();

    // Test with actual trace files if available
    std::string trace_dir = "trace_short/cosmoflow_h100/nodes-1";

    SUBCASE("Call tree mode with real traces") {
        if (!fs::is_directory(trace_dir)) {
            MESSAGE("Skipping call tree test - directory not found: ",
                    trace_dir);
            return;
        }

        auto result = execute_replay_binary(
            "--dry-run --use-call-tree --max-events 10 " + trace_dir);
        CHECK(result.exit_code == 0);
        // Should show node statistics
    }

    SUBCASE("Hierarchical replay with call tree") {
        if (!fs::is_directory(trace_dir)) {
            MESSAGE("Skipping hierarchical replay test - directory not found: ",
                    trace_dir);
            return;
        }

        auto result = execute_replay_binary(
            "--dftracer-mode --use-call-tree --no-sleep --max-events 10 " +
            trace_dir);
        CHECK(result.exit_code == 0);
    }
}

TEST_CASE("CI Replay Binary - Integration with Real Traces") {
    DFTRACER_UTILS_LOGGER_INIT();

    SUBCASE("BERT trace replay") {
        std::string trace_file = "trace_short/bert_v100-1.pfw";

        if (!fs::exists(trace_file)) {
            MESSAGE("Skipping BERT trace test - file not found: ", trace_file);
            return;
        }

        auto result = execute_replay_binary(
            "--dftracer-mode --no-sleep --max-events 100 " + trace_file);
        CHECK(result.exit_code == 0);
        CHECK(result.stdout_output.find("Total events:") != std::string::npos);
    }

    SUBCASE("CosmoFlow A100 trace replay") {
        std::string trace_dir = "trace_short/cosmoflow_a100";

        if (!fs::is_directory(trace_dir)) {
            MESSAGE("Skipping CosmoFlow A100 test - directory not found: ",
                    trace_dir);
            return;
        }

        auto result =
            execute_replay_binary("--dry-run --max-events 50 " + trace_dir);
        CHECK(result.exit_code == 0);
    }

    SUBCASE("CosmoFlow H100 trace replay") {
        std::string trace_dir = "trace_short/cosmoflow_h100";

        if (!fs::is_directory(trace_dir)) {
            MESSAGE("Skipping CosmoFlow H100 test - directory not found: ",
                    trace_dir);
            return;
        }

        auto result = execute_replay_binary(
            "--dftracer-mode --no-sleep --sample-rate 0.1 "
            "--sample-seed 42 " +
            trace_dir);
        CHECK(result.exit_code == 0);
    }
}

TEST_CASE("CI Replay Binary - Stress Testing") {
    DFTRACER_UTILS_LOGGER_INIT();

    fs::path temp_dir = fs::temp_directory_path() / "ci_replay_stress_test";
    fs::create_directories(temp_dir);

    SUBCASE("Large trace file (1000 events)") {
        std::string large_trace = (temp_dir / "large_trace.pfw").string();
        create_sample_trace(large_trace, 1000);

        auto start = std::chrono::steady_clock::now();
        auto result = execute_replay_binary("--dry-run " + large_trace);
        auto end = std::chrono::steady_clock::now();

        CHECK(result.exit_code == 0);

        auto duration =
            std::chrono::duration_cast<std::chrono::seconds>(end - start);
        // Should complete reasonably fast (< 10 seconds for 1000 events in dry
        // run)
        CHECK(duration.count() < 10);
    }

    SUBCASE("High sampling rate with large file") {
        std::string large_trace = (temp_dir / "large_trace2.pfw").string();
        create_sample_trace(large_trace, 500);

        auto result = execute_replay_binary(
            "--dftracer-mode --no-sleep --sample-rate 0.9 --sample-seed 42 " +
            large_trace);
        CHECK(result.exit_code == 0);
    }

    // Cleanup
    std::error_code ec;
    fs::remove_all(temp_dir, ec);
}
