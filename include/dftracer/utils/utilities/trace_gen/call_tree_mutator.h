#ifndef DFTRACER_UTILS_UTILITIES_TRACE_GEN_CALL_TREE_MUTATOR_H
#define DFTRACER_UTILS_UTILITIES_TRACE_GEN_CALL_TREE_MUTATOR_H

#include <dftracer/utils/utilities/common/json/parser.h>
#include <dftracer/utils/utilities/composites/dft/event.h>
#include <zlib.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <map>
#include <numeric>
#include <string>
#include <tuple>
#include <vector>

// Call-tree trace mutation.
//
// Given an existing DFTracer trace (.pfw or .pfw.gz), apply two independent,
// composable mutations and write the result to a new file (the input is never
// modified):
//
//   1. Rename M nodes ("changes"). The chosen nodes are renamed to
//      "<name_prefix><i>" (i = 1..M). By default the M nodes are spread evenly
//      across the trace in file order; with change_depth >= 0 only nodes at
//      that call-tree depth (derived from ts/dur containment) are eligible, so
//      the renames can be
//      aimed at one level at a time. The root (depth 0) is never picked unless
//      it is the only eligible node.
//
//   2. Remove N whole subtrees ("removals"). N non-overlapping subtree roots
//      are picked, spread across depths (never the root), and each chosen node
//      together with every descendant (every event whose [ts, ts+dur] is
//      contained in the root's interval, same pid/tid) is deleted. Each removal
//      shows up in the comparator as one divergent_a subtree.
//
// Every byte of every surviving, unchanged event is preserved verbatim; only
// the chosen nodes' "name" value changes and removed events' lines are dropped.
namespace dftracer::utils::utilities::trace_gen {

struct MutateConfig {
    // Number of nodes to rename. 0 disables renaming.
    std::size_t num_changes = 1;

    // Base name given to each renamed node; the 1-based change index is
    // appended (e.g. "mutated1", "mutated2", ...).
    std::string name_prefix = "mutated";

    // Call-tree depth (args.level) the renames target. -1 means "any depth"
    // (the renames are spread evenly across all events in file order); a value
    // >= 0 restricts the eligible nodes to exactly that level.
    int change_depth = -1;

    // Number of whole subtrees to remove, spread across depths. 0 disables
    // removal. Never removes the root.
    std::size_t num_removals = 0;

    // When true (with change_depth < 0), renames are spread across every depth
    // EXCEPT the root level (depth 0). Lets a trace be mutated evenly through
    // depths 1..N without touching the roots.
    bool exclude_root = false;
};

struct MutateResult {
    bool ok = false;
    std::size_t changed = 0;          // nodes actually renamed
    std::size_t total_events = 0;     // complete (ph:"X") events in the input
    std::size_t step = 0;             // spacing between renamed events
    std::size_t removed_subtrees = 0; // subtree roots actually removed
    std::size_t removed_events = 0;   // events deleted (roots + descendants)
    std::string error;                // human-readable reason when !ok
};

namespace detail {

using common::json::JsonParser;
using composites::dft::DFTracerEvent;

// One parsed complete event, with the fields the mutator reasons about.
struct EventRef {
    std::size_t line_index = 0;  // index into the raw `lines` vector
    std::string name;            // event name (value of "name")
    std::uint64_t ts = 0;        // start timestamp
    std::uint64_t te = 0;        // end timestamp (ts + dur)
    int level = 0;               // call-tree depth (args.level)
    std::uint64_t group = 0;     // (pid, tid) bucket, nesting never crosses it
};

// Read a whole trace file into memory, transparently decompressing gzip.
// zlib's gzread also reads uncompressed files, so this handles .pfw and
// .pfw.gz alike.
inline bool slurp(const std::string& path, std::string& out) {
    gzFile f = gzopen(path.c_str(), "rb");
    if (f == nullptr) return false;
    char buf[1 << 16];
    int n = 0;
    while ((n = gzread(f, buf, sizeof(buf))) > 0)
        out.append(buf, static_cast<std::size_t>(n));
    const bool ok = (n == 0);  // 0 => clean EOF; <0 => read error
    gzclose(f);
    return ok;
}

inline std::string_view trim(std::string_view s) {
    std::size_t b = 0;
    std::size_t e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r'))
        --e;
    if (e > b && s[e - 1] == ',') --e;  // drop a trailing comma
    return s.substr(b, e - b);
}

// Replace the first `"name":"<old>"` occurrence in `line` with the new value.
inline void set_name(std::string& line, const std::string& old_value,
                     const std::string& new_value) {
    const std::string needle = "\"name\":\"" + old_value + "\"";
    const std::size_t pos = line.find(needle);
    if (pos == std::string::npos) return;
    const std::string replacement = "\"name\":\"" + new_value + "\"";
    line.replace(pos, needle.size(), replacement);
}

}  // namespace detail

// Read in_path, apply the renames and/or removals described by cfg, and write
// the result to out_path (gzip-compressed when gzip_out is true). in_path is
// never modified.
inline MutateResult mutate_call_tree_trace(const std::string& in_path,
                                           const std::string& out_path,
                                           const MutateConfig& cfg,
                                           bool gzip_out) {
    using namespace detail;
    MutateResult result;

    if (cfg.num_changes == 0 && cfg.num_removals == 0) {
        result.error = "nothing to do: num_changes and num_removals are both 0";
        return result;
    }

    std::string content;
    if (!slurp(in_path, content)) {
        result.error = "could not read input file: " + in_path;
        return result;
    }

    // Split into raw lines (verbatim, without the trailing newline).
    std::vector<std::string> lines;
    {
        std::size_t start = 0;
        while (start <= content.size()) {
            std::size_t nl = content.find('\n', start);
            if (nl == std::string::npos) {
                if (start < content.size())
                    lines.emplace_back(content.substr(start));
                break;
            }
            lines.emplace_back(content.substr(start, nl - start));
            start = nl + 1;
        }
    }

    // Collect complete events in file order, with timing/depth/group.
    std::vector<EventRef> events;
    JsonParser parser;
    for (std::size_t li = 0; li < lines.size(); ++li) {
        std::string_view tv = trim(lines[li]);
        if (tv.empty() || tv == "[" || tv == "]") continue;
        if (!parser.parse(tv)) continue;
        DFTracerEvent ev;
        if (!DFTracerEvent::parse_ondemand(parser, ev)) continue;
        if (!ev.is_complete()) continue;  // skip metadata / counters

        std::uint64_t tid = ev.tid;
        if (auto p = ev.args["tid"]) tid = p.get<std::uint64_t>();

        EventRef e;
        e.line_index = li;
        e.name.assign(ev.name.data(), ev.name.size());
        e.ts = ev.ts;
        e.te = ev.ts + ev.dur;
        e.level = 0;  // filled below from containment
        e.group = (ev.pid << 20) ^ tid;
        events.push_back(std::move(e));
    }

    result.total_events = events.size();
    if (events.empty()) {
        result.error = "input trace has no complete events";
        return result;
    }

    // Derive each event's call-tree depth from ts/dur containment, per
    // (pid, tid) group. This mirrors exactly how the comparator rebuilds the
    // tree, and works on real traces that carry no explicit args.level: an
    // event's depth is the number of still-open ancestors whose interval
    // [ts, te] contains it. (args.level, when present, equals this anyway.)
    {
        std::map<std::uint64_t, std::vector<std::size_t>> groups;
        for (std::size_t i = 0; i < events.size(); ++i)
            groups[events[i].group].push_back(i);
        for (auto& kv : groups) {
            std::vector<std::size_t>& idx = kv.second;
            std::sort(idx.begin(), idx.end(),
                      [&](std::size_t a, std::size_t b) {
                          if (events[a].ts != events[b].ts)
                              return events[a].ts < events[b].ts;
                          return events[a].te > events[b].te;
                      });
            std::vector<std::uint64_t> stack;  // te of open ancestors
            for (std::size_t i : idx) {
                while (!stack.empty() && stack.back() < events[i].te)
                    stack.pop_back();
                events[i].level = static_cast<int>(stack.size());
                stack.push_back(events[i].te);
            }
        }
    }

    // Tracks which raw lines are deleted by removal.
    std::vector<char> removed(lines.size(), 0);

    // ---- Removal: pick N non-overlapping subtree roots, spread by depth. ----
    if (cfg.num_removals > 0) {
        // Candidate roots grouped by depth (never the root, level 0).
        std::map<int, std::vector<std::size_t>> by_level;
        for (std::size_t i = 0; i < events.size(); ++i)
            if (events[i].level >= 1) by_level[events[i].level].push_back(i);

        std::vector<const std::vector<std::size_t>*> levels;
        std::vector<std::size_t> cursor;
        for (const auto& kv : by_level) {
            levels.push_back(&kv.second);
            cursor.push_back(0);
        }

        // Round-robin across depths, taking the next non-overlapping candidate
        // from each level in turn until N roots are chosen or none remain.
        std::vector<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>>
            picked;  // (group, ts, te) of accepted roots
        std::vector<std::size_t> roots;
        bool progress = true;
        while (roots.size() < cfg.num_removals && progress) {
            progress = false;
            for (std::size_t l = 0;
                 l < levels.size() && roots.size() < cfg.num_removals; ++l) {
                const std::vector<std::size_t>& v = *levels[l];
                while (cursor[l] < v.size()) {
                    const EventRef& e = events[v[cursor[l]++]];
                    bool overlap = false;
                    for (const auto& p : picked) {
                        if (std::get<0>(p) == e.group && e.ts < std::get<2>(p) &&
                            std::get<1>(p) < e.te) {
                            overlap = true;
                            break;
                        }
                    }
                    if (overlap) continue;
                    picked.emplace_back(e.group, e.ts, e.te);
                    roots.push_back(v[cursor[l] - 1]);
                    progress = true;
                    break;
                }
            }
        }

        // Mark each chosen root's whole subtree for deletion. Events sorted by
        // (group, ts) make each subtree a contiguous ts-range: within a group
        // the Euler-tour nesting guarantees every event with ts in
        // [root.ts, root.te] is a descendant (its te <= root.te).
        std::vector<std::size_t> order(events.size());
        std::iota(order.begin(), order.end(), 0);
        std::sort(order.begin(), order.end(),
                  [&](std::size_t a, std::size_t b) {
                      if (events[a].group != events[b].group)
                          return events[a].group < events[b].group;
                      return events[a].ts < events[b].ts;
                  });
        for (std::size_t ri : roots) {
            const EventRef& r = events[ri];
            auto lo = std::lower_bound(
                order.begin(), order.end(), r,
                [&](std::size_t idx, const EventRef& key) {
                    if (events[idx].group != key.group)
                        return events[idx].group < key.group;
                    return events[idx].ts < key.ts;
                });
            for (auto it = lo; it != order.end(); ++it) {
                const EventRef& e = events[*it];
                if (e.group != r.group || e.ts > r.te) break;
                if (!removed[e.line_index]) {
                    removed[e.line_index] = 1;
                    ++result.removed_events;
                }
            }
        }
        result.removed_subtrees = roots.size();
    }

    // ---- Rename: M eligible nodes, evenly spaced. ----
    if (cfg.num_changes > 0) {
        std::vector<std::size_t> cand;  // indices into `events`
        cand.reserve(events.size());
        for (std::size_t i = 0; i < events.size(); ++i) {
            if (removed[events[i].line_index]) continue;
            if (cfg.change_depth >= 0 && events[i].level != cfg.change_depth)
                continue;
            if (cfg.exclude_root && events[i].level == 0) continue;
            cand.push_back(i);
        }

        if (cand.empty()) {
            result.error =
                cfg.change_depth >= 0
                    ? "no events at --change-depth " +
                          std::to_string(cfg.change_depth)
                    : "no events eligible for renaming";
            return result;
        }
        // How many to actually rename. When a depth is targeted, cap the
        // request to that depth's node count (rename them all) rather than
        // failing; without a depth target, an oversized request is an error.
        std::size_t want = cfg.num_changes;
        if (want > cand.size()) {
            if (cfg.change_depth < 0) {
                result.error = "requested " + std::to_string(cfg.num_changes) +
                               " renames but only " +
                               std::to_string(cand.size()) +
                               " eligible node(s) remain";
                return result;
            }
            want = cand.size();
        }

        // Evenly spaced selection: one node per bucket, picking the bucket
        // midpoint so the root (first event) is left alone for want <
        // the candidate count.
        const std::size_t step = cand.size() / want;
        result.step = step;
        for (std::size_t i = 0; i < want; ++i) {
            std::size_t pos = i * step + step / 2;
            if (pos >= cand.size()) pos = cand.size() - 1;
            EventRef& e = events[cand[pos]];
            const std::string new_name =
                cfg.name_prefix + std::to_string(i + 1);
            set_name(lines[e.line_index], e.name, new_name);
        }
        result.changed = want;
    }

    // ---- Write out the surviving lines. ----
    if (gzip_out) {
        gzFile f = gzopen(out_path.c_str(), "wb");
        if (f == nullptr) {
            result.error = "could not open output file: " + out_path;
            return result;
        }
        for (std::size_t li = 0; li < lines.size(); ++li) {
            if (removed[li]) continue;
            const std::string withnl = lines[li] + "\n";
            if (gzwrite(f, withnl.data(),
                        static_cast<unsigned>(withnl.size())) == 0) {
                gzclose(f);
                result.error = "write error to " + out_path;
                return result;
            }
        }
        gzclose(f);
    } else {
        std::FILE* f = std::fopen(out_path.c_str(), "wb");
        if (f == nullptr) {
            result.error = "could not open output file: " + out_path;
            return result;
        }
        for (std::size_t li = 0; li < lines.size(); ++li) {
            if (removed[li]) continue;
            std::fwrite(lines[li].data(), 1, lines[li].size(), f);
            std::fputc('\n', f);
        }
        std::fclose(f);
    }

    result.ok = true;
    return result;
}

}  // namespace dftracer::utils::utilities::trace_gen

#endif  // DFTRACER_UTILS_UTILITIES_TRACE_GEN_CALL_TREE_MUTATOR_H
