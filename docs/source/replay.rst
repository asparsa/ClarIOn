Replay Utility
==============

The replay utility replays DFTracer trace files by reading recorded events and executing them in a configurable replay mode. It supports plain text and gzipped traces, dry-run analysis, timing-aware replay, and filtered execution for focused testing.

Overview
--------

The Replay utility is designed to perform the following tasks:

- Parse DFTracer trace files (``.pfw``, ``.pfw.gz``) from one or more files or directories
- Replay events in dry-run mode for validation without issuing I/O
- Reproduce event timing or disable timing for faster execution
- Filter replay by PID, TID, function, category, timestamp range, and operation size
- Limit replay volume with sampling and maximum event counts

Key Features
------------

**Multiple Replay Modes**
  The utility supports dry-run analysis, DFTracer sleep-based replay, and direct event replay. Timing can be preserved or disabled depending on the validation goal.

**Flexible Filtering**
  Replay can be restricted to selected processes, threads, functions, categories, time windows, and sizes to isolate specific trace behavior.

**Call Tree Integration**
  The utility can replay traces using the call tree path for hierarchical execution, including optional parent-child ordering constraints.

Replay Modes
------------

Dry Run
~~~~~~~

Parses trace events and reports replay statistics without performing the underlying operations.

DFTracer Mode
~~~~~~~~~~~~~

Simulates replay using operation durations. This is useful for timing-oriented studies without issuing full I/O.

Direct Replay
~~~~~~~~~~~~~

Executes replay operations directly from the trace stream. This mode is useful when validating end-to-end replay behavior.

Performance Considerations
--------------------------

**Compressed Traces**
  Gzipped traces are supported directly. Replay performance depends on trace size and decompression overhead.

**Sampling and Limits**
  Use sampling and maximum event limits to reduce replay cost for CI, debugging, and exploratory analysis.

**Timing Control**
  Disabling timing can significantly reduce wall-clock runtime when only correctness or parsing behavior needs to be validated.

See Also
--------

- :doc:`cli` - Command-line tools
- :doc:`call-tree` - Call tree utility
- :doc:`cpp_api/index` - Full C++ API documentation
