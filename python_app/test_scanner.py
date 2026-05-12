"""
test_scanner.py
===============
Unit test suite for the CI601 Hybrid Fileless Malware Detection System.

Uses Python's built-in `unittest` framework — the closest equivalent to
JUnit (it follows the same xUnit pattern with TestCase classes, setUp /
tearDown lifecycle methods, and an `assert*` API).  The framework is
included with the standard Python installation, so no `pip install` is
required to run these tests.

Coverage  (15 tests)
--------------------
  Rule engine     : 5 tests
  ML pipeline     : 4 tests  (csv_logger feature extraction + data_prep)
  LLM analysis    : 2 tests  (helpers + structured-context builder)
  CSV / JSON I/O  : 2 tests  (append_to_csv + append_to_json)
  GUI helpers     : 2 tests  (markdown stripper + stdout redirector)

How to run
----------
From the project root (the folder containing rule_engine.py etc):

    python -m unittest test_scanner.py -v

Verbose mode prints one line per test with its docstring.  An exit code
of 0 means every test passed; any other code means at least one failure.

Design notes
------------
* Each test is fully isolated: temporary files go in a per-test tempdir
  that is removed in tearDown.
* The rule-engine tests use minimal hand-built ScanBundle objects with
  only the fields the rule under test inspects, so an unrelated change
  in another collector cannot break them.
* The GUI helper tests do NOT spin up a QApplication or any widgets —
  they exercise the pure-Python helpers (strip_markdown, the redirector
  class with a fake widget) so the tests stay headless and run on any
  machine without a display.
* The LLM tests stub anthropic at import time so they do not hit the
  real API and do not require ANTHROPIC_API_KEY to be set.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Stub out external dependencies that aren't needed for unit tests.
#
# memory_scanner is the C++ pybind11 extension — present only on the
# Windows VM. anthropic is the Claude SDK — exists on the dev machine
# but we don't want tests to call it.  PyQt5 is heavy and not needed
# for the helper-level tests below.  Stubs go in BEFORE the project
# modules are imported so the imports succeed in any environment.
# ---------------------------------------------------------------------------

import types as _types

if "memory_scanner" not in sys.modules:
    sys.modules["memory_scanner"] = _types.SimpleNamespace()

if "anthropic" not in sys.modules:
    sys.modules["anthropic"] = _types.ModuleType("anthropic")

# process_data is the file-of-dataclasses on the user's VM. The real one
# imports the memory_scanner pybind11 extension at module load time (which
# we already stubbed above) so the import normally succeeds. Stub it here
# only as a safety net for environments where process_data.py itself is
# missing (e.g. running this test file in CI before deployment). On the
# user's actual development VM this branch is never taken because the
# real process_data.py sits next to the other source files.
if "process_data" not in sys.modules:
    try:
        import process_data  # noqa: F401  -- real one if available
    except ImportError:
        from dataclasses import dataclass, field
        pd = _types.ModuleType("process_data")
        @dataclass
        class _ProcessInfo:
            pid: int = 0
            name: str = ""
            path: str = ""
            integrity: str = "medium"
            elevated: bool = False
            privileges: list = field(default_factory=list)
            modules: list = field(default_factory=list)
            memory_regions: list = field(default_factory=list)
            kernel_time: int = 0
            user_time: int = 0
            creation_time: int = 0
        @dataclass
        class _Empty: pass
        pd.ProcessInfo = _ProcessInfo
        for cls in ("VirtualAllocRegion", "ProtectChange", "WriteEvent",
                    "NtSyscallInfo", "ThreadInfo", "RemoteThread",
                    "MappedModule", "HandleEntry", "ApiActivitySnapshot",
                    "PerfSnapshot", "MemorySample"):
            setattr(pd, cls, _Empty)
        # gui.py also imports collector / printer functions from
        # process_data at module load time.  Stub them all as no-ops so
        # the gui.py import succeeds in this test environment.  None of
        # them are invoked by the GUI helper tests (which only touch
        # strip_markdown and StdoutRedirector).
        _noop = lambda *a, **kw: None
        for fn in ("get_processes", "scan_single_process",
                   "print_process_summary", "print_modules",
                   "print_memory_regions", "print_virtual_allocs",
                   "print_protect_changes", "print_write_detect",
                   "print_nt_syscall_info", "print_thread_info",
                   "print_remote_threads", "print_mapped_modules",
                   "print_handle_audit", "print_api_activity_snapshot",
                   "get_virtual_allocs", "get_thread_info",
                   "get_remote_threads", "get_mapped_modules",
                   "get_write_detect", "collect_memory_samples",
                   "print_memory_samples", "get_protect_changes",
                   "get_nt_syscall_info", "get_handle_audit",
                   "print_perf_snapshot", "get_perf_snapshot",
                   "get_api_activity_snapshot", "ts_us_to_iso"):
            setattr(pd, fn, _noop)
        sys.modules["process_data"] = pd

# Minimal PyQt5 stub for the GUI helper tests (strip_markdown, redirector).
# These helpers are pure-Python — they don't actually use any Qt classes —
# but gui.py imports PyQt5 widgets at module load time, so we need every
# QtWidgets / QtGui / QtCore name gui.py mentions to exist before the
# import statement runs. The values themselves are never invoked.
if "PyQt5" not in sys.modules:
    pyqt5 = _types.ModuleType("PyQt5")
    qtcore = _types.ModuleType("PyQt5.QtCore")
    qtwidgets = _types.ModuleType("PyQt5.QtWidgets")
    qtgui = _types.ModuleType("PyQt5.QtGui")

    class _Stub:
        """Catch-all stub: any attribute access returns another _Stub."""
        def __init__(self, *a, **kw): pass
        def __getattr__(self, _): return _Stub
        def __call__(self, *a, **kw): return _Stub()

    class _FakeQThread:
        def __init__(self, *a, **kw): pass
    class _FakeSignal:
        def __init__(self, *a, **kw): pass
        def emit(self, *a, **kw): pass
        def connect(self, *a, **kw): pass

    qtcore.QThread    = _FakeQThread
    qtcore.pyqtSignal = lambda *a, **kw: _FakeSignal()
    qtcore.Qt         = _Stub()

    # Names gui.py imports from QtWidgets — all just stand-in classes
    for name in (
        "QApplication", "QMainWindow", "QWidget", "QVBoxLayout", "QHBoxLayout",
        "QPushButton", "QTextEdit", "QTableWidget", "QTableWidgetItem",
        "QHeaderView", "QLabel", "QSplitter", "QAbstractItemView", "QFrame",
        "QTabWidget", "QStackedWidget", "QCheckBox", "QLineEdit",
        "QFileDialog", "QSizePolicy", "QScrollArea", "QSlider", "QProgressBar",
    ):
        setattr(qtwidgets, name, _Stub)

    qtgui.QColor      = _Stub
    qtgui.QTextCursor = _Stub

    pyqt5.QtCore    = qtcore
    pyqt5.QtWidgets = qtwidgets
    pyqt5.QtGui     = qtgui
    sys.modules["PyQt5"]          = pyqt5
    sys.modules["PyQt5.QtCore"]   = qtcore
    sys.modules["PyQt5.QtWidgets"] = qtwidgets
    sys.modules["PyQt5.QtGui"]    = qtgui

# Now safe to import project modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rule_engine import (
    evaluate_rules, RuleResult, RuleHit, KUSER_SHARED_DATA,
    _r01, _r04, _r07, _r13,
)
from llm_analysis import ScanBundle, build_context_dict, _addr, _entropy_label
from csv_logger import (
    extract_features, append_to_csv, append_to_json, ALL_COLUMNS,
)
from data_prep import transform_row, compute_stats, build_training_csv, MISSING


# ===========================================================================
# Lightweight test fixtures
# ===========================================================================
#
# The rule engine and feature extractor expect ScanBundle plus its child
# dataclasses (VirtualAllocRegion, ProtectChange, etc).  Rather than build
# real ones, we use SimpleNamespace objects that quack the same — every
# rule reads fields via _get() which works on either form.

from types import SimpleNamespace as NS


def make_proc(name="test.exe", pid=1234):
    """Minimal ProcessInfo-shaped object."""
    return NS(
        pid=pid, name=name, path=f"C:/test/{name}",
        integrity="medium", elevated=False,
        privileges=[], modules=[], memory_regions=[],
        kernel_time=0, user_time=0, creation_time=0,
    )


def make_bundle(**fields):
    """Build a ScanBundle-like object with only the fields a test cares about."""
    defaults = dict(
        proc=make_proc(),
        allocs=[], protect_changes=[], write_events=[],
        nt_info=None, threads=[], remote_threads=[],
        mapped_modules=[], handles=[],
        api_snapshot=None, perf=None, memory_samples=[],
        rule_result=None, if_result=None,
    )
    defaults.update(fields)
    return NS(**defaults)


# ===========================================================================
# 1. RULE ENGINE TESTS  (5)
# ===========================================================================

class TestRuleEngine(unittest.TestCase):
    """Tests for individual rules and the aggregate RuleResult logic."""

    # -- Test 1 --
    def test_r01_fires_on_executable_private_region(self):
        """R01 triggers when at least one private alloc has exec protection."""
        bundle = make_bundle(allocs=[
            NS(base=0x1000, size=4096, protect="RX",
               entropy=0.5, has_mz=False, has_pe=False, entropy_read=True),
        ])
        hit = _r01(bundle)
        self.assertTrue(hit.triggered, "R01 should fire on RX private region")
        self.assertEqual(hit.weight, 3)
        self.assertIn("0x1000", hit.detail)

    # -- Test 2 --
    def test_r04_ignores_kuser_shared_data_writes(self):
        """
        R04 must NOT fire on KUSER_SHARED_DATA — that page is kernel-written
        on every scan and would otherwise produce 100 % false positives.
        """
        bundle = make_bundle(write_events=[
            # Only KUSER write — should be filtered out
            NS(base=KUSER_SHARED_DATA, size=4096, protect="R",
               sample_before="", sample_after="", writer_pids=[]),
        ])
        hit = _r04(bundle)
        self.assertFalse(
            hit.triggered,
            "R04 must filter KUSER_SHARED_DATA writes — they are benign"
        )

        # Sanity: a real cross-process write at any other address SHOULD fire.
        bundle2 = make_bundle(write_events=[
            NS(base=0x80000000, size=4096, protect="RW",
               sample_before="", sample_after="", writer_pids=[]),
        ])
        self.assertTrue(_r04(bundle2).triggered)

    # -- Test 3 --
    def test_r07_ignores_known_benign_nt_imports(self):
        """
        R07 must skip known-benign (module, function) pairs — e.g. mswsock.dll
        legitimately imports NtQueueApcThread for async I/O.  Whitelist
        bypassing these prevents false positives on every Windows process.
        """
        # Benign import only — should NOT fire
        benign = NS(direct_nt_imports=[
            NS(importing_module="mswsock.dll", function="NtQueueApcThread",
               from_dll="ntdll.dll", watched=True),
        ], syscall_stubs=[], hooked_functions=[])
        self.assertFalse(_r07(make_bundle(nt_info=benign)).triggered)

        # Same function from an unknown module — SHOULD fire
        suspicious = NS(direct_nt_imports=[
            NS(importing_module="evil.dll", function="NtQueueApcThread",
               from_dll="ntdll.dll", watched=True),
        ], syscall_stubs=[], hooked_functions=[])
        self.assertTrue(_r07(make_bundle(nt_info=suspicious)).triggered)

    # -- Test 4 --
    def test_r13_fires_on_rw_to_rx_transition(self):
        """
        R13 detects gained-exec protection changes — the canonical
        write-then-execute shellcode-staging signature that Harness 1
        produces.
        """
        bundle = make_bundle(protect_changes=[
            NS(base=0xDEAD0000, protect_old="RW", protect_new="RX",
               protect_raw_old=0x04, protect_raw_new=0x20,
               gained_exec=True, lost_write=True),
        ])
        hit = _r13(bundle)
        self.assertTrue(hit.triggered)
        self.assertEqual(hit.weight, 3)
        self.assertIn("RW", hit.detail)
        self.assertIn("RX", hit.detail)

    # -- Test 5 --
    def test_rule_result_aggregation(self):
        """
        RuleResult.score, confidence, and label must compute correctly
        from a list of RuleHits.  Verifies the tier thresholds the GUI
        and CSV both depend on.
        """
        result = RuleResult(process_name="x.exe", pid=1)
        # Two triggered rules totalling 6 points, one clean rule
        result.hits = [
            RuleHit("R01", "n", "d", weight=3, triggered=True),
            RuleHit("R02", "n", "d", weight=3, triggered=True),
            RuleHit("R03", "n", "d", weight=2, triggered=False),
        ]
        self.assertEqual(result.score, 6)
        self.assertEqual(result.max_score, 8)
        self.assertAlmostEqual(result.confidence, 0.75, places=2)
        self.assertEqual(result.label, "Likely malicious")

        # Empty triggers → confidence 0, label Normal
        empty = RuleResult(process_name="y.exe", pid=2)
        empty.hits = [RuleHit("R01", "n", "d", weight=3, triggered=False)]
        self.assertEqual(empty.confidence, 0.0)
        self.assertEqual(empty.label, "Normal")


# ===========================================================================
# 2. ML PIPELINE TESTS  (4)
# ===========================================================================

class TestMLPipeline(unittest.TestCase):
    """Tests for csv_logger feature extraction and data_prep transformations."""

    # -- Test 6 --
    def test_extract_features_produces_all_columns(self):
        """
        extract_features() must return every column listed in ALL_COLUMNS,
        with no extras.  Missing data must use the MISSING sentinel (-1)
        rather than NaN or None — the IF cannot consume NaN.
        """
        bundle = make_bundle()   # everything default / empty
        row = extract_features(bundle)
        self.assertEqual(set(row.keys()), set(ALL_COLUMNS),
                         "Row keys must exactly match ALL_COLUMNS")

        # Every numeric value must be int or float, never None / NaN.
        for col, val in row.items():
            if col.startswith("meta_"):
                continue   # meta columns are strings
            self.assertIsInstance(val, (int, float),
                f"{col} must be numeric, got {type(val).__name__}")

    # -- Test 7 --
    def test_transform_row_maps_57_to_21_features(self):
        """
        data_prep.transform_row reduces the 57-column raw row to the 21
        training features. Verifies the column mapping documented at the
        top of data_prep.py — particularly the derived columns
        (num_rw_regions = total_private - exec_count, io_write_kb conversion,
        and the binary has_mz_header flag).
        """
        raw = {
            "meta_timestamp":              "2026-04-29T10:00:00",
            "meta_process_name":           "calc.exe",
            "meta_pid":                    "999",
            "proc_module_count":           "10",
            "proc_region_count":           "50",
            "alloc_total_private_committed": "8",   # 8 private
            "alloc_exec_count":            "3",     # 3 exec → 5 RW
            "mem_exec_private_count":      "3",
            "mem_mz_in_private_count":     "1",     # → has_mz_header = 1
            "alloc_mz_or_pe_count":        "0",     # → has_pe_header = 0
            "thread_total":                "12",
            "perf_handle_count":           "200",
            "perf_cpu_percent":            "1.5",
            "perf_working_set_mb":         "20.0",
            "perf_private_bytes_mb":       "8.0",
            "perf_io_read_mb":             "0.5",
            "perf_io_write_mb":            "1.5",   # → io_write_kb = 1536
            "mem_avg_exec_entropy":        "5.5",
            "mem_max_exec_entropy":        "7.2",
            "write_changed_region_count":  "2",
            "api_write_memory_count":      "5",
            "api_create_thread_count":     "1",
            "nt_high_value_import_count":  "0",     # → ntqueueapc_present = 0
        }
        out = transform_row(raw)

        # Direct mappings
        self.assertEqual(out["num_modules"], 10)
        self.assertEqual(out["num_executable_regions"], 3)
        # Derived: 8 - 3 = 5
        self.assertEqual(out["num_rw_regions"], 5)
        # Conversion: 1.5 MB * 1024 = 1536 KB
        self.assertAlmostEqual(out["io_write_kb"], 1536.0, places=1)
        # Binary flags
        self.assertEqual(out["has_mz_header"], 1)
        self.assertEqual(out["has_pe_header"], 0)
        self.assertEqual(out["ntqueueapc_present"], 0)

    # -- Test 8 --
    def test_compute_stats_excludes_missing_sentinel(self):
        """
        compute_stats must skip rows where a value is MISSING (-1) rather
        than including -1 in the mean/std calculation.  Including sentinels
        would pull the mean down and corrupt synthetic generation.
        """
        rows = [
            {"num_threads": 10},
            {"num_threads": 20},
            {"num_threads": MISSING},   # must be excluded
            {"num_threads": 30},
        ]
        # Pad with the other 20 columns at MISSING so compute_stats doesn't
        # error trying to look them up
        from data_prep import TRAINING_COLUMNS
        for row in rows:
            for col in TRAINING_COLUMNS:
                row.setdefault(col, MISSING)

        stats = compute_stats(rows)
        self.assertEqual(stats["num_threads"]["count"], 3,
                         "MISSING values must be excluded from count")
        self.assertEqual(stats["num_threads"]["mean"], 20.0,
                         "Mean = (10+20+30)/3 = 20, not 15 (would include -1)")
        self.assertEqual(stats["num_threads"]["min"], 10.0)
        self.assertEqual(stats["num_threads"]["max"], 30.0)

    # -- Test 9 --
    def test_build_training_csv_end_to_end(self):
        """
        Integration test: write a small raw CSV, run build_training_csv
        with compute=True, then verify both the training CSV and the
        stats JSON were produced correctly alongside each other.
        """
        with tempfile.TemporaryDirectory() as tmp:
            raw_path  = os.path.join(tmp, "raw.csv")
            train_path = os.path.join(tmp, "train.csv")

            # Write a 2-row raw CSV with valid headers
            import csv
            with open(raw_path, "w", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=ALL_COLUMNS)
                writer.writeheader()
                for pid in (100, 200):
                    row = {col: 0 for col in ALL_COLUMNS}
                    row["meta_pid"] = pid
                    row["meta_process_name"] = "x.exe"
                    row["meta_timestamp"] = "2026-01-01T00:00:00"
                    row["meta_process_path"] = ""
                    row["proc_module_count"] = 5
                    writer.writerow(row)

            n, msg = build_training_csv(raw_path, train_path, compute=True)
            self.assertEqual(n, 2, f"Expected 2 rows, got {n}: {msg}")
            self.assertTrue(os.path.isfile(train_path),
                            "Training CSV must be written")

            # Stats file should sit next to the training CSV with _stats.json
            stats_path = os.path.splitext(train_path)[0] + "_stats.json"
            self.assertTrue(os.path.isfile(stats_path),
                            "stats JSON must be written when compute=True")
            with open(stats_path) as fh:
                stats = json.load(fh)
            self.assertIn("num_modules", stats)
            self.assertEqual(stats["num_modules"]["count"], 2)


# ===========================================================================
# 3. LLM ANALYSIS TESTS  (2)
# ===========================================================================

class TestLLMAnalysis(unittest.TestCase):
    """Tests for the LLM context-building helpers (no API calls)."""

    # -- Test 10 --
    def test_addr_and_entropy_label_helpers(self):
        """
        _addr formats integers as upper-case hex with 0x prefix.
        _entropy_label maps numeric entropy to a human-readable bucket
        the LLM can reason about without needing entropy domain knowledge.
        """
        # _addr
        self.assertEqual(_addr(0x1000), "0x1000")
        self.assertEqual(_addr(0xDEADBEEF), "0xDEADBEEF")
        self.assertEqual(_addr(0), "0x0")

        # _entropy_label thresholds
        self.assertEqual(_entropy_label(-1.0), "unread")
        self.assertEqual(_entropy_label(2.0), "low")
        self.assertEqual(_entropy_label(5.0), "medium")
        self.assertEqual(_entropy_label(6.5), "high")
        # 7.2 is the boundary for "very high (packed/encrypted)"
        self.assertIn("very_high", _entropy_label(7.5))
        self.assertIn("packed", _entropy_label(7.5))

    # -- Test 11 --
    def test_build_context_dict_produces_all_14_sections(self):
        """
        build_context_dict must produce all 14 documented sections so the
        LLM (and the JSON export feature) always sees a consistent schema.
        Missing collector data must produce a 'note' field, never crash.
        """
        bundle = ScanBundle(proc=make_proc(name="firefox.exe", pid=4321))
        ctx = build_context_dict(bundle)

        required_sections = [
            "process", "modules", "memory_regions", "virtual_allocs",
            "protect_changes", "write_events", "nt_syscall", "threads",
            "remote_threads", "mapped_modules", "handles", "api_activity",
            "performance", "memory_sample_highlights",
        ]
        for section in required_sections:
            self.assertIn(section, ctx,
                f"Section '{section}' missing from context dict")

        # Process metadata propagated
        self.assertEqual(ctx["process"]["name"], "firefox.exe")
        self.assertEqual(ctx["process"]["pid"], 4321)

        # Sections without data must contain a 'note', not raise
        self.assertIn("note", ctx["nt_syscall"])
        self.assertIn("note", ctx["api_activity"])
        self.assertIn("note", ctx["performance"])


# ===========================================================================
# 4. CSV / JSON I/O TESTS  (2)
# ===========================================================================

class TestPersistence(unittest.TestCase):
    """Tests for append_to_csv and append_to_json (the data export paths)."""

    # -- Test 12 --
    def test_append_to_csv_writes_header_once_then_appends(self):
        """
        First call to append_to_csv must create the file with a header row.
        Subsequent calls must append rows WITHOUT re-writing the header —
        otherwise the dataset becomes unparseable for sklearn.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.csv")
            bundle = make_bundle()

            # First call → header + 1 row
            append_to_csv(bundle, path)
            with open(path) as fh:
                lines = fh.readlines()
            self.assertEqual(len(lines), 2,
                f"After 1 scan: expected 1 header + 1 row, got {len(lines)}")

            # Second call → header should NOT be repeated
            append_to_csv(bundle, path)
            with open(path) as fh:
                lines = fh.readlines()
            self.assertEqual(len(lines), 3,
                f"After 2 scans: expected 1 header + 2 rows, got {len(lines)}")

            # First line must contain 'meta_timestamp' (header)
            self.assertIn("meta_timestamp", lines[0])
            # Second line must NOT contain 'meta_timestamp' (data)
            self.assertNotIn("meta_timestamp", lines[1])

    # -- Test 13 --
    def test_append_to_json_writes_valid_json_with_safe_filename(self):
        """
        append_to_json must:
          1. write valid JSON containing all 14 context sections
          2. produce a filename containing the process name + PID + timestamp
          3. sanitise process names so Windows-forbidden characters never
             appear in the output filename
        """
        with tempfile.TemporaryDirectory() as tmp:
            # Process name with characters Windows forbids in filenames
            bundle = make_bundle(proc=make_proc(name="evil:name?.exe", pid=777))
            written = append_to_json(bundle, tmp)

            # File exists
            self.assertTrue(os.path.isfile(written))
            self.assertTrue(written.endswith(".json"))

            # Filename has been sanitised — no forbidden chars
            fname = os.path.basename(written)
            for forbidden in ':<>?\\/"|*':
                self.assertNotIn(forbidden, fname,
                    f"Sanitised filename must not contain '{forbidden}'")
            # PID and (sanitised) name still present.  Input "evil:name?.exe"
            # has TWO forbidden chars (':' and '?'), so the sanitised form is
            # "evil_name_.exe" — each forbidden char becomes one underscore.
            self.assertIn("777", fname)
            self.assertIn("evil_name_.exe", fname)

            # Content is valid JSON with the 14-section schema
            with open(written) as fh:
                data = json.load(fh)
            self.assertEqual(data["process"]["pid"], 777)
            self.assertIn("memory_regions", data)
            self.assertIn("memory_sample_highlights", data)


# ===========================================================================
# 5. GUI HELPER TESTS  (2)
# ===========================================================================

class TestGUIHelpers(unittest.TestCase):
    """
    Tests for pure-Python GUI helpers — these run headless because they
    don't construct any QWidgets.  Strip-markdown sanitises LLM streaming
    output; the redirector pipes print() into the home console.
    """

    # -- Test 14 --
    def test_strip_markdown_removes_formatting(self):
        """
        strip_markdown must remove bold/italic markers (** **), heading
        hashes (#), inline backticks (`), and horizontal rules (---) but
        preserve the actual content.  The LLM streams markdown by default;
        the GUI console is plain text, so this conversion runs on every
        chunk delivered to the user.
        """
        # The main GUI file may be named gui.py or python_gui.py depending
        # on the environment — try both so the test runs on any machine.
        try:
            from gui import strip_markdown
        except ModuleNotFoundError:
            from python_gui import strip_markdown

        # Bold and italic
        self.assertEqual(strip_markdown("**bold**"),  "bold")
        self.assertEqual(strip_markdown("*italic*"),  "italic")
        self.assertEqual(strip_markdown("***both***"), "both")

        # Headings
        self.assertEqual(strip_markdown("# Heading 1"),     "Heading 1")
        self.assertEqual(strip_markdown("### Heading 3"),   "Heading 3")

        # Inline code
        self.assertEqual(strip_markdown("use `VirtualAlloc` here"),
                         "use VirtualAlloc here")

        # Horizontal rules
        self.assertEqual(strip_markdown("text\n---\nmore").strip(),
                         "text\n\nmore".strip())

        # Mixed
        result = strip_markdown("## **Verdict**: `MALICIOUS`")
        self.assertEqual(result, "Verdict: MALICIOUS")

    # -- Test 15 --
    def test_stdout_redirector_writes_and_suppresses(self):
        """
        StdoutRedirector pipes print() into a QTextEdit (the home console).
        It must:
          1. Append non-empty text to the widget on write()
          2. Skip empty / whitespace-only writes (print() emits "\\n" alone)
          3. Honour the `suppress` flag for quiet-mode scans
          4. Provide a no-op flush() so it satisfies the file-like protocol
        """
        # The main GUI file may be named gui.py or python_gui.py depending
        # on the environment — try both so the test runs on any machine.
        try:
            from gui import StdoutRedirector
        except ModuleNotFoundError:
            from python_gui import StdoutRedirector

        # Mock widget that records every append call
        widget = MagicMock()
        redirector = StdoutRedirector(widget)

        # Normal write — should append
        redirector.write("hello world")
        widget.append.assert_called_once_with("hello world")

        # Empty / whitespace write — should NOT append
        widget.reset_mock()
        redirector.write("\n")
        redirector.write("   ")
        redirector.write("")
        widget.append.assert_not_called()

        # Suppress flag — should NOT append even on real text
        widget.reset_mock()
        redirector.suppress = True
        redirector.write("this should be silent")
        widget.append.assert_not_called()

        # Un-suppress restores normal behaviour
        redirector.suppress = False
        redirector.write("visible again")
        widget.append.assert_called_once_with("visible again")

        # flush() must exist (file-like protocol) and not raise
        try:
            redirector.flush()
        except Exception as exc:
            self.fail(f"flush() raised unexpectedly: {exc}")


# ===========================================================================
# Runner
# ===========================================================================
#
# Allows the tests to be invoked directly:
#   python test_scanner.py
# or via the unittest CLI:
#   python -m unittest test_scanner.py -v
#
if __name__ == "__main__":
    unittest.main(verbosity=2)