import json
import os
import re
import sys

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QPushButton,
    QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QLabel, QSplitter,
    QAbstractItemView, QFrame, QTabWidget,
    QStackedWidget, QCheckBox, QLineEdit,
    QFileDialog, QSizePolicy, QScrollArea, QSlider,
    QProgressBar,
)

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QTextCursor

from process_data import (
    get_processes,
    scan_single_process,
    print_process_summary,
    print_modules,
    print_memory_regions,
    print_virtual_allocs,
    print_protect_changes,
    print_write_detect,
    print_nt_syscall_info,
    print_thread_info,
    print_remote_threads,
    print_mapped_modules,
    print_handle_audit,
    print_api_activity_snapshot,
    get_virtual_allocs,
    get_thread_info,
    get_remote_threads,
    get_mapped_modules,
    get_write_detect,
    collect_memory_samples,
    print_memory_samples,
    get_protect_changes,
    get_nt_syscall_info,
    get_handle_audit,
    print_perf_snapshot,
    get_perf_snapshot,
    get_api_activity_snapshot,
)

from llm_analysis import ScanBundle, LLMAnalysisWorker
from csv_logger import append_to_csv, get_default_csv_path, FEATURE_COLUMNS, append_to_json, get_default_json_path
from data_prep import build_training_csv, get_default_training_path, TRAINING_COLUMNS
from synth_gen import generate_synthetic, get_default_synth_path, get_default_stats_path

try:
    from rule_engine import evaluate_rules, format_console as fmt_rule_console
    _RULE_ENGINE_AVAILABLE = True
except ImportError:
    _RULE_ENGINE_AVAILABLE = False

# isolation Forest dependencies

try:

    import numpy as np
    import joblib
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (classification_report, confusion_matrix, precision_score, recall_score, f1_score)
    _IF_DEPS_AVAILABLE = True

except ImportError:

    _IF_DEPS_AVAILABLE = False

# matplotlib for embedded charts in VerifyPanel

try:
    import matplotlib
    matplotlib.use("Agg") # non interactive backend
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
    from matplotlib.figure import Figure
    _MPL_AVAILABLE = True

except ImportError:

    _MPL_AVAILABLE = False

MISSING = -1   # sentinel used in training features

# ---------------------------------------------------------------------------
# IF training background worker
# ---------------------------------------------------------------------------

class IFTrainWorker(QThread):

    """
    Trains an IsolationForest in a background thread.

    Uses warm_start=True so trees are added in small batches, allowing real
    incremental progress to be emitted rather than a fake stage-based bar.

    Signals
    -------
    progress(int)   : 0-100
    log(str)        : line to print in HOME console
    done(str,str,str) : (model_path, scaler_path, features_path) on success
    error(str)      : error message on failure
    """

    progress = pyqtSignal(int)
    log = pyqtSignal(str)
    done = pyqtSignal(str, str, str)
    error = pyqtSignal(str)

    BATCH_SIZE = 10 # trees added per iteration (controls progress granularity)

    def __init__(self, synth_path: str, out_dir: str, contamination: float, n_estimators: int, parent = None):
        super().__init__(parent)
        self.synth_path = synth_path
        self.out_dir = out_dir
        self.contamination = contamination
        self.n_estimators = n_estimators

    def run(self) -> None:

        if not _IF_DEPS_AVAILABLE:

            self.error.emit(
                "scikit-learn / joblib / numpy not installed.\n"
                "Run:  pip install scikit-learn joblib numpy pandas"
            )

            return

        try:

            import pandas as pd
            import json as _json

            # ---- 1. Load data (0-10%) ------------------------------------

            self.log.emit(f"[IF] Loading data from {self.synth_path} ...")
            self.progress.emit(5)
            df = pd.read_csv(self.synth_path)
            self.log.emit(f"[IF] Loaded {len(df)} rows x {len(df.columns)} columns")

            # ---- 2. Clean (10-20%) ---------------------------------------

            self.progress.emit(10)

            # drop meta and constant columns
            # collect every column whose name starts with 'meta_' (timestamp, pid, etc).

            meta = []
            for c in df.columns:

                if c.startswith("meta_"):

                    meta.append(c)
            # Collect every column that should always be excluded from training:
            # any non-meta column whose non-missing values have zero variance.
            # Zero-variance columns add no signal to the model and just slow
            # training down.
            always = []

            for c in df.columns:

                if c.startswith("meta_"):

                    continue

                non_missing_values = df[c][df[c] != MISSING]

                if non_missing_values.std() == 0:

                    always.append(c)

            drop = list(set(meta + always) & set(df.columns))

            if drop:

                df = df.drop(columns=drop)

                self.log.emit(f"[IF] Dropped {len(drop)} column(s): {drop}")

            # impute -1 sentinel

            for col in df.columns:
                mask = df[col] == MISSING

                if mask.any():

                    fill = 0.0   # entropy absence = 0.0; counts absence = 0
                    df.loc[mask, col] = fill

            assert not (df == MISSING).any().any(), "Imputation missed -1 sentinel"

            features = list(df.columns)

            self.log.emit(f"[IF] Training on {len(features)} features")

            self.progress.emit(20)

            # ---- 3. Scale (20-30%) ---------------------------------------

            X = df.values.astype(float)
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            self.log.emit("[IF] StandardScaler fitted")
            self.progress.emit(30)

            # ---- 4. Train with warm_start (30-90%) -----------------------

            self.log.emit(
                f"[IF] Training IsolationForest  "
                f"(trees={self.n_estimators}, contamination={self.contamination}) ..."
            )

            trained = 0

            model = IsolationForest(

                n_estimators = self.BATCH_SIZE,
                contamination = self.contamination,
                warm_start = True,
                random_state = 42,
                n_jobs = -1,
            )

            model.fit(X_scaled)
            trained += self.BATCH_SIZE

            while trained < self.n_estimators:

                batch = min(self.BATCH_SIZE, self.n_estimators - trained)
                model.n_estimators += batch
                model.fit(X_scaled)
                trained += batch
                pct = 30 + int(trained / self.n_estimators * 60)
                self.progress.emit(min(pct, 90))

            # ---- 5. Validate (90-95%) ------------------------------------

            preds = model.predict(X_scaled)
            flagged = (preds == -1).sum()

            self.log.emit(
                f"[IF] Training complete. "
                f"Flagged {flagged}/{len(preds)} rows as anomalies "
                f"({flagged/len(preds) * 100:.1f}%)  "
                f"[expected ~ {self.contamination * 100:.0f}%]"
            )

            self.progress.emit(95)

            # ---- 6. Save (95-100%) ---------------------------------------
            import os as _os

            _os.makedirs(self.out_dir, exist_ok = True)

            model_path = _os.path.join(self.out_dir, "if_model.pkl")
            scaler_path  = _os.path.join(self.out_dir, "if_scaler.pkl")
            feature_path = _os.path.join(self.out_dir, "if_features.json")

            joblib.dump(model,  model_path)
            joblib.dump(scaler, scaler_path)
            with open(feature_path, "w") as fh:
               _json.dump(features, fh, indent = 2)

            self.log.emit(f"[IF] Saved model    -> {model_path}")
            self.log.emit(f"[IF] Saved scaler   -> {scaler_path}")
            self.log.emit(f"[IF] Saved features -> {feature_path}")

            self.progress.emit(100)

            self.done.emit(model_path, scaler_path, feature_path)

        except Exception as exc:

            import traceback

            self.error.emit(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")

# ---------------------------------------------------------------------------
# Markdown stripper
# ---------------------------------------------------------------------------

_MD_BOLD_ITALIC = re.compile(r'\*{1,3}(.*?)\*{1,3}')
_MD_HEADING = re.compile(r'^#{1,6}\s*', re.MULTILINE)
_MD_INLINE_CODE = re.compile(r'`([^`]*)`')
_MD_HORIZ_RULE = re.compile(r'^[-_*]{3,}\s*$', re.MULTILINE)

def strip_markdown(text: str) -> str:

    text = _MD_BOLD_ITALIC.sub(r'\1', text)
    text = _MD_HEADING.sub('', text)
    text = _MD_INLINE_CODE.sub(r'\1', text)
    text = _MD_HORIZ_RULE.sub('', text)

    return text

# ---------------------------------------------------------------------------
# Stdout -> HOME console
# ---------------------------------------------------------------------------

class StdoutRedirector:

    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.suppress = False  # when true, quiet mode swallows verbose output

    def write(self, text):

        if self.suppress:

            return

        if text and text.strip():

            self.text_widget.append(text.rstrip())

    def flush(self):

        pass

# ---------------------------------------------------------------------------
# Persistent settings file
# ---------------------------------------------------------------------------

def _get_output_dir() -> str:

    """Return (and create if needed) the output/ folder next to this script."""

    base = os.path.dirname(os.path.abspath(__file__))
    out  = os.path.join(base, "output")
    os.makedirs(out, exist_ok = True)

    return out

_SETTINGS_FILE = os.path.join(_get_output_dir(), "scanner_settings.json")

# ---------------------------------------------------------------------------
# Background workers
# ---------------------------------------------------------------------------

class ProcessListWorker(QThread):

    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def run(self):

        try:
            self.finished.emit(get_processes())

        except Exception as e:

            self.error.emit(str(e))

class ScanWorker(QThread):

    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, pid: int):

        super().__init__()
        self.pid = pid

    def run(self):

        try:

            self.finished.emit(scan_single_process(self.pid))

        except Exception as e:

            self.error.emit(str(e))

# ---------------------------------------------------------------------------
# Settings panel widget
# ---------------------------------------------------------------------------

class SettingsPanel(QWidget):

    """
    In-window settings panel shown when the gear button is clicked.
    Replaces the main content area; clicking the back button restores it.
    """

    def __init__(self, parent = None):
        super().__init__(parent)
        self.setObjectName("settingsPanel")
        self._build_ui()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # -- Settings header bar -----------------------------------------

        hdr = QWidget()
        hdr.setObjectName("settingsHeader")
        hdr_layout = QHBoxLayout(hdr)
        hdr_layout.setContentsMargins(16, 10, 16, 10)

        title = QLabel("SETTINGS")
        title.setObjectName("settingsTitle")

        self.back_btn = QPushButton("[ < ]  Back")
        self.back_btn.setObjectName("btnSecondary")
        self.back_btn.setFixedHeight(30)

        hdr_layout.addWidget(title)
        hdr_layout.addStretch()
        hdr_layout.addWidget(self.back_btn)
        outer.addWidget(hdr)

        # -- Scrollable content area -------------------------------------

        scroll = QScrollArea()
        scroll.setObjectName("settingsScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        content = QWidget()
        content.setObjectName("settingsContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(28)
        layout.setAlignment(Qt.AlignTop)

        # ---- Section: Data Collection ----------------------------------

        layout.addWidget(self._section_label("DATA COLLECTION"))

        # CSV toggle row

        csv_row = QWidget()
        csv_row_layout = QHBoxLayout(csv_row)
        csv_row_layout.setContentsMargins(0, 0, 0, 0)
        csv_row_layout.setSpacing(12)

        self.csv_toggle = QCheckBox()
        self.csv_toggle.setObjectName("settingsToggle")
        self.csv_toggle.setFixedSize(20, 20)

        csv_text_col = QVBoxLayout()
        csv_text_col.setSpacing(2)
        csv_label = QLabel("Save scan data to CSV")
        csv_label.setObjectName("settingItemLabel")

        csv_desc = QLabel(
            "Appends a row of numerical features to the CSV file after each "
            "scan. Use this to build a training dataset for the Isolation "
            "Forest anomaly detector."
        )

        csv_desc.setObjectName("settingItemDesc")
        csv_desc.setWordWrap(True)
        csv_text_col.addWidget(csv_label)
        csv_text_col.addWidget(csv_desc)

        csv_row_layout.addWidget(self.csv_toggle, 0, Qt.AlignTop)
        csv_row_layout.addLayout(csv_text_col, 1)
        layout.addWidget(csv_row)

        # CSV file path row

        path_row = QWidget()
        path_row.setObjectName("pathRow")
        path_layout = QHBoxLayout(path_row)
        path_layout.setContentsMargins(32, 0, 0, 0)
        path_layout.setSpacing(8)

        path_label = QLabel("Output file:")
        path_label.setObjectName("settingItemLabel")
        path_label.setFixedWidth(90)

        self.csv_path_input = QLineEdit()
        self.csv_path_input.setObjectName("settingsLineEdit")
        self.csv_path_input.setText(get_default_csv_path())
        self.csv_path_input.setPlaceholderText("Path to CSV file...")

        self.browse_btn = QPushButton("Browse")
        self.browse_btn.setObjectName("btnSecondary")
        self.browse_btn.setFixedHeight(28)
        self.browse_btn.setFixedWidth(70)
        self.browse_btn.clicked.connect(self._browse_csv)

        path_layout.addWidget(path_label)
        path_layout.addWidget(self.csv_path_input, 1)
        path_layout.addWidget(self.browse_btn)
        layout.addWidget(path_row)

        # CSV status label updated after each write 

        self.csv_status_label = QLabel("")
        self.csv_status_label.setObjectName("csvStatusLabel")
        self.csv_status_label.setContentsMargins(32, 0, 0, 0)
        layout.addWidget(self.csv_status_label)

        # JSON toggle row

        # mirrors the CSV section above but writes one JSON file per scan
        # the JSON contains the full structured view of the scan, same one
        # that gets sent to the llm through build_context_dict in llm_analysis.py

        json_row = QWidget()
        json_row_layout = QHBoxLayout(json_row)
        json_row_layout.setContentsMargins(0, 0, 0, 0)
        json_row_layout.setSpacing(12)

        self.json_toggle = QCheckBox()
        self.json_toggle.setObjectName("settingsToggle")
        self.json_toggle.setFixedSize(20, 20)

        json_text_col = QVBoxLayout()
        json_text_col.setSpacing(2)
        json_label = QLabel("Save raw scan data to JSON")
        json_label.setObjectName("settingItemLabel")

        json_desc = QLabel(

            "Saves the full structured scan data as a JSON file after each "
            "scan, one file per scan. Uses the same view of the scan that "
            "the LLM sees."
        )

        json_desc.setObjectName("settingItemDesc")
        json_desc.setWordWrap(True)
        json_text_col.addWidget(json_label)
        json_text_col.addWidget(json_desc)

        json_row_layout.addWidget(self.json_toggle, 0, Qt.AlignTop)
        json_row_layout.addLayout(json_text_col, 1)
        layout.addWidget(json_row)

        # JSON output directory row
        # the path is a directory not a file because each scan creates its own filename inside the directory

        json_path_row = QWidget()
        json_path_row.setObjectName("pathRow")
        json_path_layout = QHBoxLayout(json_path_row)
        json_path_layout.setContentsMargins(32, 0, 0, 0)
        json_path_layout.setSpacing(8)

        json_path_label = QLabel("Output dir:")
        json_path_label.setObjectName("settingItemLabel")
        json_path_label.setFixedWidth(90)

        self.json_path_input = QLineEdit()
        self.json_path_input.setObjectName("settingsLineEdit")
        self.json_path_input.setText(get_default_json_path())
        self.json_path_input.setPlaceholderText("Path to JSON output directory...")

        self.json_browse_btn = QPushButton("Browse")
        self.json_browse_btn.setObjectName("btnSecondary")
        self.json_browse_btn.setFixedHeight(28)
        self.json_browse_btn.setFixedWidth(70)
        self.json_browse_btn.clicked.connect(self._browse_json)

        json_path_layout.addWidget(json_path_label)
        json_path_layout.addWidget(self.json_path_input, 1)
        json_path_layout.addWidget(self.json_browse_btn)
        layout.addWidget(json_path_row)

        # JSON status label updated after each write

        self.json_status_label = QLabel("")
        self.json_status_label.setObjectName("csvStatusLabel")
        self.json_status_label.setContentsMargins(32, 0, 0, 0)
        layout.addWidget(self.json_status_label)

        # ---- Section: About the feature set ----------------------------

        layout.addWidget(self._section_label("FEATURE SET  (" + str(len(FEATURE_COLUMNS)) + " FEATURES)"))

        feat_desc = QLabel(
            "Each scan row captures the indicators below. All values are "
            "numeric so the CSV can be fed directly to scikit-learn's "
            "IsolationForest without additional encoding. Missing data "
            "is represented as -1."
        )

        feat_desc.setObjectName("settingItemDesc")
        feat_desc.setWordWrap(True)
        layout.addWidget(feat_desc)

        # Feature group summary table (static labels)

        groups = [

            ("proc_*",    "Process token / privilege / count attributes"),
            ("mod_*",     "Module list observations (non-file-backed count)"),
            ("mem_*",     "Memory region stats (exec private, entropy, MZ)"),
            ("alloc_*",   "VirtualAlloc: private committed region counts"),
            ("prot_*",    "VirtualProtect: protection change counts"),
            ("write_*",   "WriteProcessMemory: changed region counts"),
            ("nt_*",      "NT syscall: direct imports, stubs, ntdll hooks"),
            ("thread_*",  "Thread start addresses, private-exec starters"),
            ("rthread_*", "Remote / newly created thread detection"),
            ("mmap_*",    "Manually mapped / hidden module detection"),
            ("handle_*",  "External handle audit (VM_WRITE, CREATE_THREAD)"),
            ("api_*",     "Inferred API call counts from memory diffing"),
            ("perf_*",    "CPU%, working set, I/O counters"),
            ("sample_*",  "Memory sample byte pattern highlights"),
        ]

        for prefix, desc in groups:

            row_w = QWidget()
            row_l = QHBoxLayout(row_w)
            row_l.setContentsMargins(0, 0, 0, 0)
            row_l.setSpacing(12)
            prefix_lbl = QLabel(prefix)
            prefix_lbl.setObjectName("featurePrefix")
            prefix_lbl.setFixedWidth(90)
            desc_lbl = QLabel(desc)
            desc_lbl.setObjectName("settingItemDesc")
            row_l.addWidget(prefix_lbl)
            row_l.addWidget(desc_lbl, 1)
            layout.addWidget(row_w)

        # ---- Section: Build Training CSV ------------------------------

        layout.addWidget(self._section_label("TRAINING DATA BUILDER"))

        build_desc = QLabel(

            "Remaps the raw scan CSV into the 21-feature schema used by the "
            "Isolation Forest trainer. Derives higher-level columns such as "
            "num_rw_regions, has_mz_header, and ntqueueapc_present from the "
            "raw collector data."
        )

        build_desc.setObjectName("settingItemDesc")
        build_desc.setWordWrap(True)
        layout.addWidget(build_desc)

        # Training output path row

        tpath_row = QWidget()
        tpath_layout = QHBoxLayout(tpath_row)
        tpath_layout.setContentsMargins(0, 0, 0, 0)
        tpath_layout.setSpacing(8)

        tpath_label = QLabel("Output file:")
        tpath_label.setObjectName("settingItemLabel")
        tpath_label.setFixedWidth(90)

        self.training_path_input = QLineEdit()
        self.training_path_input.setObjectName("settingsLineEdit")
        self.training_path_input.setText(get_default_training_path())
        self.training_path_input.setPlaceholderText("Path to training CSV...")
        self.training_path_input.textChanged.connect(self._sync_stats_path)

        self.training_browse_btn = QPushButton("Browse")
        self.training_browse_btn.setObjectName("btnSecondary")
        self.training_browse_btn.setFixedHeight(28)
        self.training_browse_btn.setFixedWidth(70)
        self.training_browse_btn.clicked.connect(self._browse_training)

        tpath_layout.addWidget(tpath_label)
        tpath_layout.addWidget(self.training_path_input, 1)
        tpath_layout.addWidget(self.training_browse_btn)
        layout.addWidget(tpath_row)

        # Compute toggle row

        compute_row = QWidget()
        compute_row_layout = QHBoxLayout(compute_row)
        compute_row_layout.setContentsMargins(0, 0, 0, 0)
        compute_row_layout.setSpacing(12)

        self.compute_toggle = QCheckBox()
        self.compute_toggle.setObjectName("settingsToggle")
        self.compute_toggle.setFixedSize(20, 20)

        compute_text_col = QVBoxLayout()
        compute_text_col.setSpacing(2)
        compute_label = QLabel("Compute statistics")
        compute_label.setObjectName("settingItemLabel")
        compute_desc_lbl = QLabel(

            "When on, computes mean, std, min and max for each feature "
            "across the full dataset and saves them to a separate "
            "training_data_stats.json file alongside the CSV. "
            "These stats are NOT added to the CSV - they are saved for "
            "synthetic data generation later."
        )

        compute_desc_lbl.setObjectName("settingItemDesc")
        compute_desc_lbl.setWordWrap(True)
        compute_text_col.addWidget(compute_label)
        compute_text_col.addWidget(compute_desc_lbl)

        compute_row_layout.addWidget(self.compute_toggle, 0, Qt.AlignTop)
        compute_row_layout.addLayout(compute_text_col, 1)
        layout.addWidget(compute_row)

        # Build button

        self.build_btn = QPushButton("[>>]  Build Training CSV")
        self.build_btn.setObjectName("btnBuild")
        self.build_btn.setFixedHeight(36)
        self.build_btn.clicked.connect(self._on_build_clicked)
        layout.addWidget(self.build_btn)

        # Build status label

        self.build_status_label = QLabel("")
        self.build_status_label.setObjectName("buildStatusLabel")
        self.build_status_label.setWordWrap(True)
        layout.addWidget(self.build_status_label)

        # ---- Section: Synthetic Data Generator ------------------------

        layout.addWidget(self._section_label("SYNTHETIC DATA GENERATOR"))

        synth_desc = QLabel(
            "Generates synthetic process samples by applying Gaussian "
            "perturbations to real rows from the training CSV. "
            "Requires the training CSV and stats JSON (build with "
            "'Compute statistics' enabled)."
        )

        synth_desc.setObjectName("settingItemDesc")
        synth_desc.setWordWrap(True)
        layout.addWidget(synth_desc)

        # -- File paths (training CSV + stats JSON can be pre-existing files)

        def _file_row(lbl_text, placeholder, browse_slot, default = "", open_mode = False):

            row_w = QWidget()
            row_l = QHBoxLayout(row_w)
            row_l.setContentsMargins(0, 0, 0, 0)
            row_l.setSpacing(8)
            lbl = QLabel(lbl_text)
            lbl.setObjectName("settingItemLabel")
            lbl.setFixedWidth(90)
            inp = QLineEdit(default)
            inp.setObjectName("settingsLineEdit")
            inp.setPlaceholderText(placeholder)
            btn = QPushButton("Browse")
            btn.setObjectName("btnSecondary")
            btn.setFixedHeight(28)
            btn.setFixedWidth(70)
            btn.clicked.connect(browse_slot)
            row_l.addWidget(lbl)
            row_l.addWidget(inp, 1)
            row_l.addWidget(btn)

            return row_w, inp

        stats_row, self.stats_path_input = _file_row(

            "Stats JSON:", "Path to training_data_stats.json...",
            self._browse_stats, open_mode = True
        )

        layout.addWidget(stats_row)

        synth_out_row, self.synth_path_input = _file_row(

            "Output file:", "Path to synthetic_data.csv...",
            self._browse_synth, default=get_default_synth_path()
        )

        layout.addWidget(synth_out_row)

        file_note = QLabel(

            "Set Training CSV and Stats JSON to previously collected files "
            "to generate synthetic data without running a new scan."
        )

        file_note.setObjectName("settingItemDesc")
        file_note.setWordWrap(True)
        layout.addWidget(file_note)

        # -- Variants row

        vrow = QWidget()
        vrow_l = QHBoxLayout(vrow)
        vrow_l.setContentsMargins(0, 0, 0, 0)
        vrow_l.setSpacing(16)
        vrow_l.addWidget(QLabel("Variants per row:"))
        self.variants_input = QLineEdit("10")
        self.variants_input.setObjectName("settingsLineEdit")
        self.variants_input.setFixedWidth(60)
        vrow_l.addWidget(self.variants_input)
        vrow_l.addStretch()
        layout.addWidget(vrow)

        # -- Noise scale + adaptive toggle

        noise_row = QWidget()
        noise_l = QHBoxLayout(noise_row)
        noise_l.setContentsMargins(0, 0, 0, 0)
        noise_l.setSpacing(12)

        self.adaptive_toggle = QCheckBox()
        self.adaptive_toggle.setObjectName("settingsToggle")
        self.adaptive_toggle.setFixedSize(20, 20)

        adaptive_col = QVBoxLayout()
        adaptive_col.setSpacing(2)
        adaptive_col.addWidget(QLabel("Adaptive noise  (random 0.1 - 0.5 per sample)"))

        adaptive_desc = QLabel(
            "Each sample gets a different noise scale chosen at random. "
            "Disables the fixed scale input below."
        )

        adaptive_desc.setObjectName("settingItemDesc")
        adaptive_desc.setWordWrap(True)
        adaptive_col.addWidget(adaptive_desc)

        noise_l.addWidget(self.adaptive_toggle, 0, Qt.AlignTop)
        noise_l.addLayout(adaptive_col, 1)
        layout.addWidget(noise_row)

        # Fixed scale (greyed out when adaptive is on)

        scale_row = QWidget()
        scale_row_l = QHBoxLayout(scale_row)
        scale_row_l.setContentsMargins(28, 0, 0, 0)
        scale_row_l.setSpacing(10)
        self.scale_label = QLabel("Fixed noise scale:")
        self.scale_label.setObjectName("settingItemLabel")
        self.scale_input = QLineEdit("0.2")
        self.scale_input.setObjectName("settingsLineEdit")
        self.scale_input.setFixedWidth(60)
        self.scale_input.setToolTip("noise = normal(0, std * scale). Typical range 0.1-0.3.")
        scale_row_l.addWidget(self.scale_label)
        scale_row_l.addWidget(self.scale_input)
        scale_row_l.addStretch()
        layout.addWidget(scale_row)

        self.adaptive_toggle.stateChanged.connect(self._on_adaptive_changed)

        # -- Distribution split slider

        split_outer = QWidget()
        split_outer_l = QHBoxLayout(split_outer)
        split_outer_l.setContentsMargins(0, 0, 0, 0)
        split_outer_l.setSpacing(12)

        self.dist_toggle = QCheckBox()
        self.dist_toggle.setObjectName("settingsToggle")
        self.dist_toggle.setFixedSize(20, 20)

        dist_col = QVBoxLayout()
        dist_col.setSpacing(6)
        dist_col.addWidget(QLabel("Enable distribution sampling  (split control)"))

        dist_desc = QLabel(
            "When off: 100% noise-based.  When on: use the slider to "
            "set the noise vs distribution split."
        )

        dist_desc.setObjectName("settingItemDesc")
        dist_desc.setWordWrap(True)
        dist_col.addWidget(dist_desc)

        # Slider row only active when dist_toggle is on

        self.slider_widget = QWidget()
        slider_l = QVBoxLayout(self.slider_widget)
        slider_l.setContentsMargins(0, 4, 0, 0)
        slider_l.setSpacing(4)

        self.split_slider = QSlider(Qt.Horizontal)
        self.split_slider.setObjectName("splitSlider")
        self.split_slider.setRange(0, 100)
        self.split_slider.setValue(70)
        self.split_slider.setTickInterval(10)
        self.split_slider.setTickPosition(QSlider.TicksBelow)

        self.split_label = QLabel("Noise-based: 70%   |   Distribution-based: 30%")

        self.split_label.setObjectName("settingItemDesc")

        slider_l.addWidget(self.split_slider)
        slider_l.addWidget(self.split_label)
        dist_col.addWidget(self.slider_widget)
        self.slider_widget.setEnabled(False)

        split_outer_l.addWidget(self.dist_toggle, 0, Qt.AlignTop)
        split_outer_l.addLayout(dist_col, 1)
        layout.addWidget(split_outer)

        self.dist_toggle.stateChanged.connect(self._on_dist_toggle_changed)
        self.split_slider.valueChanged.connect(self._on_split_changed)

        # -- Anomaly injection

        anom_row = QWidget()
        anom_row_l = QHBoxLayout(anom_row)
        anom_row_l.setContentsMargins(0, 0, 0, 0)
        anom_row_l.setSpacing(12)

        self.anomaly_toggle = QCheckBox()
        self.anomaly_toggle.setObjectName("settingsToggle")
        self.anomaly_toggle.setFixedSize(20, 20)

        anom_col = QVBoxLayout()
        anom_col.setSpacing(4)
        anom_col.addWidget(QLabel("Inject controlled anomalies"))

        anom_rate_row = QWidget()
        anom_rate_l = QHBoxLayout(anom_rate_row)
        anom_rate_l.setContentsMargins(0, 0, 0, 0)
        anom_rate_l.setSpacing(8)
        anom_rate_l.addWidget(QLabel("Rate (1-5%):"))
        self.anomaly_rate_input = QLineEdit("2")
        self.anomaly_rate_input.setObjectName("settingsLineEdit")
        self.anomaly_rate_input.setFixedWidth(50)
        anom_rate_l.addWidget(self.anomaly_rate_input)
        anom_rate_l.addStretch()
        anom_col.addWidget(anom_rate_row)

        anom_desc = QLabel(

            "Injects extreme values into a random subset of synthetic rows: "
            "num_threads (very high), entropy_mean/max (7.0-8.0), "
            "cross_process_writes (non-zero), api_createremotethread (1)."
        )

        anom_desc.setObjectName("settingItemDesc")
        anom_desc.setWordWrap(True)
        anom_col.addWidget(anom_desc)

        anom_row_l.addWidget(self.anomaly_toggle, 0, Qt.AlignTop)
        anom_row_l.addLayout(anom_col, 1)
        layout.addWidget(anom_row)

        # -- Generate button

        self.synth_btn = QPushButton("[~]  Generate Synthetic Data")
        self.synth_btn.setObjectName("btnSynth")
        self.synth_btn.setFixedHeight(36)
        self.synth_btn.clicked.connect(self._on_synth_clicked)
        layout.addWidget(self.synth_btn)

        self.synth_status_label = QLabel("")
        self.synth_status_label.setObjectName("synthStatusLabel")
        self.synth_status_label.setWordWrap(True)
        layout.addWidget(self.synth_status_label)

        # ---- Section: Isolation Forest Training -----------------------

        layout.addWidget(self._section_label("ISOLATION FOREST — TRAINING"))

        if_train_desc = QLabel(

            "Train the Isolation Forest once on your synthetic dataset. "
            "The model, scaler, and feature list are saved to disk and "
            "reused automatically on every subsequent scan. "
            "Requires: scikit-learn  joblib  numpy  pandas."
        )

        if_train_desc.setObjectName("settingItemDesc")
        if_train_desc.setWordWrap(True)
        layout.addWidget(if_train_desc)

        # Synth data path

        def _file_row_if(lbl_text, placeholder, browse_slot, default = ""):

            row_w = QWidget()
            row_l = QHBoxLayout(row_w)
            row_l.setContentsMargins(0, 0, 0, 0)
            row_l.setSpacing(8)
            lbl = QLabel(lbl_text)
            lbl.setObjectName("settingItemLabel")
            lbl.setFixedWidth(100)
            inp = QLineEdit(default)
            inp.setObjectName("settingsLineEdit")
            inp.setPlaceholderText(placeholder)
            btn = QPushButton("Browse")
            btn.setObjectName("btnSecondary")
            btn.setFixedHeight(28)
            btn.setFixedWidth(70)
            btn.clicked.connect(browse_slot)
            row_l.addWidget(lbl)
            row_l.addWidget(inp, 1)
            row_l.addWidget(btn)

            return row_w, inp

        synth_in_row, self.if_synth_input = _file_row_if(

            "Synth data:", "Path to synthetic_data.csv...",
            self._browse_if_synth, default=get_default_synth_path()
        )

        layout.addWidget(synth_in_row)

        model_out_row, self.if_model_dir_input = _file_row_if(

            "Model output:", "Directory to save model files...",
            self._browse_if_out,
            default=os.path.join(_get_output_dir(), "models")
        )

        layout.addWidget(model_out_row)

        # Contamination + n_estimators row

        param_row = QWidget()
        param_l = QHBoxLayout(param_row)
        param_l.setContentsMargins(0, 0, 0, 0)
        param_l.setSpacing(20)

        param_l.addWidget(QLabel("Contamination:"))
        self.if_contamination_input = QLineEdit("0.02")
        self.if_contamination_input.setObjectName("settingsLineEdit")
        self.if_contamination_input.setFixedWidth(60)

        self.if_contamination_input.setToolTip(

            "Expected anomaly fraction (0.01-0.10). "
            "Raise if too many missed; lower if too many false positives."
        )

        param_l.addWidget(self.if_contamination_input)

        param_l.addSpacing(12)
        param_l.addWidget(QLabel("Trees:"))
        self.if_trees_input = QLineEdit("200")
        self.if_trees_input.setObjectName("settingsLineEdit")
        self.if_trees_input.setFixedWidth(60)
        param_l.addWidget(self.if_trees_input)
        param_l.addStretch()
        layout.addWidget(param_row)

        # Train button

        self.if_train_btn = QPushButton("[▶]  Train Isolation Forest")
        self.if_train_btn.setObjectName("btnTrain")
        self.if_train_btn.setFixedHeight(36)
        self.if_train_btn.clicked.connect(self._on_if_train_clicked)
        layout.addWidget(self.if_train_btn)

        # Progress bar hidden until training starts

        self.if_progress_bar = QProgressBar()
        self.if_progress_bar.setObjectName("ifProgressBar")
        self.if_progress_bar.setRange(0, 100)
        self.if_progress_bar.setValue(0)
        self.if_progress_bar.setFixedHeight(14)
        self.if_progress_bar.setVisible(False)
        layout.addWidget(self.if_progress_bar)

        # Training status label

        self.if_train_status = QLabel("")
        self.if_train_status.setObjectName("settingItemDesc")
        self.if_train_status.setWordWrap(True)
        layout.addWidget(self.if_train_status)

        # ---- Section: Isolation Forest Model --------------------------

        layout.addWidget(self._section_label("ISOLATION FOREST — MODEL"))

        model_load_desc = QLabel(

            "Load a previously trained model to enable anomaly scoring on "
            "every scan. If a model was just trained, it is loaded automatically."
        )

        model_load_desc.setObjectName("settingItemDesc")
        model_load_desc.setWordWrap(True)
        layout.addWidget(model_load_desc)

        model_load_row, self.if_model_path_input = _file_row_if(
            "Model file:", "Path to if_model.pkl...",
            self._browse_if_model
        )

        layout.addWidget(model_load_row)

        self.if_load_btn = QPushButton("[↑]  Load Model")
        self.if_load_btn.setObjectName("btnSecondary")
        self.if_load_btn.setFixedHeight(32)
        self.if_load_btn.clicked.connect(self._on_if_load_clicked)
        layout.addWidget(self.if_load_btn)

        self.if_verify_btn = QPushButton("[■]  Verify Model Quality")
        self.if_verify_btn.setObjectName("btnTrain")
        self.if_verify_btn.setFixedHeight(32)

        # Connected by MainWindow._connect_if_signals

        layout.addWidget(self.if_verify_btn)

        self.if_model_status = QLabel("No model loaded")
        self.if_model_status.setObjectName("settingItemDesc")
        layout.addWidget(self.if_model_status)

        layout.addStretch()

        # ---- Section: Process List Options ----------------------------

        layout.addWidget(self._section_label("PROCESS LIST"))

        def _toggle_row(label_text, desc_text):

            row = QWidget()
            row_l = QHBoxLayout(row)
            row_l.setContentsMargins(0, 0, 0, 0)
            row_l.setSpacing(12)
            toggle = QCheckBox()
            toggle.setObjectName("settingsToggle")
            toggle.setFixedSize(20, 20)
            text_col = QVBoxLayout()
            text_col.setSpacing(2)
            text_col.addWidget(QLabel(label_text))
            desc = QLabel(desc_text)
            desc.setObjectName("settingItemDesc")
            desc.setWordWrap(True)
            text_col.addWidget(desc)
            row_l.addWidget(toggle, 0, Qt.AlignTop)
            row_l.addLayout(text_col, 1)

            return row, toggle

        hide_row, self.hide_denied_toggle = _toggle_row(

            "Hide unauthorised processes",
            "Removes entries where the scanner has no permission to read the "
            "process name or path (shown as '<access denied>' or 'unknown'). "
            "Keeps the list clean when running without elevated privileges."
        )

        layout.addWidget(hide_row)

        group_row, self.group_procs_toggle = _toggle_row(

            "Group processes by name",
            "Collapses multiple instances of the same executable into a single "
            "row showing the count (e.g. 'chrome.exe  x6'). Scanning a grouped "
            "row runs a full scan on every PID in the group, one after another, "
            "and appends a CSV row for each."
        )

        layout.addWidget(group_row)

        # ---- Section: Display -----------------------------------------

        layout.addWidget(self._section_label("DISPLAY"))

        quiet_row, self.quiet_mode_toggle = _toggle_row(

            "Quiet console output",
            "Suppresses the full verbose scan printout in the HOME console. "
            "Only essential lines are shown: scan start / complete, CSV write "
            "confirmation, and any errors. The LLM analysis tab is unaffected."
        )

        layout.addWidget(quiet_row)

        # ---- Section: General -----------------------------------------

        layout.addWidget(self._section_label("GENERAL"))

        persist_row, self.persist_toggle = _toggle_row(

            "Remember settings between sessions",
            "Saves all current settings (file paths, toggles, noise scale, etc.) "
            "to a local file when any value changes. On next launch the saved "
            "values are restored automatically. Disable to always start fresh."
        )

        layout.addWidget(persist_row)

        layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

    # ------------------------------------------------------------------

    def _section_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("settingsSectionLabel")

        return lbl

    def _browse_csv(self):

        path, _ = QFileDialog.getSaveFileName(
            self, "Choose CSV output file",
            self.csv_path_input.text(), "CSV files (*.csv);; All files (*)"
        )

        if path:

            self.csv_path_input.setText(path)

    def _browse_json(self):

        # JSON output is a directory not a file because each scan creates its own filename inside the directory
        # getExistingDirectory shows a folder picker rather than file picker

        path = QFileDialog.getExistingDirectory(
            self, "Choose JSON output directory", self.json_path_input.text()
        )

        if path:

            self.json_path_input.setText(path)

    def _browse_training(self):

        path, _ = QFileDialog.getSaveFileName(

            self, "Choose training CSV output file",

            self.training_path_input.text(),

            "CSV files (*.csv);; All files (*)"

        )

        if path:

            self.training_path_input.setText(path)

    def _sync_stats_path(self, training_path: str):

        """Auto fill the stats JSON path whenever the training path changes."""

        if training_path.strip():

            self.stats_path_input.setText(get_default_stats_path(training_path.strip()))

    def _on_build_clicked(self):

        source = self.csv_path_input.text().strip()
        dest = self.training_path_input.text().strip()

        if not source:

            self.set_build_status("  Source CSV path is empty.", ok = False)

            return

        if not dest:

            self.set_build_status("  Training output path is empty.", ok = False)

            return

        self.build_btn.setEnabled(False)
        self.set_build_status("Building...", ok = True)

        compute = self.compute_toggle.isChecked()

        try:

            count, msg = build_training_csv(source, dest, compute=compute)

            if count > 0:

                self.set_build_status("  " + msg, ok = True)

            else:

                self.set_build_status("  " + msg, ok = False)

        except Exception as exc:

            self.set_build_status(f"  Error: {exc}", ok = False)

        finally:

            self.build_btn.setEnabled(True)

    # ------------------------------------------------------------------
    # public API used by MainWindow
    # ------------------------------------------------------------------

    @property
    def csv_enabled(self) -> bool:

        return self.csv_toggle.isChecked()

    @property
    def csv_path(self) -> str:

        return self.csv_path_input.text().strip()

    @property
    def json_enabled(self) -> bool:

        return self.json_toggle.isChecked()

    @property
    def json_path(self) -> str:

        return self.json_path_input.text().strip()

    @property
    def hide_denied(self) -> bool:

        return self.hide_denied_toggle.isChecked()

    @property
    def group_processes(self) -> bool:

        return self.group_procs_toggle.isChecked()

    @property
    def quiet_mode(self) -> bool:

        return self.quiet_mode_toggle.isChecked()

    @property
    def persist_settings(self) -> bool:

        return self.persist_toggle.isChecked()

    def set_csv_status(self, text: str, ok: bool = True):

        if ok:

            colour = "#00e5a0"

        else:

            colour = "#ff6b6b"

        self.csv_status_label.setText(text)
        self.csv_status_label.setStyleSheet(f"color: {colour}; font-size: 11px;")

    def set_json_status(self, text: str, ok: bool = True):

        if ok:

            colour = "#00e5a0"

        else:

            colour = "#ff6b6b"

        self.json_status_label.setText(text)
        self.json_status_label.setStyleSheet(f"color: {colour}; font-size: 11px;")

    def set_build_status(self, text: str, ok: bool = True):

        if ok:

            colour = "#00e5a0"

        else:

            colour = "#ff6b6b"

        self.build_status_label.setText(text)
        self.build_status_label.setStyleSheet(f"color: {colour}; font-size: 11px;")

    def _browse_stats(self):

        path, _ = QFileDialog.getOpenFileName(

            self, "Choose stats JSON file", self.stats_path_input.text(), "JSON files (*.json);; All files (*)"
        )

        if path:

            self.stats_path_input.setText(path)

    def _browse_synth(self):

        path, _ = QFileDialog.getSaveFileName(
            self, "Choose synthetic data output file", self.synth_path_input.text(), "CSV files (*.csv);;All files (*)"

        )

        if path:

            self.synth_path_input.setText(path)

    # -- Toggle handlers -----------------------------------------------

    # unchecked = enabled

    def _on_adaptive_changed(self, state: int):

        """Grey out / restore the fixed scale input."""

        enabled = (state == 0)

        self.scale_input.setEnabled(enabled)
        self.scale_label.setEnabled(enabled)

        if not enabled:

            colour = "#555555"

        else:

            colour = "#c8c8c8"

        self.scale_label.setStyleSheet(f"color: {colour};")

    def _on_dist_toggle_changed(self, state: int):

        self.slider_widget.setEnabled(state != 0)

    def _on_split_changed(self, value: int):

        noise_pct = value
        dist_pct  = 100 - value

        self.split_label.setText(
            f"Noise-based: {noise_pct}%   |   Distribution-based: {dist_pct}%"
        )

    # -- Generate ------------------------------------------------------

    def _on_synth_clicked(self):

        training = self.training_path_input.text().strip()
        stats = self.stats_path_input.text().strip()
        dest = self.synth_path_input.text().strip()

        if not training:

            self.set_synth_status("Training CSV path is empty.", ok = False)

            return

        if not stats:

            stats = get_default_stats_path(training)

            self.stats_path_input.setText(stats)

        if not dest:

            self.set_synth_status("Output path is empty.", ok = False)
            return

        # validate variants

        try:

            variants = int(self.variants_input.text().strip())

            if variants < 1:

                raise ValueError

        except ValueError:

            self.set_synth_status("Variants must be a positive integer.", ok = False)

            return

        # validate scale only needed if not adaptive

        adaptive = self.adaptive_toggle.isChecked()

        scale = 0.2

        if not adaptive:

            try:

                scale = float(self.scale_input.text().strip())

                if not (0.0 < scale <= 1.0):

                    raise ValueError

            except ValueError:

                self.set_synth_status(

                    "Noise scale must be a number between 0.0 and 1.0.", ok = False
                )

                return

        # noise and distribution split

        if self.dist_toggle.isChecked():

            noise_pct = self.split_slider.value()

        else:

            noise_pct = 100  # pure noise based when distribution sampling is off

        # Anomaly injection

        inject = self.anomaly_toggle.isChecked()

        anomaly_rate = 0.02

        if inject:

            try:

                rate_pct = float(self.anomaly_rate_input.text().strip())

                if not (1.0 <= rate_pct <= 5.0):

                    raise ValueError

                anomaly_rate = rate_pct / 100.0

            except ValueError:

                self.set_synth_status(
                    "Anomaly rate must be between 1 and 5 (percent).", ok = False
                )

                return

        self.synth_btn.setEnabled(False)
        self.set_synth_status("Generating...", ok = True)

        try:

            count, msg = generate_synthetic(
                training_path = training,
                stats_path = stats,
                dest_path = dest,
                variants = variants,
                scale = scale,
                adaptive_noise = adaptive,
                noise_pct = noise_pct,
                inject_anomalies = inject,
                anomaly_rate = anomaly_rate,
            )

            self.set_synth_status("  " + msg, ok = (count > 0))

        except Exception as exc:

            self.set_synth_status(f"  Error: {exc}", ok = False)

        finally:

            self.synth_btn.setEnabled(True)

    def set_synth_status(self, text: str, ok: bool = True):

        if ok:

            colour = "#00e5a0"

        else:

            colour = "#ff6b6b"

        self.synth_status_label.setText(text)
        self.synth_status_label.setStyleSheet(f"color: {colour}; font-size: 11px;")

    # -- IF browse helpers ---------------------------------------------

    def _browse_if_synth(self):

        path, _ = QFileDialog.getOpenFileName(

            self, "Select synthetic data CSV", self.if_synth_input.text(), "CSV files (*.csv);;All files (*)"
        )

        if path:

            self.if_synth_input.setText(path)

    def _browse_if_out(self):

        path = QFileDialog.getExistingDirectory(self, "Select model output directory", self.if_model_dir_input.text())

        if path:

            self.if_model_dir_input.setText(path)

    def _browse_if_model(self):

        path, _ = QFileDialog.getOpenFileName(self, "Select trained IF model", self.if_model_path_input.text(), "Pickle files (*.pkl);;All files (*)")

        if path:

            self.if_model_path_input.setText(path)

    # these are connected by MainWindow after construction

    def _on_if_train_clicked(self):

        pass # overridden by MainWindow._connect_if_signals()

    def _on_if_load_clicked(self):

        pass # overridden by MainWindow._connect_if_signals()

    def set_if_train_status(self, text: str, ok: bool = True):

        if ok:

            colour = "#00e5a0"

        else:

            colour = "#ff6b6b"

        self.if_train_status.setText(text)
        self.if_train_status.setStyleSheet(f"color: {colour}; font-size: 11px;")

    def set_if_model_status(self, text: str, ok: bool = True):

        if ok:

            colour = "#00e5a0"

        else:

            colour = "#888888"

        self.if_model_status.setText(text)
        self.if_model_status.setStyleSheet(f"color: {colour}; font-size: 11px;")

# ---------------------------------------------------------------------------
# VerifyPanel Isolation Forest quality verification page
# ---------------------------------------------------------------------------

# pick the right base class depending on whether matplotlib is available

# When matplotlib is installed inherit from its Qt canvas; otherwise use a plain widget so the file still imports

if _MPL_AVAILABLE:

    _MplCanvasBase = FigureCanvasQTAgg

else:

    _MplCanvasBase = QWidget

class _MplCanvas(_MplCanvasBase):

    """Thin wrapper around a matplotlib Figure for embedding in PyQt5."""

    def __init__(self, width = 5, height = 3.5, parent = None):

        if _MPL_AVAILABLE:

            fig = Figure(figsize=(width, height), facecolor = "#0a0a0a")
            self.ax = fig.add_subplot(111)
            self.ax.set_facecolor("#111111")
            fig.tight_layout(pad = 1.2)

            super().__init__(fig)

        else:

            super().__init__(parent)

    def clear(self):

        if _MPL_AVAILABLE:

            self.ax.clear()
            self.ax.set_facecolor("#111111")


class VerifyPanel(QWidget):

    """
    Full page model quality verification panel.

    Embedded as STACK_VERIFY (page 2) in the main QStackedWidget.
    Opened from the IF Model section in Settings
    back button returns to Settings.
    """

    def __init__(self, parent = None):
        super().__init__(parent)
        self.setObjectName("settingsPanel")
        self._build_ui()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Header bar

        hdr = QWidget()
        hdr.setObjectName("settingsHeader")
        hdr_l = QHBoxLayout(hdr)
        hdr_l.setContentsMargins(16, 10, 16, 10)
        title = QLabel("ISOLATION FOREST — VERIFICATION")
        title.setObjectName("settingsTitle")

        self.back_btn = QPushButton("[ < ]  Back to Settings")
        self.back_btn.setObjectName("btnSecondary")
        self.back_btn.setFixedHeight(30)
        self.run_btn = QPushButton("[▶]  Run Verification")
        self.run_btn.setObjectName("btnTrain")
        self.run_btn.setFixedHeight(30)

        hdr_l.addWidget(title)
        hdr_l.addStretch()
        hdr_l.addWidget(self.run_btn)
        hdr_l.addSpacing(8)
        hdr_l.addWidget(self.back_btn)
        outer.addWidget(hdr)

        # Scrollable content

        scroll = QScrollArea()
        scroll.setObjectName("settingsScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        content.setObjectName("settingsContent")
        self._layout = QVBoxLayout(content)
        self._layout.setContentsMargins(32, 24, 32, 24)
        self._layout.setSpacing(24)
        self._layout.setAlignment(Qt.AlignTop)

        self._build_status_section()
        self._build_metrics_section()
        self._build_charts_section()
        self._build_report_section()
        self._build_overfit_section()
        self._build_mannwhitney_section()
        self._build_score_gap_section()
        self._build_comparison_section()
        self._build_visualise_section()

        self._layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

    def _section(self, text):

        lbl = QLabel(text)
        lbl.setObjectName("settingsSectionLabel")

        return lbl

    # ---- Status ------------------

    def _build_status_section(self):

        self._layout.addWidget(self._section("VERIFICATION STATUS"))

        self.status_lbl = QLabel(
            "Click  [▶ Run Verification]  to analyse the trained model.\n"
            "You need a trained model loaded and the synthetic CSV available."
        )

        self.status_lbl.setObjectName("settingItemDesc")
        self.status_lbl.setWordWrap(True)
        self._layout.addWidget(self.status_lbl)

    # ---- Headline metric cards ----------------------------------------

    def _build_metrics_section(self):

        self._layout.addWidget(self._section("CLASSIFICATION METRICS"))

        desc = QLabel(
            "Labels are inferred from the synthetic dataset: rows where the "
            "anomaly generator injected extreme values are treated as anomalies "
            "(label=1). All other rows are normal (label=0)."
        )

        desc.setObjectName("settingItemDesc")
        desc.setWordWrap(True)
        self._layout.addWidget(desc)

        cards = QWidget()
        cards_l = QHBoxLayout(cards)
        cards_l.setContentsMargins(0, 0, 0, 0)
        cards_l.setSpacing(12)

        def _card(attr, lbl_text, tooltip = ""):

            w = QWidget()
            w.setObjectName("verifyCard")
            vl = QVBoxLayout(w)
            vl.setContentsMargins(12, 10, 12, 10)
            vl.setSpacing(4)
            lbl = QLabel(lbl_text)
            lbl.setObjectName("verifyCardLabel")
            val = QLabel("—")
            val.setObjectName("verifyCardValue")
            val.setAlignment(Qt.AlignCenter)

            if tooltip:
                w.setToolTip(tooltip)

            vl.addWidget(lbl)
            vl.addWidget(val)
            setattr(self, attr, val)

            return w

        cards_l.addWidget(_card("lbl_precision", "PRECISION", "Of all rows flagged as anomaly, what fraction truly were anomalous?"))

        cards_l.addWidget(_card("lbl_recall", "RECALL / DETECTION RATE", "Of all true anomalies, what fraction did the model catch?"))

        cards_l.addWidget(_card("lbl_f1", "F1 SCORE", "Harmonic mean of precision and recall."))

        cards_l.addWidget(_card("lbl_fpr", "FALSE POSITIVE RATE", "Fraction of normal rows wrongly flagged as anomalous."))


        self._layout.addWidget(cards)

        # confusion matrix text

        self.cm_lbl = QLabel("")
        self.cm_lbl.setObjectName("settingItemDesc")
        self.cm_lbl.setWordWrap(True)
        self._layout.addWidget(self.cm_lbl)

    # ---- Charts -------------------------------------------------------

    def _build_charts_section(self):

        self._layout.addWidget(self._section("SCORE DISTRIBUTION  &  FEATURE SCATTER"))

        chart_row = QWidget()
        chart_l = QHBoxLayout(chart_row)
        chart_l.setContentsMargins(0, 0, 0, 0)
        chart_l.setSpacing(16)

        if _MPL_AVAILABLE:

            self.canvas_dist = _MplCanvas(width=5, height=3.4)
            self.canvas_scatter = _MplCanvas(width=5, height=3.4)
            chart_l.addWidget(self.canvas_dist)
            chart_l.addWidget(self.canvas_scatter)

        else:

            no_mpl = QLabel(

                "Charts unavailable — install matplotlib:\n"
                "pip install matplotlib"
            )

            no_mpl.setObjectName("settingItemDesc")
            chart_l.addWidget(no_mpl)

        self._layout.addWidget(chart_row)

        hints = QLabel(

            "Left: anomaly scores — two distinct humps (bimodal) means the model "
            "found a clear boundary. Blue = normal, red = flagged.\n"
            "Right: entropy_max vs cross_process_writes — normal (blue) and "
            "anomaly (red) clusters should be visually separated."
        )

        hints.setObjectName("settingItemDesc")
        hints.setWordWrap(True)
        self._layout.addWidget(hints)

    # ---- classification report ----------------------------------------

    def _build_report_section(self):

        self._layout.addWidget(self._section("DETAILED CLASSIFICATION REPORT"))
        self.report_lbl = QLabel("Run verification to see the full report.")
        self.report_lbl.setObjectName("settingItemDesc")
        self.report_lbl.setWordWrap(True)
        self._layout.addWidget(self.report_lbl)

    # ---- overfitting check --------------------------------------------

    def _build_overfit_section(self):

        self._layout.addWidget(self._section("OVERFITTING CHECK  (TRAIN / TEST SPLIT)"))

        desc = QLabel(
            "Isolation Forest rarely overfits (it uses random sub-sampling by design). "
            "This check splits the synthetic data 70/30 and compares the mean anomaly "
            "score on held-out test rows vs training rows. A difference < 0.005 "
            "indicates no meaningful overfitting."
        )

        desc.setObjectName("settingItemDesc")
        desc.setWordWrap(True)

        self._layout.addWidget(desc)
        self.overfit_lbl = QLabel("—")
        self.overfit_lbl.setObjectName("settingItemDesc")
        self._layout.addWidget(self.overfit_lbl)

    # ---- Mann-Whitney U test ------------------------------------------

    # compares anomaly score distribtuino of normal rows vs anomaly rows
    # p value confirms the model assigns different scores to injected anomalies
    # this is the reason its the primary statistic

    def _build_mannwhitney_section(self):

        self._layout.addWidget(self._section("MANN-WHITNEY U TEST  (SCORE SEPARATION)"))

        desc = QLabel(

            "Non-parametric statistical test comparing the anomaly score "
            "distributions of normal rows vs anomaly-labelled rows. A small "
            "p-value (< 0.05) confirms the model assigns statistically "
            "different scores to injected anomalies — for example detection is not "
            "due to chance. p < 0.001 is the strong threshold typically "
            "expected for a well-trained anomaly detector."
        )

        desc.setObjectName("settingItemDesc")
        desc.setWordWrap(True)
        self._layout.addWidget(desc)

        # headline result line: U statistic + p-value

        self.mw_result_lbl = QLabel("Run verification to compute the test.")
        self.mw_result_lbl.setObjectName("settingItemDesc")
        self.mw_result_lbl.setWordWrap(True)
        self._layout.addWidget(self.mw_result_lbl)

        # verdict line: coloured by significance level

        self.mw_verdict_lbl = QLabel("")
        self.mw_verdict_lbl.setObjectName("settingItemDesc")
        self.mw_verdict_lbl.setWordWrap(True)
        self._layout.addWidget(self.mw_verdict_lbl)

    # ---- Mean Score Gap --------------

    # mann-whitney u test checks whether score distributions are different
    # while mean score gap checks by how much they differ

    # Formula: abs( mean(scores | label = 0) - mean(scores | label = 1) )
    # gap >= 0.10 = strong separation
    # gap >= 0.05 = moderate separation
    # gap >= 0.02 = weak separation (model discriminates)
    # gap < 0.02 = poor separation (distributions almost overlap)

    def _build_score_gap_section(self):

        self._layout.addWidget(self._section("MEAN SCORE GAP  (SEPARATION MAGNITUDE)"))

        desc = QLabel(

            "Quantifies how far apart the model places normal and anomaly-labelled "
            "rows on average. Computed as the absolute difference between the mean "
            "anomaly score of normal rows and the mean anomaly score of anomaly "
            "rows. A larger gap means the model assigns more clearly distinct "
            "scores to the two classes. This is the magnitude metric that pairs "
            "with the Mann-Whitney p-value above which only tells you the "
            "distributions differ, not by how much."
        )

        desc.setObjectName("settingItemDesc")
        desc.setWordWrap(True)

        self._layout.addWidget(desc)

        # headline result line: the two means and the gap

        self.gap_result_lbl = QLabel("Run verification to compute the gap.")
        self.gap_result_lbl.setObjectName("settingItemDesc")
        self.gap_result_lbl.setWordWrap(True)
        self._layout.addWidget(self.gap_result_lbl)

        # verdict line: by separation tier

        self.gap_verdict_lbl = QLabel("")
        self.gap_verdict_lbl.setObjectName("settingItemDesc")
        self.gap_verdict_lbl.setWordWrap(True)
        self._layout.addWidget(self.gap_verdict_lbl)

    # ---- Rules vs ML comparison ---------------

    def _build_comparison_section(self):

        self._layout.addWidget(self._section("RULES vs ML COMPARISON"))

        desc = QLabel(
            "The table below shows how the rule engine and Isolation Forest "
            "classify the same rows, demonstrating the complementary strengths "
            "of the two layer detection system."
        )

        desc.setObjectName("settingItemDesc")
        desc.setWordWrap(True)

        self._layout.addWidget(desc)
        self.comparison_lbl = QLabel("—")
        self.comparison_lbl.setObjectName("settingItemDesc")
        self.comparison_lbl.setWordWrap(True)
        self._layout.addWidget(self.comparison_lbl)

    # ---- Result charts generated on demand -------------------

    def _build_visualise_section(self):

        self._layout.addWidget(self._section("VISUALISATION"))

        vis_desc = QLabel(

            "Generate detailed charts to visually inspect model behaviour. "
            "Requires matplotlib (pip install matplotlib)."
        )

        vis_desc.setObjectName("settingItemDesc")
        vis_desc.setWordWrap(True)
        self._layout.addWidget(vis_desc)

        self.vis_btn = QPushButton("[▶]  Visualise")
        self.vis_btn.setObjectName("btnTrain")
        self.vis_btn.setFixedHeight(36)
        self.vis_btn.setEnabled(False) # enabled only after verification runs
        self._layout.addWidget(self.vis_btn)

        self.vis_status = QLabel("")
        self.vis_status.setObjectName("settingItemDesc")
        self._layout.addWidget(self.vis_status)

        # Container for all 6 charts: hidden until Visualise is clicked

        self.vis_container = QWidget()
        vis_outer = QVBoxLayout(self.vis_container)
        vis_outer.setContentsMargins(0, 8, 0, 0)
        vis_outer.setSpacing(20)

        def _chart_cell(canvas, title_text, desc_text):

            """Wrap a canvas in a labelled cell."""

            cell = QWidget()
            cell_l = QVBoxLayout(cell)
            cell_l.setContentsMargins(0, 0, 0, 0)
            cell_l.setSpacing(4)
            t = QLabel(title_text)
            t.setObjectName("settingItemLabel")
            d = QLabel(desc_text)
            d.setObjectName("settingItemDesc")
            d.setWordWrap(True)
            cell_l.addWidget(t)
            cell_l.addWidget(canvas)
            cell_l.addWidget(d)

            return cell

        if _MPL_AVAILABLE:

            # row 1: score distribution AND confusion matrix heatmap

            row1 = QWidget()
            row1_l = QHBoxLayout(row1)
            row1_l.setContentsMargins(0, 0, 0, 0)
            row1_l.setSpacing(16)

            self.cv_scores = _MplCanvas(width = 5.5, height = 3.8)
            self.cv_cm = _MplCanvas(width = 5.5, height = 3.8)

            row1_l.addWidget(_chart_cell(

                self.cv_scores,
                "Figure 1 — Anomaly Score Distribution",
                "Histogram of isolation scores for all rows. "
                "Blue = normal rows, red = flagged. Two distinct humps (bimodal) "
                "indicate a clear normal/anomaly boundary."
            ))

            row1_l.addWidget(_chart_cell(

                self.cv_cm,
                "Figure 2 — Confusion Matrix",
                "Visual breakdown of TP / FP / TN / FN counts. "
                "Darker green = correct classifications. "
                "Off-diagonal cells show misclassifications."
            ))

            vis_outer.addWidget(row1)

            # row 2: class metrics bar AND feature separability bar

            row2 = QWidget()
            row2_l = QHBoxLayout(row2)
            row2_l.setContentsMargins(0, 0, 0, 0)
            row2_l.setSpacing(16)

            self.cv_metrics  = _MplCanvas(width = 5.5, height = 3.8)
            self.cv_features = _MplCanvas(width = 5.5, height = 3.8)

            row2_l.addWidget(_chart_cell(

                self.cv_metrics,
                "Figure 3 — Precision / Recall / F1 by Class",
                "Grouped bar chart comparing metrics for the normal class vs the "
                "anomaly class. Taller bars = stronger detection performance."
            ))

            row2_l.addWidget(_chart_cell(

                self.cv_features,
                "Figure 4 — Feature Separability",
                "Mean feature value in flagged rows minus mean in normal rows. "
                "Larger bars = that feature drives anomaly detection more strongly."
            ))

            vis_outer.addWidget(row2)

            # row 3: score vs entropy scatter AND precision recall curve

            row3 = QWidget()
            row3_l = QHBoxLayout(row3)
            row3_l.setContentsMargins(0, 0, 0, 0)
            row3_l.setSpacing(16)

            self.cv_scatter2 = _MplCanvas(width = 5.5, height = 3.8)
            self.cv_pr_curve = _MplCanvas(width = 5.5, height = 3.8)

            row3_l.addWidget(_chart_cell(

                self.cv_scatter2,
                "Figure 5 — Anomaly Score vs Entropy",
                "Each dot is a row, coloured by isolation score intensity. "
                "Flagged rows (score < 0) cluster at high entropy values."
            ))

            row3_l.addWidget(_chart_cell(

                self.cv_pr_curve,
                "Figure 6 — Precision-Recall Curve",
                "Precision and recall at varying contamination thresholds. "
                "The area under this curve (AUC-PR) measures overall detection quality."
            ))

            vis_outer.addWidget(row3)

        else:

            no_mpl = QLabel(

                "Charts require matplotlib:\n"
                "pip install matplotlib\n"
                "Restart the application after installing."
            )

            no_mpl.setObjectName("settingItemDesc")
            vis_outer.addWidget(no_mpl)

        self.vis_container.setVisible(False)
        self._layout.addWidget(self.vis_container)

    # ---- public update API called by MainWindow -----------------------

    def set_status(self, text: str, ok: bool = True):

        if ok:

            colour = "#00e5a0"

        else:

            colour = "#ff6b6b"

        self.status_lbl.setText(text)
        self.status_lbl.setStyleSheet(f"color: {colour}; font-size: 12px;")

    def update_metrics(self, precision: float, recall: float, f1: float, fpr: float, tn: int, fp: int, fn: int, tp: int):

        def _pct(v):

            return f"{v * 100:.1f}%"

        self.lbl_precision.setText(_pct(precision))
        self.lbl_recall.setText(_pct(recall))
        self.lbl_f1.setText(_pct(f1))
        self.lbl_fpr.setText(_pct(fpr))

        def _colour(v, good_above=0.8):

            if v >= good_above:

                return "#00e5a0"

            elif v >= 0.6:

                return "#ffd43b"

            else:

                return "#ff6b6b"

        self.lbl_precision.setStyleSheet(f"color:{_colour(precision)}; font-size:22px; font-weight:500;")
        self.lbl_recall.setStyleSheet(f"color:{_colour(recall)}; font-size:22px; font-weight:500;")
        self.lbl_f1.setStyleSheet(f"color:{_colour(f1)}; font-size:22px; font-weight:500;")

        if fpr < 0.05:

            fpr_colour = "#00e5a0"

        elif fpr < 0.1:

            fpr_colour = "#ffd43b"

        else:

            fpr_colour = "#ff6b6b"

        self.lbl_fpr.setStyleSheet(f"color:{fpr_colour}; font-size:22px; font-weight:500;")

        self.cm_lbl.setText(

            f"Confusion matrix:  TP= {tp}  FP= {fp}  TN= {tn}  FN= {fn}  |  "
            f"Total anomalies in data: {tp+fn}  |  "
            f"Total normal rows: {tn+fp}"
        )

    def update_charts(self, scores_all, labels, preds):

        if not _MPL_AVAILABLE:

            return

        TEXT_CLR = "#888888"
        TICK_CLR = "#555555"

        def _style_ax(ax):

            ax.tick_params(colors=TICK_CLR, labelsize=8)
            ax.xaxis.label.set_color(TEXT_CLR)
            ax.yaxis.label.set_color(TEXT_CLR)
            ax.title.set_color(TEXT_CLR)

            for spine in ax.spines.values():
                spine.set_edgecolor("#2a2a2a")

        # -- score distribution --

        ax = self.canvas_dist.ax

        ax.clear()
        ax.set_facecolor("#111111")
        normal_scores  = scores_all[preds == 1]
        anomaly_scores = scores_all[preds == -1]
        bins = np.linspace(scores_all.min(), scores_all.max(), 50)

        ax.hist(normal_scores,  bins = bins, color = "#378ADD", alpha = 0.75, label = "Normal")
        ax.hist(anomaly_scores, bins = bins, color = "#E24B4A", alpha = 0.85, label = "Flagged")
        ax.axvline(0, color = "#555555", linestyle = "--", linewidth = 0.8)

        ax.set_xlabel("Anomaly score")
        ax.set_ylabel("Count")
        ax.set_title("Score Distribution")

        ax.legend(fontsize=7, facecolor="#1a1a1a", labelcolor = TEXT_CLR, edgecolor = "#2a2a2a")

        _style_ax(ax)

        self.canvas_dist.figure.tight_layout(pad = 1.0)
        self.canvas_dist.draw()

    def update_scatter(self, df_feat, preds):

        if not _MPL_AVAILABLE or df_feat is None:

            return

        if "entropy_max" not in df_feat.columns or \
           "cross_process_writes_count" not in df_feat.columns:

            return

        TEXT_CLR = "#888888"
        TICK_CLR = "#555555"

        ax = self.canvas_scatter.ax
        ax.clear()
        ax.set_facecolor("#111111")

        x = df_feat["entropy_max"].values
        y = df_feat["cross_process_writes_count"].values
        colors = np.where(preds == 1, "#378ADD", "#E24B4A")

        ax.scatter(x[preds == 1],  y[preds == 1],  c = "#378ADD", alpha = 0.3, s = 4, label = "Normal", rasterized = True)
        ax.scatter(x[preds == -1], y[preds == -1], c = "#E24B4A", alpha = 0.8, s = 10, label = "Flagged", rasterized = True)

        ax.set_xlabel("entropy_max")
        ax.set_ylabel("cross_process_writes")
        ax.set_title("Feature Scatter (entropy vs writes)")

        ax.legend(fontsize = 7, facecolor = "#1a1a1a", labelcolor = TEXT_CLR, edgecolor = "#2a2a2a")

        for spine in ax.spines.values():
            spine.set_edgecolor("#2a2a2a")

        ax.tick_params(colors = TICK_CLR, labelsize = 8)
        ax.xaxis.label.set_color(TEXT_CLR)
        ax.yaxis.label.set_color(TEXT_CLR)
        ax.title.set_color(TEXT_CLR)

        self.canvas_scatter.figure.tight_layout(pad=1.0)
        self.canvas_scatter.draw()

    def update_report(self, text: str):
        self.report_lbl.setText(text)

    def update_overfit(self, text: str, ok: bool = True):

        if ok:

            colour = "#00e5a0"

        else:

            colour = "#ffd43b"

        self.overfit_lbl.setText(text)
        self.overfit_lbl.setStyleSheet(f"color: {colour}; font-size: 12px;")

    def update_mannwhitney(self, u_stat: float, p_value: float, n_normal: int, n_anomaly: int):

        """
        Display Mann-Whitney U test results in the verify panel.

        Colours the verdict by significance level:
          p <  0.001 = green  (highly significant)
          p <  0.05 = yellow (significant)
          p >= 0.05 = red (not significant — model not separating well)
        """

        # format p-value: notation for very small values used
        # 4 decimal places otherwise p < 1e-300 is reported as ≈ 0

        if p_value < 1e-300:

            p_str = "p ≈ 0  (below floating-point precision)"

        elif p_value < 0.0001:

            p_str = f"p = {p_value:.2e}"

        else:

            p_str = f"p = {p_value:.4f}"

        self.mw_result_lbl.setText(

            f"U statistic: {u_stat:,.0f}   |   {p_str}   |   "
            f"n(normal) = {n_normal}   n(anomaly) = {n_anomaly}"
        )

        self.mw_result_lbl.setStyleSheet("color: #c8c8c8; font-size: 12px;")

        # verdict line

        if p_value < 0.001:

            verdict = ("Highly significant — strong statistical evidence the "
                       "model assigns different scores to injected anomalies.")
            colour = "#00e5a0"

        elif p_value < 0.05:

            verdict = ("Significant — the model distinguishes anomalies from "
                       "normal rows, but the separation could be stronger.")
            colour = "#ffd43b"

        else:

            verdict = ("Not significant — score distributions overlap. The "
                       "model is not reliably separating injected anomalies "
                       "from normal rows. Consider retraining with more data "
                       "or stronger anomaly injection.")
            colour = "#ff6b6b"

        self.mw_verdict_lbl.setText(verdict)
        self.mw_verdict_lbl.setStyleSheet(f"color: {colour}; font-size: 11px;")

    def update_mannwhitney_error(self, message: str):

        """Show an error in the Mann-Whitney section (e.g. scipy missing)."""

        self.mw_result_lbl.setText(message)
        self.mw_result_lbl.setStyleSheet("color: #ff6b6b; font-size: 12px;")
        self.mw_verdict_lbl.setText("")

    def update_score_gap(self, mean_normal: float, mean_anomaly: float, n_normal: int, n_anomaly: int):

        """
        Display the mean anomaly-score gap in the verify panel.

        Colours the verdict by separation magnitude.  Thresholds chosen
        for IsolationForest decision_function() outputs which typically
        span roughly -0.15 (most anomalous) to +0.10 (most normal):

          gap >= 0.10  = green (strong separation)
          gap >= 0.05  = yellow (moderate separation)
          gap >= 0.02  = orange (weak — model marginally discriminates)
          gap <  0.02  = red (poor — distributions nearly overlap)
        """

        gap = abs(mean_normal - mean_anomaly)

        self.gap_result_lbl.setText(

            f"mean(normal) = {mean_normal:+.4f}   |   "
            f"mean(anomaly) = {mean_anomaly:+.4f}   |   "
            f"gap = {gap:.4f}   |   "
            f"n(normal) = {n_normal}   n(anomaly) = {n_anomaly}"
        )

        self.gap_result_lbl.setStyleSheet("color: #c8c8c8; font-size: 12px;")

        # Verdict and colour from the magnitude tier

        if gap >= 0.10:

            verdict = ("Strong separation — the model clearly distinguishes "
                       "anomalies from normal rows on the score axis.")
            colour = "#00e5a0"

        elif gap >= 0.05:

            verdict = ("Moderate separation — anomalies score visibly lower "
                       "than normal rows on average; detection is reliable "
                       "for clear cases.")
            colour = "#ffd43b"

        elif gap >= 0.02:

            verdict = ("Weak separation — the model assigns slightly different "
                       "scores to the two classes, but the gap is small "
                       "enough that borderline cases will be ambiguous.")
            colour = "#ffa94d"

        else:

            verdict = ("Poor separation — the two distributions nearly "
                       "overlap. Threshold-based classification will be "
                       "unreliable. Consider retraining with stronger "
                       "anomaly examples or more contrast in the features.")
            colour = "#ff6b6b"

        self.gap_verdict_lbl.setText(verdict)
        self.gap_verdict_lbl.setStyleSheet(f"color: {colour}; font-size: 11px;")

    def update_score_gap_error(self, message: str):

        """Show an error in the score-gap section."""

        self.gap_result_lbl.setText(message)
        self.gap_result_lbl.setStyleSheet("color: #ff6b6b; font-size: 12px;")
        self.gap_verdict_lbl.setText("")

    def update_comparison(self, text: str):

        self.comparison_lbl.setText(text)

    def update_visualisations(self, scores, labels, preds, df_feat):

        """Render all 6 visualisation charts from verification data."""

        if not _MPL_AVAILABLE:

            self.vis_status.setText(
                "Install matplotlib to enable charts:  pip install matplotlib"
            )

            self.vis_status.setStyleSheet("color:#ff6b6b; font-size:11px;")

            return

        TC = "#888888" # text colour
        TK = "#555555" # tick colour
        BG = "#111111" # axes background

        def _style(ax):

            ax.set_facecolor(BG)
            ax.tick_params(colors=TK, labelsize=8)
            ax.xaxis.label.set_color(TC)
            ax.yaxis.label.set_color(TC)
            ax.title.set_color(TC)

            for sp in ax.spines.values():
                sp.set_edgecolor("#2a2a2a")

        def _draw(canvas):

            canvas.figure.tight_layout(pad=1.2)
            canvas.draw()

        # ---- figure 1: score distribution ---------

        ax = self.cv_scores.ax

        ax.clear()

        bins = np.linspace(scores.min(), scores.max(), 50)

        ax.hist(scores[preds == 1],  bins = bins, color = "#378ADD", alpha = 0.75, label = f"Normal (n={int((preds==1).sum())})")
        ax.hist(scores[preds == -1], bins = bins, color = "#E24B4A", alpha = 0.85, label = f"Flagged (n={int((preds==-1).sum())})")

        ax.axvline(0, color="#555555", linestyle = "--", linewidth = 0.9, label = "Decision boundary")
        ax.set_xlabel("Anomaly score")
        ax.set_ylabel("Count")
        ax.set_title("Anomaly Score Distribution")
        ax.legend(fontsize = 7, facecolor = "#1a1a1a", labelcolor = TC, edgecolor = "#2a2a2a")

        _style(ax)
        _draw(self.cv_scores)

        # ---- figure 2: confusion matrix  ---------------------

        from sklearn.metrics import confusion_matrix as _cm
        cm = _cm(labels, np.where(preds == -1, 1, 0))
        ax = self.cv_cm.ax
        ax.clear()
        im = ax.imshow(cm, interpolation = "nearest", cmap = plt.cm.Greens) # type = ignore
        ax.set_title("Confusion Matrix")
        ticks = [0, 1]
        ax.set_xticks(ticks)
        ax.set_yticks(ticks)

        ax.set_xticklabels(["Normal", "Anomaly"], color = TC, fontsize = 8)
        ax.set_yticklabels(["Normal", "Anomaly"], color = TC, fontsize = 8, rotation = 90, va = "center")

        ax.set_xlabel("Predicted", color = TC)
        ax.set_ylabel("Actual", color = TC)
        thresh = cm.max() / 2

        for i in range(cm.shape[0]):

            for j in range(cm.shape[1]):

                # decide cell text colour based on contrast against background

                if cm[i, j] > thresh:

                    cell_text_colour = "white"

                else:

                    cell_text_colour = "#888888"

                ax.text(j, i, str(cm[i, j]), ha = "center", va = "center", color = cell_text_colour, fontsize = 13, fontweight = "bold")

        for sp in ax.spines.values():

            sp.set_edgecolor("#2a2a2a")

        ax.tick_params(colors=TK)
        _draw(self.cv_cm)

        # ---- figure 3: class metrics bar chart ---------------

        from sklearn.metrics import precision_score, recall_score, f1_score

        preds_bin = np.where(preds == -1, 1, 0)
        classes   = ["Normal", "Anomaly"]
        metrics   = {

            "Precision": [
                precision_score(1 - labels, 1 - preds_bin, zero_division = 0),
                precision_score(labels,     preds_bin,     zero_division = 0),
            ],

            "Recall": [
                recall_score(1 - labels, 1 - preds_bin, zero_division = 0),
                recall_score(labels,     preds_bin,     zero_division = 0),
            ],

            "F1": [
                f1_score(1 - labels, 1 - preds_bin, zero_division = 0),
                f1_score(labels,     preds_bin,     zero_division = 0),
            ],
        }

        ax = self.cv_metrics.ax
        ax.clear()

        x = np.arange(len(classes))
        width = 0.25

        colours = ["#378ADD", "#1D9E75", "#E24B4A"]

        for i, (metric_name, values) in enumerate(metrics.items()):

            bars = ax.bar(x + i * width, values, width, label = metric_name, color = colours[i], alpha = 0.85)

            for bar, v in zip(bars, values):

                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01, f"{v*100:.0f}%", ha = "center", va = "bottom", color = TC, fontsize = 7)

        ax.set_xticks(x + width)
        ax.set_xticklabels(classes, color=TC)
        ax.set_ylim(0, 1.15)
        ax.set_ylabel("Score")
        ax.set_title("Precision / Recall / F1 by Class")

        ax.legend(fontsize = 7, facecolor = "#1a1a1a", labelcolor = TC, edgecolor = "#2a2a2a")
        _style(ax)
        _draw(self.cv_metrics)

        # ---- figure 4: feature sparability bar ------------------=

        ax = self.cv_features.ax
        ax.clear()

        if df_feat is not None:

            normal_rows  = df_feat[preds == 1]
            flagged_rows = df_feat[preds == -1]

            if len(flagged_rows) > 0:

                diffs = {}

                for col in df_feat.columns:

                    n_mean = normal_rows[col].mean()

                    f_mean = flagged_rows[col].mean()

                    # normalise by overall std so all features are on same scale

                    std = df_feat[col].std()

                    if std > 0:

                        diffs[col] = (f_mean - n_mean) / std

                diffs_sorted = sorted(diffs.items(), key = lambda x: abs(x[1]), reverse = True)[:12]

                # Helper shorten feature names so they fit the y-axis without truncation
                # strips noise prefixes  that dont add meaning,
                # then converts underscores to spaces for natural reading

                # for example below
                # api_writeprocessmemory_count -> writeprocessmemory
                # cross_process_writes_count -> cross process writes
                # has_mz_header -> has mz header

                def _short(name):

                    n = name

                    if n.startswith("api_"):

                        n = n[4:]

                    n = n.replace("_count", "").replace("_present", "")

                    n = n.replace("_", " ")

                    return n

                # split the sorted (name, value) tuples into two parallel lists
                # feat_names holds the shortened display labels
                # feat_vals holds the corresponding numeric values for the bar lengths

                feat_names = []

                feat_vals  = []

                for name, value in diffs_sorted:

                    feat_names.append(_short(name))
                    feat_vals.append(value)

                # Build the bar colour list: red for positive values blue for negative

                bar_colours = []

                for v in feat_vals:

                    if v > 0:

                        bar_colours.append("#E24B4A")

                    else:

                        bar_colours.append("#378ADD")

                bars = ax.barh(range(len(feat_vals)), feat_vals, color = bar_colours, alpha = 0.85)

                ax.set_yticks(range(len(feat_names)))

                ax.set_yticklabels(feat_names, color = TC, fontsize = 9)

                # value labels at the end of each bar so the magnitude is readable directly without measuring against the x-axis

                if feat_vals:

                    abs_values = []
                    for v in feat_vals:

                        abs_values.append(abs(v))
                    max_abs = max(abs_values)

                else:

                    max_abs = 1.0
                pad = max_abs * 0.015

                for bar, v in zip(bars, feat_vals):
                    x = bar.get_width()

                    if v >= 0:

                        ha = "left"

                    else:

                        ha = "right"

                    if v >= 0:

                        pad_signed = pad

                    else:

                        pad_signed = -pad

                    ax.text(x + pad_signed,

                            bar.get_y() + bar.get_height() / 2,
                            f"{v:+.2f}",
                            va = "center", ha = ha,
                            color = TC, fontsize = 8)

                # give long y tick labels enough room on the left and extend x axis past the value labels, so no clip at the right egde

                ax.set_xlim(-max_abs * 1.20, max_abs * 1.20)

                self.cv_features.figure.subplots_adjust(left=0.32)

                ax.axvline(0, color = "#555555", linewidth = 0.8)

                ax.set_xlabel("Normalised mean difference (flagged − normal)")
                ax.set_title("Feature Separability  (top 12)")
                ax.invert_yaxis()

        _style(ax)

        _draw(self.cv_features)

        # ---- figure 5: anomaly score vs entropy_max ccatter -------------------------------------------------

        ax = self.cv_scatter2.ax

        ax.clear()

        if df_feat is not None and "entropy_max" in df_feat.columns:

            entropy = df_feat["entropy_max"].values

            # colour each point by its anomaly score
            # blue = more normal

            sc = ax.scatter(entropy, scores, c = scores, cmap = "RdYlGn", s = 4, alpha = 0.6, rasterized = True, vmin = scores.min(), vmax = scores.max())

            ax.axhline(0, color = "#555555", linestyle = "--", linewidth = 0.8, label = "Decision boundary")

            ax.set_xlabel("entropy_max")
            ax.set_ylabel("Anomaly score")
            ax.set_title("Anomaly Score vs Entropy Max")
            ax.legend(fontsize = 7, facecolor = "#1a1a1a", labelcolor = TC, edgecolor = "#2a2a2a")

            try:

                cb = self.cv_scatter2.figure.colorbar(sc, ax = ax, pad = 0.02)
                cb.ax.tick_params(colors = TK, labelsize = 7)
                cb.outline.set_edgecolor("#2a2a2a")

            except Exception:

                pass

        _style(ax)
        _draw(self.cv_scatter2)

        # ---- figure 6: precision recall curve threshold sweep --------------------------------------------

        ax = self.cv_pr_curve.ax
        ax.clear()
        thresholds = np.linspace(0.005, 0.15, 40)
        precisions = []
        recalls = []
        f1s = []

        for t in thresholds:

            cutoff = np.percentile(scores, t * 100)
            preds_t  = np.where(scores <= cutoff, 1, 0)

            if preds_t.sum() == 0:

                precisions.append(0); recalls.append(0); f1s.append(0)
                continue

            prec = precision_score(labels, preds_t, zero_division = 0)
            rec = recall_score(labels, preds_t, zero_division = 0)
            f1 = f1_score(labels, preds_t, zero_division = 0)

            precisions.append(prec)
            recalls.append(rec)
            f1s.append(f1)

        # build percent labels for the threshold tick axis

        pct_labels = []

        for t in thresholds:

            label = "%.1f%%" % (t * 100)

            pct_labels.append(label)

        ax.plot(thresholds * 100, precisions, color = "#378ADD",

                linewidth = 1.5, label = "Precision")

        ax.plot(thresholds * 100, recalls,    color = "#E24B4A",

                linewidth = 1.5, label = "Recall")

        ax.plot(thresholds * 100, f1s,        color = "#1D9E75",

                linewidth = 1.5, label = "F1", linestyle = "--")

        # mark current contamination

        current_cont = 0.02

        ax.axvline(current_cont * 100, color = "#ffd43b", linestyle = ":", linewidth = 1.2, label = f"Current ({current_cont*100:.0f}%)")

        ax.set_xlabel("Contamination %  (threshold sweep)")
        ax.set_ylabel("Score")
        ax.set_ylim(0, 1.05)
        ax.set_title("Precision / Recall vs Threshold")

        ax.legend(fontsize = 7, facecolor = "#1a1a1a", labelcolor = TC, edgecolor = "#2a2a2a")

        _style(ax)
        _draw(self.cv_pr_curve)

        self.vis_container.setVisible(True)

        self.vis_status.setText(
            "6 charts generated. Scroll down to view."
        )

        self.vis_status.setStyleSheet("color:#00e5a0; font-size:11px;")

# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):

    def __init__(self):

        super().__init__()
        self.setWindowTitle("Memory Scanner")
        self.setMinimumSize(1200, 700)
        self.resize(1400, 800)

        self._selected_pid = None
        self._selected_pids = [] # list of pids to scan 1 for single, N for group
        self._pending_pids = [] # queue for multi-scan group mode
        self._list_worker = None
        self._scan_worker = None
        self._llm_worker = None
        self._if_train_worker = None
        self._all_processes = []
        self._scan_bundle = None

        # isolation forest runtime state

        self._if_model = None
        self._if_scaler = None
        self._if_features = None
        self._last_verify_data = None # cached after _run_verification for Visualise

        self._setup_ui()
        self._redirect_stdout()
        self._load_settings() # restore saved state before first refresh
        self._connect_persist_signals()
        self._connect_if_signals()
        self._try_autoload_if_model()
        self._refresh_processes()

    # ---------------------------------------------------------------
    # GUI construction
    # ------------------------------------------------------------------

    def _setup_ui(self):

        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(8)

        self.setCentralWidget(root)

        # --header bar -------------------------

        header = QWidget()
        header.setObjectName("header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(10, 6, 10, 6)

        title = QLabel("MEMORY SCANNER")
        title.setObjectName("title")

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("statusLabel")
        self.status_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.gear_btn = QPushButton("[*]")
        self.gear_btn.setObjectName("btnGear")
        self.gear_btn.setFixedSize(34, 34)
        self.gear_btn.setToolTip("Settings")
        self.gear_btn.clicked.connect(self._toggle_settings)

        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(self.status_label)
        header_layout.addSpacing(12)
        header_layout.addWidget(self.gear_btn)
        root_layout.addWidget(header)

        # -- toolbar --------------------------------------------------

        toolbar = QWidget()
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(0, 0, 0, 0)
        toolbar_layout.setSpacing(6)

        self.refresh_btn = QPushButton("[R]  Refresh Processes")
        self.refresh_btn.setObjectName("btnSecondary")
        self.refresh_btn.setFixedHeight(34)
        self.refresh_btn.clicked.connect(self._refresh_processes)

        self.scan_btn = QPushButton("[>]  Scan Selected Process")
        self.scan_btn.setObjectName("btnPrimary")
        self.scan_btn.setFixedHeight(34)
        self.scan_btn.setEnabled(False)
        self.scan_btn.clicked.connect(self._scan_selected)

        self.scan_all_btn = QPushButton("[>>]  Scan All")
        self.scan_all_btn.setObjectName("btnScanAll")
        self.scan_all_btn.setFixedHeight(34)

        self.scan_all_btn.setToolTip(

            "Scan every visible process in the list sequentially.\n"
            "Respects the 'Hide unauthorised' and 'Group by name' settings."
        )

        self.scan_all_btn.clicked.connect(self._scan_all)

        self.llm_btn = QPushButton("[AI]  Analyse with LLM")
        self.llm_btn.setObjectName("btnAI")
        self.llm_btn.setFixedHeight(34)
        self.llm_btn.setEnabled(False)

        self.llm_btn.setToolTip(

            "Send scan results to Claude for contextual threat analysis.\n"
            "Requires ANTHROPIC_API_KEY environment variable."
        )

        self.llm_btn.clicked.connect(self._run_llm_analysis)

        self.clear_btn = QPushButton("[X]  Clear")
        self.clear_btn.setObjectName("btnDanger")
        self.clear_btn.setFixedHeight(34)
        self.clear_btn.setToolTip("Clear the currently visible tab")
        self.clear_btn.clicked.connect(self._clear_active_tab)

        self.filter_input = QTextEdit()
        self.filter_input.setObjectName("filterInput")
        self.filter_input.setPlaceholderText("Filter by name or PID...")
        self.filter_input.setFixedHeight(34)
        self.filter_input.setLineWrapMode(QTextEdit.NoWrap)
        self.filter_input.textChanged.connect(self._apply_filter)

        toolbar_layout.addWidget(self.refresh_btn)
        toolbar_layout.addWidget(self.scan_btn)
        toolbar_layout.addWidget(self.scan_all_btn)
        toolbar_layout.addWidget(self.llm_btn)
        toolbar_layout.addStretch()
        toolbar_layout.addWidget(self.filter_input, 1)
        toolbar_layout.addWidget(self.clear_btn)
        root_layout.addWidget(toolbar)

        # -- stacked content area: index 0 = main, index 1 = settings -----------------------------

        self.stack = QStackedWidget()
        self.stack.setObjectName("mainStack")

        # ---- page 0: main layout splitter --------------------------

        main_page = QWidget()
        main_layout = QVBoxLayout(main_page)
        main_layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(6)
        splitter.setObjectName("splitter")

        # left: process table

        table_frame = QFrame()
        table_frame.setObjectName("tableFrame")
        table_layout = QVBoxLayout(table_frame)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(4)

        table_label = QLabel("RUNNING PROCESSES")
        table_label.setObjectName("panelLabel")
        table_layout.addWidget(table_label)

        self.table = QTableWidget()
        self.table.setObjectName("processTable")
        self.table.setColumnCount(5)

        self.table.setHorizontalHeaderLabels(

            ["PID", "Name", "Integrity", "Elevated", "Path"]
        )

        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)

        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.table.itemDoubleClicked.connect(lambda _: self._scan_selected())

        table_layout.addWidget(self.table)

        self.proc_count_label = QLabel("")
        self.proc_count_label.setObjectName("countLabel")
        table_layout.addWidget(self.proc_count_label)

        # right: tabbed output
        right_frame = QFrame()
        right_frame.setObjectName("rightFrame")
        right_layout = QVBoxLayout(right_frame)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("outputTabs")

        # tab 0: HOME

        home_widget = QWidget()
        home_widget.setObjectName("tabPage")
        home_layout = QVBoxLayout(home_widget)
        home_layout.setContentsMargins(6, 6, 6, 6)
        home_layout.setSpacing(0)

        self.console = QTextEdit()
        self.console.setObjectName("console")
        self.console.setReadOnly(True)

        home_layout.addWidget(self.console)

        self.tabs.addTab(home_widget, "  HOME  ")

        # Tab 1: LLM

        llm_widget = QWidget()
        llm_widget.setObjectName("tabPage")
        llm_layout = QVBoxLayout(llm_widget)
        llm_layout.setContentsMargins(6, 6, 6, 6)
        llm_layout.setSpacing(4)

        self.llm_info_label = QLabel(

            "  No analysis yet. Run a scan then click  [AI] Analyse with LLM."
        )

        self.llm_info_label.setObjectName("llmInfoLabel")
        llm_layout.addWidget(self.llm_info_label)
        self.llm_console = QTextEdit()
        self.llm_console.setObjectName("llmConsole")
        self.llm_console.setReadOnly(True)

        llm_layout.addWidget(self.llm_console)

        self.tabs.addTab(llm_widget, "  LLM  ")

        right_layout.addWidget(self.tabs)

        splitter.addWidget(table_frame)
        splitter.addWidget(right_frame)
        splitter.setSizes([480, 820])
        main_layout.addWidget(splitter)
        self.stack.addWidget(main_page)

        # ---- page 1: settings panel ----------------------------------

        self.settings_panel = SettingsPanel()
        self.settings_panel.back_btn.clicked.connect(self._toggle_settings)
        self.stack.addWidget(self.settings_panel)

        # ---- page 2: verify panel ------------------------------------

        self.verify_panel = VerifyPanel()
        self.verify_panel.back_btn.clicked.connect(self._show_settings_from_verify)
        self.verify_panel.run_btn.clicked.connect(self._run_verification)
        self.verify_panel.vis_btn.clicked.connect(self._run_visualise)
        self.stack.addWidget(self.verify_panel)

        root_layout.addWidget(self.stack, 1)

    def _redirect_stdout(self):

        sys.stdout = StdoutRedirector(self.console)

    # ------------------------------------------------------------------
    # Settings toggle
    # ------------------------------------------------------------------

    STACK_MAIN = 0
    STACK_SETTINGS = 1
    STACK_VERIFY = 2

    def _toggle_settings(self):

        if self.stack.currentIndex() == self.STACK_MAIN:

            self.stack.setCurrentIndex(self.STACK_SETTINGS)

            self.gear_btn.setStyleSheet(

                "background: #1a0a2e; border: 1px solid #9b59b6; color: #c39bd3;"
                "border-radius: 3px;"
            )

        else:

            self.stack.setCurrentIndex(self.STACK_MAIN)
            self.gear_btn.setStyleSheet("")  # revert to stylesheet default

    # ------------------------------------------------------------------
    # tab helpers
    # ------------------------------------------------------------------

    TAB_HOME = 0
    TAB_LLM  = 1

    def _switch_tab(self, index: int):

        self.tabs.setCurrentIndex(index)

    # ------------------------------------------------------------------
    # process list
    # ------------------------------------------------------------------

    def _refresh_processes(self):

        self._set_status("Loading processes...", busy = True)

        self.refresh_btn.setEnabled(False)
        self.table.setRowCount(0)
        self._selected_pid = None
        self.scan_btn.setEnabled(False)
        self.llm_btn.setEnabled(False)
        self._scan_bundle = None

        self._list_worker = ProcessListWorker()

        self._list_worker.finished.connect(self._on_processes_loaded)
        self._list_worker.error.connect(self._on_list_error)
        self._list_worker.start()

    def _on_processes_loaded(self, processes):

        self._all_processes = processes
        self._populate_table(processes)
        self.refresh_btn.setEnabled(True)

        self._set_status(

            f"{len(processes)} processes  |  double-click or select + Scan"
        )


    def _on_list_error(self, msg):

        self._log_home(f"[ERROR] Failed to list processes: {msg}")
        self.refresh_btn.setEnabled(True)
        self._set_status("Error loading processes")

    def _populate_table(self, processes):

        sp = self.settings_panel

        # if denied filter

        if sp.hide_denied:

            denied_names = {'<access denied>', 'unknown', ''}

            # keep only processes whose name isnt in the denied set and does not look like a placeholder name

            filtered = []

            for p in processes:

                if p.name.lower() in denied_names:

                    continue

                if p.name.startswith('<'):

                    continue

                filtered.append(p)

            processes = filtered

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)

        if sp.group_processes:

            # group by name, collecting all PIDs per name

            groups: dict = {}

            for p in processes:

                groups.setdefault(p.name, []).append(p)

            for name, procs in groups.items():

                row = self.table.rowCount()

                self.table.insertRow(row)


                count = len(procs)

                if count > 1:

                    display_name = f"{name}  x{count}"

                else:

                    display_name = name

                # collect PIDs from all processes sharing the same name

                pids = []

                for p in procs:

                    pids.append(p.pid)

                if count == 1:

                    pid_text = str(pids[0])

                else:

                    pid_text = f"{pids[0]}…"

                pid_item = QTableWidgetItem(pid_text)
                name_item = QTableWidgetItem(display_name)
                integrity_item = QTableWidgetItem(procs[0].integrity)

                # format elevated flag and path before placing into the table

                if procs[0].elevated:

                    elevated_text = "Yes"

                else:

                    elevated_text = "No"

                elevated_item = QTableWidgetItem(elevated_text)

                if count == 1:

                    path_text = procs[0].path

                else:

                    path_text = "(multiple)"

                path_item = QTableWidgetItem(path_text)


                colour_map = {
                    "system": "#ff6b6b", "high": "#ffa94d",
                    "medium": "#74c0fc", "low":  "#868e96",
                }

                integrity_item.setForeground(
                    QColor(colour_map.get(procs[0].integrity.lower(), "#aaa"))
                )

                if procs[0].elevated:
                    elevated_item.setForeground(QColor("#ffa94d"))

                # store the full pid list in UserRole so scan can retrieve it

                for item in (pid_item, name_item, integrity_item, elevated_item, path_item):
                    item.setData(Qt.UserRole, pids)

                self.table.setItem(row, 0, pid_item)
                self.table.setItem(row, 1, name_item)
                self.table.setItem(row, 2, integrity_item)
                self.table.setItem(row, 3, elevated_item)
                self.table.setItem(row, 4, path_item)

            shown = len(groups)

        else:

            for proc in processes:

                row = self.table.rowCount()
                self.table.insertRow(row)

                pid_item = QTableWidgetItem()
                pid_item.setData(Qt.DisplayRole, proc.pid)
                name_item = QTableWidgetItem(proc.name)
                integrity_item = QTableWidgetItem(proc.integrity)

                if proc.elevated:

                    elevated_text = "Yes"

                else:

                    elevated_text = "No"

                elevated_item  = QTableWidgetItem(elevated_text)
                path_item = QTableWidgetItem(proc.path)

                colour_map = {
                    "system": "#ff6b6b", "high": "#ffa94d",
                    "medium": "#74c0fc", "low":  "#868e96",
                }

                integrity_item.setForeground(

                    QColor(colour_map.get(proc.integrity.lower(), "#aaa"))
                )

                if proc.elevated:

                    elevated_item.setForeground(QColor("#ffa94d"))

                for item in (pid_item, name_item, integrity_item, elevated_item, path_item):
                    item.setData(Qt.UserRole, [proc.pid])

                self.table.setItem(row, 0, pid_item)
                self.table.setItem(row, 1, name_item)
                self.table.setItem(row, 2, integrity_item)
                self.table.setItem(row, 3, elevated_item)
                self.table.setItem(row, 4, path_item)

            shown = len(processes)

        self.table.setSortingEnabled(True)
        self.proc_count_label.setText(f"Showing {shown} entries")

    # ------------------------------------------------------------------
    # Filter
    # ------------------------------------------------------------------

    def _apply_filter(self):

        text = self.filter_input.toPlainText().strip().lower()

        if not text:

            self._populate_table(self._all_processes)

            return

        # match if the filter text appears in the process name or the PID

        matched = []

        for p in self._all_processes:

            if text in p.name.lower():

                matched.append(p)

                continue

            if text in str(p.pid):

                matched.append(p)

        self._populate_table(matched)

    # ------------------------------------------------------------------
    # selection
    # ------------------------------------------------------------------

    def _on_selection_changed(self):

        rows = self.table.selectedItems()

        if rows:

            pids = rows[0].data(Qt.UserRole)  # always a list now

            # normalise the pids to always be a list

            if isinstance(pids, list):

                self._selected_pids = pids

            else:

                self._selected_pids = [pids]

            self._selected_pid  = self._selected_pids[0]
            self.scan_btn.setEnabled(True)

            if len(self._selected_pids) > 1:

                if len(rows) > 1:

                    name = rows[1].text().split('  x')[0]

                else:

                    name = ""

                self.scan_btn.setText(

                    f"[>]  Scan  {name}  ({len(self._selected_pids)} PIDs)"
                )

            else:

                self.scan_btn.setText(f"[>]  Scan  PID {self._selected_pid}")

        else:

            self._selected_pid  = None
            self._selected_pids = []
            self.scan_btn.setEnabled(False)
            self.scan_btn.setText("[>]  Scan Selected Process")

    # ------------------------------------------------------------------
    # scan
    # ------------------------------------------------------------------

    def _scan_selected(self):

        if not self._selected_pids:

            return

        if self.stack.currentIndex() == self.STACK_SETTINGS:

            self._toggle_settings()

        self._switch_tab(self.TAB_HOME)

        # load the full queue from the selection
        # then start scan

        # copy so selection changes do nkt affect it

        self._pending_pids = list(self._selected_pids)
        total = len(self._pending_pids)
        pid = self._pending_pids.pop(0)

        if total > 1:

            self._log_home(f"\n{'=' * 60}")
            self._log_home(f"  Group scan: {total} PIDs queued")
            self._log_home(f"{'=' * 60}\n")

        else:

            self._log_home(f"\n{'=' * 60}")
            self._log_home(f"  Scanning PID {pid} ...")
            self._log_home(f"{'=' * 60}\n")

        self._start_single_scan(pid)

    def _scan_all(self):

        """
        scan every visible process in the list sequentially.

        applies the same filtering logic used by _populate_table so what you see is exactly what gets scanned:

          - If Hide unauthorised is on  → access-denied / unknown processes skipped
          - If Group by name is on → one PID per group (the first in each group), consistent with how the table collapses rows
          - Text filter is intentionally ignored — scan all, not just filtered view
        """

        if not self._all_processes:

            self._log_home("[!] No processes loaded — click Refresh first.")

            return

        sp = self.settings_panel

        # apply the same hide denied filter as _populate_table

        processes = self._all_processes

        if sp.hide_denied:

            denied_names = {'<access denied>', 'unknown', ''}

            # keep only processes whose name isn't in the denied set

            filtered = []

            for p in processes:

                if p.name.lower() in denied_names:

                    continue
                if p.name.startswith('<'):

                    continue

                filtered.append(p)

            processes = filtered

        if not processes:

            self._log_home("[!] No processes to scan after applying filters.")

            return

        # build the PID list: one pid per visible entry

        if sp.group_processes:

            # if grouped mode: collect all pids from every group exactly as _populate_table does and scan all pids in the group

            groups: dict = {}

            for p in processes:

                groups.setdefault(p.name, []).append(p)

            pids: list[int] = []

            for procs in groups.values():

                # add every process's PID to the pids list

                for proc in procs:

                    pids.append(proc.pid)
        else:

            pids = []

            for p in processes:

                pids.append(p.pid)

        total = len(pids)

        if total == 0:

            self._log_home("[!] No PIDs to scan.")

            return

        # switch to HOME tab and log the job header

        if self.stack.currentIndex() != self.STACK_MAIN:

            self.stack.setCurrentIndex(self.STACK_MAIN)

        self._switch_tab(self.TAB_HOME)

        filter_note = ""

        if sp.hide_denied:

            filter_note += "  |  unauthorised processes hidden"

        if sp.group_processes:

            filter_note += "  |  grouped mode (all PIDs per group included)"

        self._log_home(
            f"\n{'=' * 62}\n"
            f"  SCAN ALL  —  {total} process(es) queued{filter_note}\n"
            f"{'=' * 62}\n"
        )

        # load queue and start 
        # works the same as group scan so progress reporting and csv logging is the same

        self._pending_pids = pids[1:]
        self._start_single_scan(pids[0])

    def _start_single_scan(self, pid: int):

        """Launch ScanWorker for one pid. Called for first scan and each queued follow-up."""

        self.scan_btn.setEnabled(False)
        self.scan_all_btn.setEnabled(False)
        self.refresh_btn.setEnabled(False)
        self.llm_btn.setEnabled(False)
        self._scan_bundle = None

        self._set_status(f"Scanning PID {pid}...", busy = True)

        self._scan_worker = ScanWorker(pid)
        self._scan_worker.finished.connect(self._on_scan_done)
        self._scan_worker.error.connect(self._on_scan_error)
        self._scan_worker.start()

    def _on_scan_done(self, proc):

        quiet = self.settings_panel.quiet_mode

        if quiet and hasattr(sys.stdout, 'suppress'):

            sys.stdout.suppress = True

        print_process_summary(proc)
        print_modules(proc)
        print_memory_regions(proc)

        allocs          = get_virtual_allocs(proc.pid)
        write_events    = get_write_detect(proc.pid, delay_ms=500)
        threads         = get_thread_info(proc.pid)
        remote_threads  = get_remote_threads(proc.pid, delay_ms=500)
        mapped_modules  = get_mapped_modules(proc.pid)
        protect_changes = get_protect_changes(proc.pid, delay_ms=500)
        nt_info         = get_nt_syscall_info(proc.pid)
        handles         = get_handle_audit(proc.pid)

        print_virtual_allocs(proc.pid, proc.name)
        print_protect_changes(proc.pid, proc.name)
        print_write_detect(proc.pid, proc.name)
        print_nt_syscall_info(proc.pid, proc.name)
        print_thread_info(proc.pid, proc.name)
        print_remote_threads(proc.pid, proc.name)
        print_mapped_modules(proc.pid, proc.name)
        print_handle_audit(proc.pid, proc.name)

        api_snapshot = None

        try:

            api_snapshot = get_api_activity_snapshot(proc.pid)
            self._print_api(api_snapshot, proc.name)

        except AttributeError as e:

            print(f"\n[!] API activity snapshot skipped: {e}")

        perf = get_perf_snapshot(proc.pid, delay_ms = 1000)

        self._print_perf(perf, proc.name)

        samples = collect_memory_samples(

            pid = proc.pid,
            allocs = allocs,
            threads = threads,
            remote_threads = remote_threads,
            mapped_modules = mapped_modules,
            write_events = write_events,
        )

        print_memory_samples(samples)

        # restore console output -------------------------------------------

        if hasattr(sys.stdout, 'suppress'):
            sys.stdout.suppress = False

        # build bundle

        self._scan_bundle = ScanBundle(
            proc = proc,
            allocs  = allocs,
            protect_changes = protect_changes,
            write_events = write_events,
            nt_info = nt_info,
            threads = threads,
            remote_threads = remote_threads,
            mapped_modules = mapped_modules,
            handles = handles,
            memory_samples = samples,
            api_snapshot = api_snapshot,
            perf = perf,
        )

        # -- rule engine --

        if _RULE_ENGINE_AVAILABLE:

            try:

                rule_result = evaluate_rules(self._scan_bundle)

                self._scan_bundle.rule_result = rule_result

                self._log_home("\n" + fmt_rule_console(rule_result) + "\n")

            except Exception as exc:

                self._log_home(f"[RULE ENGINE ERROR] {exc}")

        # -- isolation Forest inference ------

        self._run_if_inference(self._scan_bundle)

        # -- csv logging ----

        self._maybe_write_csv()

        # -- JSON logging ------------------

        self._maybe_write_json()

        # always log essential summary
        # format perf values with a fallback when no sample is available

        if perf and perf.sample_ok:

            cpu = f"{perf.cpu_percent:.2f}%"

        else:

            cpu = "n/a"

        if perf and perf.sample_ok:

            ws = f"{perf.working_set_kb/1024:.1f} MB"

        else:

            ws = "n/a"

        self._log_home(

            f"[OK] {proc.name} (PID {proc.pid})  |  "
            f"{len(proc.modules)} modules  |  {len(proc.memory_regions)} regions  |  "
            f"CPU {cpu}  WS {ws}"
        )

        # -- multi scan queue: start next PID if pending --

        if self._pending_pids:

            next_pid = self._pending_pids.pop(0)
            remaining = len(self._pending_pids)

            if remaining:

                suffix = f"  ({remaining} more after this)"

            else:

                suffix = "  (last in group)"

            self._log_home(

                f"  -> Next: PID {next_pid}"
                + suffix
            )

            self._start_single_scan(next_pid)

            return

        # -- All scans complete --
        self.scan_btn.setEnabled(True)
        self.scan_all_btn.setEnabled(True)
        self.refresh_btn.setEnabled(True)
        self.llm_btn.setEnabled(True)

        self._set_status(
            f"Scan complete  -  {proc.name} (PID {proc.pid})  |  "
            f"{len(proc.modules)} modules  |  {len(proc.memory_regions)} regions  |  "
            f"Ready for AI analysis"
        )

        if not quiet:

            self._log_home(

                "\n[OK] Scan complete. "
                "Click [AI] Analyse with LLM to run AI analysis.\n"
            )

        self.console.moveCursor(QTextCursor.End)

    def _on_scan_error(self, msg):

        self._log_home(f"[ERROR] Scan failed: {msg}")
        self.scan_btn.setEnabled(True)
        self.scan_all_btn.setEnabled(True)
        self.refresh_btn.setEnabled(True)
        self._set_status("Scan failed")

    # ------------------------------------------------------------------
    # Perf printer
    # ------------------------------------------------------------------

    def _print_api(self, snap, name: str):

        """Print an API activity snapshot already collected. No extra scan."""

        if snap is None:

            return

        if hasattr(snap, 'counts'):

            counts = snap.counts

        else:

            counts = snap.get('counts', {})

        if hasattr(snap, 'timeline'):

            timeline = snap.timeline

        else:

            timeline = snap.get('timeline', [])

        if hasattr(snap, 'window_ms'):

            window = snap.window_ms

        else:

            window = snap.get('window_ms', 1000)

        if hasattr(snap, 'samples_taken'):

            taken = snap.samples_taken

        else:

            taken = snap.get('samples_taken', 0)


        # support both object and dict access

        def _c(key):

            if isinstance(counts, dict):

                return counts.get(key, 0)

            return getattr(counts, key, 0)

        if taken > 1:

            interval = window // max(taken - 1, 1)

        else:

            interval = window

        print(f"\nAPI activity snapshot for {name}")
        print(f"  Window: {window}ms  |  {taken} sub-samples  |  ~{interval}ms interval")
        print(f"\n  Inferred call counts")
        print(f"  VirtualAllocEx        : {_c('virtual_alloc')}")
        print(f"  VirtualProtect        : {_c('virtual_protect')}")
        print(f"  WriteProcessMemory    : {_c('write_memory')}")
        print(f"  CreateRemoteThread    : {_c('create_thread')}")
        print(f"  Total events          : {_c('total')}")

        if timeline:

            print(f"\n  Timeline  ({len(timeline)} events)")
            print(f"  {'ms':>6}  {'Type':<12} {'Detail'}")
            print(f"  {'-'*60}")

            for ev in timeline:

                if isinstance(ev, dict):
                    ts  = ev.get('ts_ms', 0)
                    typ = ev.get('event_type', '')
                    det = ev.get('detail', '')

                else:

                    ts  = getattr(ev, 'ts_ms', 0)
                    typ = getattr(ev, 'event_type', '')
                    det = getattr(ev, 'detail', '')

                label = typ.replace('virtual_alloc','ALLOC').replace('virtual_protect','PROTECT') \
                           .replace('protect_exec','PROT->RX').replace('write_memory','WRITE') \
                           .replace('create_thread','THREAD')

                print(f"  {ts:>5}ms  {label:<12} {det}")

        else:

            print("\n  No events detected in observation window.")

        if hasattr(snap, 'event_sequence'):

            seq = snap.event_sequence

        else:

            seq = snap.get('event_sequence', [])

        if seq:

            if not isinstance(seq, list):

                seq_list = list(seq)

            else:

                seq_list = seq

            print(f"\n  Event sequence (distinct, first-seen order)")

            for s in seq_list:

                print(f"    {s}")

    def _print_perf(self, perf, name: str):

        """Print a PerfSnapshot that was already collected. No extra sleep."""

        from process_data import ts_us_to_iso

        pid = perf.pid

        print(f"\nPerformance metrics for {name} (PID {pid})")
        print(f"  Observation window : 1000 ms")

        if perf.scan_ts_us:

            print(f"  Scan time          : {ts_us_to_iso(perf.scan_ts_us)}")
            print(f"  Trace ID           : {perf.trace_id}")

        if not perf.sample_ok:

            print("  Could not sample process (access denied or process exited).")

            return

        bar_width = 40
        pct_capped = min(perf.cpu_percent, 100.0)
        filled = int(pct_capped / 100.0 * bar_width)
        bar = "#" * filled + "-" * (bar_width - filled)
        print(f"\nCPU%          : {perf.cpu_percent:6.2f}%  [{bar}]")

        ws_mb  = perf.working_set_kb  / 1024
        prv_mb = perf.private_bytes_kb / 1024
        pk_mb  = perf.peak_ws_kb      / 1024

        print(f"\nWorking set   : {ws_mb:8.1f} MB")
        print(f"  Private bytes : {prv_mb:8.1f} MB")
        print(f"  Peak WS       : {pk_mb:8.1f} MB")
        print(f"  Page faults   : {perf.page_faults:,}")

        def _fmt(n):

            if n < 1024:

                return f"{n} B"

            if n < 1024**2:

                return f"{n/1024:.1f} KB"

            if n < 1024**3:

                return f"{n/1024**2:.1f} MB"

            return f"{n/1024**3:.2f} GB"

        print(f"\nI/O reads     : {_fmt(perf.io_read_bytes)}  ({perf.io_read_ops:,} ops)")
        print(f"  I/O writes    : {_fmt(perf.io_write_bytes)}  ({perf.io_write_ops:,} ops)")

        if perf.io_other_bytes:
            print(f"  I/O other     : {_fmt(perf.io_other_bytes)}  ({perf.io_other_ops:,} ops)")

        print(f"\nHandles       : {perf.handle_count}")
        print(f"  Threads       : {perf.thread_count}")

    # ------------------------------------------------------------------
    # CSV logging
    # ------------------------------------------------------------------

    def _maybe_write_csv(self):

        """Write a CSV row if the toggle is on. Updates the settings status."""

        if not self.settings_panel.csv_enabled:
            return

        path = self.settings_panel.csv_path

        if not path:

            self.settings_panel.set_csv_status(
                " CSV path is empty - set a file path in Settings.", ok = False
            )

            return

        try:

            append_to_csv(self._scan_bundle, path)

            # count existing rows to show a running total

            with open(path, "r", encoding = "utf-8") as fh:

                # Count rows in the csv by looping the file handle

                row_count = 0

                for _ in fh:

                    row_count += 1

                row_count -= 1   # subtract header row

            self.settings_panel.set_csv_status(

                f"  Last write OK  -  {path}  ({row_count} rows total)", ok = True
            )

            self._log_home(f"[CSV] Row appended -> {path}  ({row_count} rows total)")

        except Exception as exc:

            msg = f"  CSV write failed: {exc}"
            self.settings_panel.set_csv_status(msg, ok = False)
            self._log_home(f"[CSV ERROR] {exc}")

    # ------------------------------------------------------------------
    # JSON logging
    # ------------------------------------------------------------------
    # mirrors _maybe_write_csv but for the JSON toggle
    # JSON writes one file per scan rather than appending to a single file
    # the directory is auto created if it doesnt exist

    def _maybe_write_json(self):

        """Write a JSON file if the toggle is on. Updates the settings status."""

        if not self.settings_panel.json_enabled:

            return

        dirpath = self.settings_panel.json_path

        if not dirpath:

            self.settings_panel.set_json_status(
                "  JSON output directory is empty - set one in Settings.", ok = False
            )

            return

        try:

            # append_to_json returns the full filepath that was written
            # this is shown in the status label so the user knows where it went

            written = append_to_json(self._scan_bundle, dirpath)

            self.settings_panel.set_json_status(

                f"  Last write OK  -  {written}",
                ok = True
            )

            self._log_home(f"[JSON] File written -> {written}")

        except Exception as exc:

            msg = f"  JSON write failed: {exc}"
            self.settings_panel.set_json_status(msg, ok = False)
            self._log_home(f"[JSON ERROR] {exc}")

    # ------------------------------------------------------------------------------------------------------------------------------------
    # llm analysis
    # ------------------------------------------------------------------

    def _run_llm_analysis(self):

        if self._scan_bundle is None:

            self._log_home("[!] No scan data available. Run a scan first.")

            return

        proc = self._scan_bundle.proc
        self._switch_tab(self.TAB_LLM)
        self.llm_console.clear()

        self.llm_info_label.setText(
            f"  Analysing  {proc.name}  (PID {proc.pid})  ..."
        )

        self._log_llm(f"{'=' * 60}")
        self._log_llm(f"  AI ANALYSIS  -  {proc.name}  (PID {proc.pid})")
        self._log_llm(f"{'=' * 60}\n")

        self.llm_btn.setEnabled(False)
        self.scan_btn.setEnabled(False)
        self.refresh_btn.setEnabled(False)
        self._set_status("Sending to Claude for analysis...", busy = True)

        self._llm_worker = LLMAnalysisWorker(self._scan_bundle)
        self._llm_worker.chunk.connect(self._on_llm_chunk)
        self._llm_worker.done.connect(self._on_llm_done)
        self._llm_worker.error.connect(self._on_llm_error)
        self._llm_worker.start()

    def _on_llm_chunk(self, text: str):

        cleaned = strip_markdown(text)

        if not cleaned:
            return

        cursor = self.llm_console.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(cleaned)

        self.llm_console.setTextCursor(cursor)
        self.llm_console.ensureCursorVisible()

    def _on_llm_done(self):

        self._log_llm(f"\n\n{'=' * 60}")
        self._log_llm("  ANALYSIS COMPLETE")
        self._log_llm(f"{'=' * 60}\n")

        self.llm_info_label.setText(

            f"  Analysis complete  -  {self._scan_bundle.proc.name} "
            f"(PID {self._scan_bundle.proc.pid})"
        )

        self.llm_btn.setEnabled(True)
        self.scan_btn.setEnabled(True)
        self.scan_all_btn.setEnabled(True)
        self.refresh_btn.setEnabled(True)

        self._set_status(

            f"AI analysis complete  -  {self._scan_bundle.proc.name} "
            f"(PID {self._scan_bundle.proc.pid})"
        )

    def _on_llm_error(self, msg: str):

        self._log_llm(f"\n[ERROR] LLM analysis failed:\n  {msg}\n")

        self._log_llm(

            "  Check that ANTHROPIC_API_KEY is set in your environment\n"
            "  and that `pip install anthropic` has been run.\n"
        )

        self.llm_info_label.setText(" Analysis failed. See output for details.")
        self.llm_btn.setEnabled(True)
        self.scan_btn.setEnabled(True)
        self.scan_all_btn.setEnabled(True)
        self.refresh_btn.setEnabled(True)
        self._set_status("AI analysis failed")

    # ------------------------------------------------------------------
    # isolation forest wiring, training, inference
    # ------------------------------------------------------------------
    # this block foucses on wiring, training and inference of the if model

    def _connect_if_signals(self):

        """Connect the IF buttons in SettingsPanel to MainWindow handlers."""

        sp = self.settings_panel
        sp.if_train_btn.clicked.connect(self._start_if_training)
        sp.if_load_btn.clicked.connect(self._on_if_load_clicked)
        sp.if_verify_btn.clicked.connect(self._show_verify)

    def _show_verify(self):

        self.stack.setCurrentIndex(self.STACK_VERIFY)

    def _show_settings_from_verify(self):

        self.stack.setCurrentIndex(self.STACK_SETTINGS)

    # ------------------------------------------------------------------
    # isolation Forest model verification
    # ------------------------------------------------------------------

    # Anomaly indicator thresholds used for VERIFICATION LABELING only
    # These must be strict enough that only genuinely-injected rows are labele anomaly
    #
    # Thresholds are deliberately tight = 
    # entropy_max   > 7.0 not 6.5  (7.0+ is clearly synth-injected territory)
    # cross_process >= 12 (5-20 was injection range; 12+ is clearly high)
    # api_writeMem  >= 10 (baseline=4; Gaussian noise reaches 8–9 normally)

    _ANOM_INDICATORS = {

        "has_mz_header": lambda v: v >= 1,
        "has_pe_header": lambda v: v >= 1,
        "entropy_max": lambda v: v > 7.0,
        "cross_process_writes_count": lambda v: v >= 12,
        "api_writeprocessmemory_count": lambda v: v >= 10,
        "api_createremotethread_count": lambda v: v >= 1,
    }

    # minimum number of indicators that must fire to label a row as anomaly
    # requiring >= 2 prevents single feature noise from polluting labels a genuinely injected row will have multiple extreme values

    _ANOM_MIN_INDICATORS = 2

    def _run_verification(self):

        """
        Run the full IF model quality verification against the synthetic CSV.
        All computation is synchronous (fast enough on 2700 rows).
        Updates VerifyPanel display sections directly.
        """

        if not _IF_DEPS_AVAILABLE:

            self.verify_panel.set_status(

                "scikit-learn / joblib not installed. "
                "pip install scikit-learn joblib numpy pandas matplotlib",
                ok = False)

            return

        if self._if_model is None or self._if_scaler is None or self._if_features is None:

            self.verify_panel.set_status(

                "No model loaded. Train or load a model first (Settings → IF Model).",
                ok = False)

            return

        synth_path = self.settings_panel.if_synth_input.text().strip()

        if not synth_path or not os.path.isfile(synth_path):

            self.verify_panel.set_status(

                "Synthetic data CSV not found. Check the path in Settings → IF Training.",

                ok = False)

            return

        try:

            import pandas as pd
            from sklearn.model_selection import train_test_split

            vp = self.verify_panel
            vp.set_status("Running verification...", ok = True)

            # ---- 1. load and prepare data --------------------------------

            df_raw = pd.read_csv(synth_path)
            df = df_raw.copy()

            # collect every column starting with meta_ like pid and timestamp etc

            meta = []

            for c in df.columns:

                if c.startswith("meta_"):
                    meta.append(c)

            # drop only those meta columns that actually exist in df

            cols_to_drop = []

            for c in meta:

                if c in df.columns:

                    cols_to_drop.append(c)
            df = df.drop(columns=cols_to_drop)

            # keep only the features the IF was trained on and only those that are actually present in the current dataframe.

            feat_cols = []

            for f in self._if_features:

                if f in df.columns:
                    feat_cols.append(f)

            df_feat = df[feat_cols].copy()

            for col in df_feat.columns:
                df_feat.loc[df_feat[col] == MISSING, col] = 0.0

            X = df_feat.values.astype(float)
            X_scaled = self._if_scaler.transform(X)

            # ---- 2. build inferred labels --------------------------------

            # A row is labeled anomaly only when >= _ANOM_MIN_INDICATORS thresholds fire
            # htis prevents gssian noise on a single feature from polluting the label set
            # genuinely injected rows will have multiple extreme values at once.

            label_scores = np.zeros(len(df_raw), dtype = int)

            for col, cond in self._ANOM_INDICATORS.items():

                if col in df_raw.columns:

                    # apply the indicator condition to each value 

                    def _check_indicator(v):

                        if v == MISSING:

                            return False

                        return cond(float(v))

                    mask = df_raw[col].apply(_check_indicator).values
                    label_scores += mask.astype(int)

            labels = (label_scores >= self._ANOM_MIN_INDICATORS).astype(int)
            n_anomaly = labels.sum()
            n_normal = len(labels) - n_anomaly

            if n_anomaly == 0:

                vp.set_status(

                    "No anomaly rows detected in dataset using indicator thresholds. "
                    "Regenerate with anomaly injection enabled.",

                    ok = False)

                return

            # ---- 3. predict and score -------------------------------------

            preds_raw = self._if_model.predict(X_scaled) # -1 or 1
            scores    = self._if_model.decision_function(X_scaled)

            # Convert IF convention: -1 = 1 (anomaly), 1 = 0 (normal)

            preds_bin = np.where(preds_raw == -1, 1, 0)

            # ---- 4. compute metrics ------------------------------------

            prec = precision_score(labels, preds_bin, zero_division = 0)
            rec = recall_score(labels, preds_bin, zero_division = 0)
            f1 = f1_score(labels, preds_bin, zero_division = 0)
            cm = confusion_matrix(labels, preds_bin)

            # unpack confusion matrix only if it has the expected 2x2 shape otherwise downstream

            if cm.shape == (2, 2):

                tn, fp, fn, tp = cm.ravel()

            else:

                tn, fp, fn, tp = (0, 0, 0, 0)

            # false positive rate

            if (fp + tn) > 0:

                fpr  = fp / (fp + tn)

            else:

                fpr  = 0.0

            vp.update_metrics(prec, rec, f1, fpr, int(tn), int(fp), int(fn), int(tp))

            # ---- 5. classification report text -------------------------

            report = classification_report(

                labels, preds_bin,
                target_names = ["normal", "anomaly"],
                digits = 3,
                zero_division = 0
            )

            vp.update_report(

                f"<pre style='color:#888888;font-size:11px;font-family:monospace'>"
                f"{report}</pre>"
            )

            # ---- 6. charts ---------------------------------------------

            vp.update_charts(scores, labels, preds_raw)
            vp.update_scatter(df_feat, preds_raw)

            # cache data so Visualise button can re use without reloading

            self._last_verify_data = {

                "scores": scores,
                "labels": labels,
                "preds": preds_raw,
                "df_feat": df_feat,
            }

            vp.vis_btn.setEnabled(True)

            # ---- 7. overfitting check --------------------

            idx = np.arange(len(X_scaled))

            idx_train, idx_test = train_test_split(

                idx, test_size = 0.30, random_state = 42, stratify = labels
            )

            from sklearn.ensemble import IsolationForest as _IF

            tmp = _IF(

                n_estimators = self._if_model.n_estimators,
                contamination = self._if_model.contamination,
                random_state = 42,
                n_jobs = -1,
            )

            tmp.fit(X_scaled[idx_train])
            train_scores = tmp.decision_function(X_scaled[idx_train])
            test_scores  = tmp.decision_function(X_scaled[idx_test])
            diff = abs(train_scores.mean() - test_scores.mean())

            overfit_ok = diff < 0.005

            # pick the human readable verdict text

            if overfit_ok:

                overfit_verdict_text = "No overfitting detected ✓"

            else:

                overfit_verdict_text = "Slight variance — normal for IF"

            vp.update_overfit(

                f"Train mean score: {train_scores.mean():.4f}  |  "
                f"Test mean score: {test_scores.mean():.4f}  |  "
                f"Difference: {diff:.4f}  →  "
                f"{overfit_verdict_text}",
                ok = overfit_ok
            )

            # ---- 7b. Mann-Whitney U test  -------------
            # Compares the anomaly score distributions of normal rows vv anomaly labelled rows
            #
            # The labels array built in step 2 is the grouping variable:
            #   labels == 0  =  normal rows
            #   labels == 1  =  anomaly rows

            try:

                from scipy.stats import mannwhitneyu

                normal_scores  = scores[labels == 0]
                anomaly_scores = scores[labels == 1]

                # two-sided test: are the distributions different?
                # The verdict text below is the same regardless because the ml assigns more negative scores to anomalies by design.

                mw_result = mannwhitneyu(

                    normal_scores, anomaly_scores,
                    alternative = 'two-sided'
                )

                vp.update_mannwhitney(

                    u_stat = float(mw_result.statistic),
                    p_value = float(mw_result.pvalue),
                    n_normal = int(len(normal_scores)),
                    n_anomaly = int(len(anomaly_scores)),

                )

            except ImportError:

                vp.update_mannwhitney_error(

                    "scipy not installed — run: pip install scipy"
                )

            except Exception as exc:

                vp.update_mannwhitney_error(

                    f"Mann-Whitney U test failed: {exc}"
                )

            # ---- 7c. mean score gap ----------------------------------------------------------------------------------------------------------------
            # numpy computation
            #  reuses the same scores and labels arrays the Mann-Whitney test used so the two metrics describe the same data partition 

            try:

                normal_scores  = scores[labels == 0]
                anomaly_scores = scores[labels == 1]

                if len(normal_scores) == 0 or len(anomaly_scores) == 0:

                    vp.update_score_gap_error(

                        "Cannot compute gap: one of the groups is empty."
                    )

                else:

                    mean_n = float(np.mean(normal_scores))
                    mean_a = float(np.mean(anomaly_scores))

                    vp.update_score_gap(

                        mean_normal = mean_n,
                        mean_anomaly = mean_a,
                        n_normal = int(len(normal_scores)),
                        n_anomaly = int(len(anomaly_scores)),
                    )

            except Exception as exc:

                vp.update_score_gap_error(

                    f"Mean score gap calculation failed: {exc}"
                )

            # ---- 8. Rules vs ML comparison text -------------------------

            if _RULE_ENGINE_AVAILABLE and self._scan_bundle is not None:
                rule_r = self._scan_bundle.rule_result

                if rule_r:

                    last_score = scores[-1]

                    last_pred = preds_raw[-1]

                    if last_pred == 1 or last_score >= 0:

                        if_label = "Normal"

                    elif last_score >= -0.05:

                        if_label = "Suspicious"

                    elif last_score >= -0.10:

                        if_label = "Likely malicious"

                    else:

                        if_label = "Highly malicious"

                    comparison = (
                        f"Last scan — Rule engine: {rule_r.label.upper()} "
                        f"({rule_r.confidence*100:.0f}%)  |  "
                        f"IF: {if_label.upper()} (score {last_score:.4f})\n\n"
                        "All three layers (rules / IF / LLM) now share the "
                        "same verdict vocabulary so they can be compared "
                        "directly:\n"
                        "  Normal   /  Suspicious   /  Likely malicious   /  Highly malicious\n\n"
                        "Interpretation guide:\n"
                        "  Rules NORMAL + IF NORMAL    → Safe (confirmed clean by both layers)\n"
                        "  Rules ≥SUSP  + IF ≥SUSP     → Threat (both layers agree)\n"
                        "  Rules ≥SUSP  + IF NORMAL    → Pattern caught by rules that ML missed\n"
                        "  Rules NORMAL + IF ≥SUSP     → Structural outlier ML caught that rules missed\n\n"
                        f"Overall model: {len(df_raw)} rows  |  "
                        f"{n_anomaly} labeled anomaly  |  "
                        f"{n_normal} labeled normal  |  "
                        f"Precision {prec*100:.1f}%  Recall {rec*100:.1f}%  F1 {f1*100:.1f}%"

                    )

                    vp.update_comparison(comparison)
            else:

                vp.update_comparison(

                    f"Dataset: {len(df_raw)} rows  |  "
                    f"Labeled anomaly: {n_anomaly}  |  "
                    f"Labeled normal: {n_normal}\n\n"
                    "Scan a process and run verification again to see Rules vs IF comparison."
                )

            # ---- Done --------------------------------------------------
            # decide the overall secondary verifier verdict from the three core metrics
            # 
            # three tiers: GOOD if both precision and recall are strong
            # ACCEPTABLE if both are moderate
            # otherwise needs more data

            if prec > 0.7 and rec > 0.7 and fpr < 0.05:

                verdict = "GOOD"

            elif prec > 0.5 and rec > 0.5:

                verdict = "ACCEPTABLE"

            else:

                verdict = "NEEDS MORE DATA"

            vp.set_status(

                f"Verification complete  |  Precision {prec*100:.1f}%  "
                f"Recall {rec * 100:.1f}%  F1 {f1 * 100:.1f}%  FPR {fpr * 100:.1f}%  "
                f"→  {verdict}",
                ok = (verdict == "GOOD")
            )

        except Exception as exc:

            import traceback

            self.verify_panel.set_status(

                f"Verification failed: {exc}", ok = False)

            self._log_home(f"[IF VERIFY ERROR] {traceback.format_exc()}")

    def _try_autoload_if_model(self):

        """On startup, try to load model files from the configured output dir."""

        sp = self.settings_panel

        out_dir = sp.if_model_dir_input.text().strip()

        if not out_dir:
            return

        model_path = os.path.join(out_dir, "if_model.pkl")
        scaler_path = os.path.join(out_dir, "if_scaler.pkl")
        feature_path = os.path.join(out_dir, "if_features.json")

        # only auto load when ALL three files exist together 

        all_present = True

        for p in (model_path, scaler_path, feature_path):

            if not os.path.isfile(p):
                all_present = False
                break

        if all_present:

            self._load_if_model(model_path, scaler_path, feature_path, silent = True)

    def _load_if_model(self, model_path: str, scaler_path: str, feature_path: str, silent: bool = False):

        """Load IF model, scaler and feature list from disk."""

        if not _IF_DEPS_AVAILABLE:

            if not silent:

                self._log_home("[IF] joblib/sklearn not installed — cannot load model.")

            return

        import json as _json

        try:
            self._if_model = joblib.load(model_path)
            self._if_scaler = joblib.load(scaler_path)

            with open(feature_path) as fh:
                self._if_features = _json.load(fh)

            msg = (f"Model loaded: {len(self._if_features)} features  |  " f"{self._if_model.n_estimators} trees  |  " f"contamination={self._if_model.contamination}")

            self.settings_panel.set_if_model_status(msg, ok = True)

            if not silent:

                self._log_home(f"[IF] {msg}")
                self._log_home(f"[IF] Ready — anomaly scoring active on every scan.")

        except Exception as exc:

            self._if_model = self._if_scaler = self._if_features = None
            self.settings_panel.set_if_model_status(f"Load failed: {exc}", ok = False)

            if not silent:
                self._log_home(f"[IF ERROR] Failed to load model: {exc}")

    def _on_if_load_clicked(self):

        sp = self.settings_panel
        model_path = sp.if_model_path_input.text().strip()

        if not model_path or not os.path.isfile(model_path):
            sp.set_if_model_status("Model file not found — check the path.", ok = False)
            return

        out_dir = os.path.dirname(model_path)
        scaler_path = os.path.join(out_dir, "if_scaler.pkl")
        feature_path = os.path.join(out_dir, "if_features.json")

        self._load_if_model(model_path, scaler_path, feature_path)

    def _extract_if_features(self, bundle) -> dict:

        """
        build the 21 feature dict from a live ScanBundle

        Column names must exactly match those used during training.
        Missing / unavailable values use the MISSING sentinel (-1), which train_if.py imputes to 0.0 before fitting
        """

        KUSER = 0x7FFE0000

        def _is_exec(protect: str) -> bool:

            p = (protect or "").upper()

            return "RX" in p or "WX" in p or "RWX" in p or " X" in p

        def _api(key: str) -> int:

            snap = bundle.api_snapshot
            if snap is None:

                return 0

            counts = getattr(snap, "counts", None)
            if counts is None:

                return 0

            if isinstance(counts, dict):

                return counts.get(key, 0)

            return getattr(counts, key, 0)

        proc = bundle.proc
        allocs = bundle.allocs or []
        perf = bundle.perf
        has_perf = perf and getattr(perf, "sample_ok", False)

        # build subsets of allocs by characteristic

        exec_allocs = []

        for a in allocs:

            if _is_exec(getattr(a, "protect", "")):
                exec_allocs.append(a)

        rw_allocs = []

        for a in allocs:

            protect_text = (getattr(a, "protect", "") or "").upper()

            if "RW" in protect_text and "X" not in protect_text:
                rw_allocs.append(a)

        mz_allocs = []

        for a in allocs:

            if getattr(a, "has_mz", False):

                mz_allocs.append(a)

        pe_allocs = []

        for a in allocs:

            if getattr(a, "has_pe", False):

                pe_allocs.append(a)

        # entropy across all allocs with valid readings

        entropies = []

        for a in allocs:

            value = getattr(a, "entropy", -1)

            if value is None:

                value = -1

            if value >= 0:

                entropies.append(value)

        # fold the entropies list into mean and max, with sentinel fallbacks for the empty case

        if entropies:

            entropy_mean = round(sum(entropies) / len(entropies), 4)
            entropy_max  = round(max(entropies), 4)

        else:

            entropy_mean = MISSING
            entropy_max = MISSING

        # Private committed memory regions

        private_committed = []

        for r in proc.memory_regions:

            if getattr(r, "type", "") != "Private":

                continue

            if getattr(r, "state", "") != "Commit":

                continue

            private_committed.append(r)

        # Cross-process writes excluding KUSER_SHARED_DATA 

        real_writes = []

        for w in (bundle.write_events or []):

            base = getattr(w, "base", 0) or 0

            if base != KUSER:

                real_writes.append(w)

        # NtQueueApcThread from a non-benign module
        BENIGN_QUEUE = {("sechost.dll", "NtQueueApcThread"), ("mswsock.dll", "NtQueueApcThread")}

        ni = bundle.nt_info
        if ni:

            imports = getattr(ni, "direct_nt_imports", []) or []

        else:

            imports = []

        ntqueue = False

        for i in imports:

            if not getattr(i, "watched", False):
                continue

            if getattr(i, "function", "") != "NtQueueApcThread":
                continue

            mod_name = getattr(i, "importing_module", "").lower()
            fn_name = getattr(i, "function", "")

            if (mod_name, fn_name) in BENIGN_QUEUE:
                continue

            ntqueue = True
            break

        # ----- pre compute every value first so the return dict below stays flat and readabl
        # ----- each line here handles one missing data fallback

        if bundle.threads:

            num_threads = len(bundle.threads)

        else:

            num_threads = 0

        if has_perf:

            num_handles = perf.handle_count
            cpu_usage = round(perf.cpu_percent, 4)
            working_set_mb = round(perf.working_set_kb / 1024, 2)
            private_bytes_mb = round(perf.private_bytes_kb / 1024, 2)
            io_read_mb = round(perf.io_read_bytes / (1024 * 1024), 2)
            io_write_kb = round(perf.io_write_bytes / 1024, 2)

        else:

            num_handles = MISSING
            cpu_usage = MISSING
            working_set_mb = MISSING
            private_bytes_mb = MISSING
            io_read_mb = MISSING
            io_write_kb = MISSING

        # three binary indicator flags
        #  — 1 if the corresponding evidence exists, 0 otherwise.

        if mz_allocs:

            has_mz_header = 1

        else:

            has_mz_header = 0

        if pe_allocs:

            has_pe_header = 1

        else:

            has_pe_header = 0

        if ntqueue:

            ntqueueapc_present = 1

        else:

            ntqueueapc_present = 0

        return {

            "num_modules": len(proc.modules),
            "num_memory_regions": len(proc.memory_regions),
            "num_private_regions": len(private_committed),
            "num_executable_regions": len(exec_allocs),
            "num_rw_regions": len(rw_allocs),
            "num_rx_regions": len(exec_allocs),
            "num_threads": num_threads,
            "num_handles": num_handles,
            "cpu_usage": cpu_usage,
            "working_set_mb": working_set_mb,
            "private_bytes_mb": private_bytes_mb,
            "io_read_mb": io_read_mb,
            "io_write_kb": io_write_kb,
            "entropy_mean": entropy_mean,
            "entropy_max": entropy_max,
            "has_mz_header": has_mz_header,
            "has_pe_header": has_pe_header,
            "cross_process_writes_count": len(real_writes),
            "api_writeprocessmemory_count": _api("write_memory"),
            "api_createremotethread_count": _api("create_thread"),
            "ntqueueapc_present": ntqueueapc_present,
        }

    def _run_if_inference(self, bundle):

        """Run IF on a scan bundle, log to HOME console, and store result on bundle."""

        if not _IF_DEPS_AVAILABLE:

            return

        if self._if_model is None or self._if_scaler is None or self._if_features is None:

            return # no model loaded = silent skip

        try:

            raw = self._extract_if_features(bundle)

            # Build feature vector in trained column order imputing MISSING = 0.0

            # Two passes for clarity:
            # first collect raw values in feature order
            # then replace the MISSING sentinel with 0.0 
            # blocks the IF from consuming the -1 sentinel 

            row = []

            for f in self._if_features:

                row.append(raw.get(f, 0.0))

            cleaned_row = []

            for v in row:

                if v == MISSING:

                    cleaned_row.append(0.0)

                else:

                    cleaned_row.append(float(v))

            row = cleaned_row

            X = np.array([row])
            X_scaled = self._if_scaler.transform(X)

            pred = self._if_model.predict(X_scaled)[0] # -1 or 1
            score = self._if_model.decision_function(X_scaled)[0] # more negative = more anomalous

            # map the anomaly score to the 4 tier verdict used by rule and llm engines
            #   score >=  0.00  =  Normal       
            #   score >= -0.05  =  Suspicious
            #   score >= -0.10  =  Likely malicious
            #   score <  -0.10  =  Highly maliciou

            if pred == 1 or score >= 0:

                verdict = "Normal"

            elif score >= -0.05:

                verdict = "Suspicious"

            elif score >= -0.10:

                verdict = "Likely malicious"

            else:

                verdict = "Highly malicious"

            if verdict == "Normal":

                colour_tag = "✓"

            else:

                colour_tag = "!"

            # store on bundle so LLM prompt can include it

            bundle.if_result = {

                "verdict": verdict,
                "score": round(float(score), 4),
                "pred_raw": int(pred),
                "n_trees": self._if_model.n_estimators,
                "contamination": self._if_model.contamination,
            }

            W = 62

            lines = [
                "=" * W,
                f"  ISOLATION FOREST  —  {bundle.proc.name}  (PID {bundle.proc.pid})",
                "=" * W,
                f"  [{colour_tag}]  Anomaly score : {score:.4f}  "
                f"(more negative = more isolated from normal cluster)",
                f"       Verdict       : {verdict.upper()}",
                "=" * W,
            ]

            self._log_home("\n" + "\n".join(lines) + "\n")

        except Exception as exc:

            self._log_home(f"[IF ERROR] Inference failed: {exc}")

    def _run_visualise(self):

        """Generate all 6 visualisation charts from cached verification data."""

        if not _IF_DEPS_AVAILABLE or not _MPL_AVAILABLE:

            self.verify_panel.vis_status.setText(
                "Requires scikit-learn and matplotlib: "
                "pip install scikit-learn matplotlib"
            )

            self.verify_panel.vis_status.setStyleSheet("color:#ff6b6b; font-size:11px;")

            return

        if self._last_verify_data is None:

            self.verify_panel.vis_status.setText(
                "Run verification first before visualising."
            )

            self.verify_panel.vis_status.setStyleSheet("color:#ffd43b; font-size:11px;")
            return

        try:

            d = self._last_verify_dataself.verify_panel.update_visualisations(

                scores  = d["scores"],
                labels  = d["labels"],
                preds   = d["preds"],
                df_feat = d["df_feat"],
            )

        except Exception as exc:

            import traceback

            self.verify_panel.vis_status.setText(f"Chart error: {exc}")
            self.verify_panel.vis_status.setStyleSheet("color:#ff6b6b; font-size:11px;")
            self._log_home(f"[VISUALISE ERROR] {traceback.format_exc()}")

    def _start_if_training(self):

        """Validate inputs and launch IFTrainWorker."""

        if not _IF_DEPS_AVAILABLE:

            self._log_home(
                "[IF] scikit-learn / joblib / numpy not installed.\n"
                "     Run: pip install scikit-learn joblib numpy pandas"
            )

            return

        sp = self.settings_panel
        synth = sp.if_synth_input.text().strip()
        out = sp.if_model_dir_input.text().strip()

        if not synth or not os.path.isfile(synth):

            sp.set_if_train_status("Synthetic data file not found.", ok = False)

            return

        if not out:

            sp.set_if_train_status("Model output directory is empty.", ok = False)

            return

        try:

            cont = float(sp.if_contamination_input.text().strip())

            if not (0.001 <= cont <= 0.5):

                raise ValueError

        except ValueError:
            sp.set_if_train_status("Contamination must be 0.001–0.5.", ok = False)
            return

        try:

            trees = int(sp.if_trees_input.text().strip())

            if trees < 10:

                raise ValueError

        except ValueError:

            sp.set_if_train_status("Trees must be an integer ≥ 10.", ok = False)

            return

        # switch to HOME tab so output is visible then go back to show progress

        self._switch_tab(self.TAB_HOME)

        self._log_home(
            f"\n{'=' * 62}\n"
            f"  ISOLATION FOREST TRAINING\n"
            f"{'=' * 62}\n"
            f"  Data        : {synth}\n"
            f"  Output dir  : {out}\n"
            f"  Trees       : {trees}   Contamination: {cont}\n"
        )

        sp.if_train_btn.setEnabled(False)
        sp.if_progress_bar.setVisible(True)
        sp.if_progress_bar.setValue(0)
        sp.set_if_train_status("Training in progress...", ok = True)

        self._if_train_worker = IFTrainWorker(synth, out, cont, trees)
        self._if_train_worker.progress.connect(self._on_if_progress)
        self._if_train_worker.log.connect(self._log_home)
        self._if_train_worker.done.connect(self._on_if_done)
        self._if_train_worker.error.connect(self._on_if_error)
        self._if_train_worker.start()

    def _on_if_progress(self, pct: int):

        self.settings_panel.if_progress_bar.setValue(pct)

    def _on_if_done(self, model_path: str, scaler_path: str, feature_path: str):

        # disconnect so queued duplicate deliveries are ignored

        try:
            self._if_train_worker.done.disconnect(self._on_if_done)

        except Exception:

            pass

        sp = self.settings_panel
        sp.if_train_btn.setEnabled(True)
        sp.if_progress_bar.setValue(100)

        sp.set_if_train_status(f"Training complete  →  {model_path}", ok = True)
        self._log_home("[IF] Training complete. Loading model automatically...")
        self._load_if_model(model_path, scaler_path, feature_path)

        sp.if_model_path_input.setText(model_path)

    def _on_if_error(self, msg: str):

        sp = self.settings_panel
        sp.if_train_btn.setEnabled(True)
        sp.if_progress_bar.setVisible(False)
        sp.set_if_train_status(f"Error: see console", ok = False)

        self._log_home(f"[IF ERROR] Training failed:\n{msg}")

    # ------------------------------------------------------------------
    # Saved settings
    # ------------------------------------------------------------------

    def _settings_dict(self) -> dict:

        sp = self.settings_panel

        return {

            "csv_enabled": sp.csv_toggle.isChecked(),
            "csv_path": sp.csv_path_input.text(),
            "json_enabled": sp.json_toggle.isChecked(),
            "json_path": sp.json_path_input.text(),
            "training_path": sp.training_path_input.text(),
            "compute_enabled": sp.compute_toggle.isChecked(),
            "stats_path": sp.stats_path_input.text(),
            "synth_path": sp.synth_path_input.text(),
            "variants": sp.variants_input.text(),
            "scale": sp.scale_input.text(),
            "adaptive": sp.adaptive_toggle.isChecked(),
            "dist_enabled": sp.dist_toggle.isChecked(),
            "split_value": sp.split_slider.value(),
            "anomaly_enabled": sp.anomaly_toggle.isChecked(),
            "anomaly_rate": sp.anomaly_rate_input.text(),
            "hide_denied": sp.hide_denied_toggle.isChecked(),
            "group_processes": sp.group_procs_toggle.isChecked(),
            "quiet_mode": sp.quiet_mode_toggle.isChecked(),
            "persist_settings": sp.persist_toggle.isChecked(),

            # IF training / mode

            "if_synth_path": sp.if_synth_input.text(),
            "if_model_dir": sp.if_model_dir_input.text(),
            "if_contamination": sp.if_contamination_input.text(),
            "if_trees": sp.if_trees_input.text(),
            "if_model_path": sp.if_model_path_input.text(),
        }

    def _save_settings(self):

        if not self.settings_panel.persist_settings:

            return

        try:

            with open(_SETTINGS_FILE, 'w', encoding = 'utf-8') as fh:

                json.dump(self._settings_dict(), fh, indent = 2)

        except Exception:

            pass # silent ignore write errors

    def _load_settings(self):

        if not os.path.isfile(_SETTINGS_FILE):

            return

        try:

            with open(_SETTINGS_FILE, 'r', encoding = 'utf-8') as fh:
                d = json.load(fh)

        except Exception:

            return

        sp = self.settings_panel

        # restore saved toggle first so _save_settings works correctly

        sp.persist_toggle.setChecked(d.get("persist_settings", False))

        if not sp.persist_settings:

            return # file exists but persist was off when it was saved

        sp.csv_toggle.setChecked(d.get("csv_enabled", False))

        if d.get("csv_path"):
            sp.csv_path_input.setText(d["csv_path"])

        sp.json_toggle.setChecked(d.get("json_enabled", False))

        if d.get("json_path"):
            sp.json_path_input.setText(d["json_path"])

        if d.get("training_path"):

            sp.training_path_input.setText(d["training_path"])
        sp.compute_toggle.setChecked(d.get("compute_enabled", False))

        if d.get("stats_path"):

            sp.stats_path_input.setText(d["stats_path"])

        if d.get("synth_path"):

            sp.synth_path_input.setText(d["synth_path"])

        if d.get("variants"):

            sp.variants_input.setText(d["variants"])

        if d.get("scale"):

            sp.scale_input.setText(d["scale"])

        sp.adaptive_toggle.setChecked(d.get("adaptive", False))
        sp.dist_toggle.setChecked(d.get("dist_enabled", False))
        sp.split_slider.setValue(d.get("split_value", 70))
        sp.anomaly_toggle.setChecked(d.get("anomaly_enabled", False))

        if d.get("anomaly_rate"):
            sp.anomaly_rate_input.setText(d["anomaly_rate"])

        sp.hide_denied_toggle.setChecked(d.get("hide_denied", False))
        sp.group_procs_toggle.setChecked(d.get("group_processes", False))
        sp.quiet_mode_toggle.setChecked(d.get("quiet_mode", False))

        # IF settings

        if d.get("if_synth_path"):

            sp.if_synth_input.setText(d["if_synth_path"])

        if d.get("if_model_dir"):

            sp.if_model_dir_input.setText(d["if_model_dir"])

        if d.get("if_contamination"):

            sp.if_contamination_input.setText(d["if_contamination"])

        if d.get("if_trees"):

            sp.if_trees_input.setText(d["if_trees"])

        if d.get("if_model_path"):

            sp.if_model_path_input.setText(d["if_model_path"])

    def _connect_persist_signals(self):

        """Wire every settings control to _save_settings so changes auto persist."""

        sp = self.settings_panel

        for toggle in (

            sp.csv_toggle, sp.json_toggle, sp.compute_toggle, sp.adaptive_toggle,
            sp.dist_toggle, sp.anomaly_toggle,
            sp.hide_denied_toggle, sp.group_procs_toggle,
            sp.quiet_mode_toggle, sp.persist_toggle,

        ):
            toggle.stateChanged.connect(self._save_settings)

        for inp in (

            sp.csv_path_input, sp.json_path_input, sp.training_path_input,
            sp.stats_path_input, sp.synth_path_input,
            sp.variants_input, sp.scale_input, sp.anomaly_rate_input,
            sp.if_synth_input, sp.if_model_dir_input,
            sp.if_contamination_input, sp.if_trees_input, sp.if_model_path_input,

        ):
            inp.textChanged.connect(self._save_settings)


        sp.split_slider.valueChanged.connect(self._save_settings)

        # The 2 process list toggles also need to repopulate the table

        sp.hide_denied_toggle.stateChanged.connect(
            lambda: self._populate_table(self._all_processes)
        )

        sp.group_procs_toggle.stateChanged.connect(
            lambda: self._populate_table(self._all_processes)
        )

    # -------------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------------

    def _clear_active_tab(self):

        if self.tabs.currentIndex() == self.TAB_HOME:

            self.console.clear()

        else:

            self.llm_console.clear()

            self.llm_info_label.setText(
                "  No analysis yet. Run a scan then click  [AI] Analyse with LLM."
            )

    def _log_home(self, text: str):

        self.console.append(text)

    def _log_llm(self, text: str):

        self.llm_console.append(text)

    def _set_status(self, text: str, busy: bool = False):

        if busy:

            colour = "#ffa94d"

        else:

            colour = "#00e5a0"

        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {colour}; font-size: 11px;")


# ---------------------------------------------------------------------------
# Stylesheet
# ---------------------------------------------------------------------------

STYLE = """

* { font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace; }

QMainWindow, QWidget {
    background-color: #0c0c0c;
    color: #c8c8c8;
}

/* -- Header -------------------------------------------------------------- */
QWidget#header {
    background: #111111;
    border-bottom: 1px solid #1e1e1e;
    border-radius: 4px;
}
QLabel#title {
    font-size: 15px;
    font-weight: bold;
    letter-spacing: 5px;
    color: #00e5a0;
}
QLabel#statusLabel { color: #00e5a0; font-size: 11px; }

/* -- Panel / count labels ------------------------------------------------ */
QLabel#panelLabel {
    font-size: 10px;
    letter-spacing: 3px;
    color: #555555;
    padding: 2px 0;
}
QLabel#countLabel { font-size: 10px; color: #404040; }
QLabel#llmInfoLabel {
    font-size: 11px;
    color: #555555;
    padding: 4px 2px;
    border-bottom: 1px solid #1a1a1a;
}

/* -- Buttons ------------------------------------------------------------- */
QPushButton {
    border-radius: 3px;
    padding: 0 14px;
    font-size: 12px;
}
QPushButton#btnScanAll {
    background: #0a1a10; border: 1px solid #2d6a4f; color: #52b788;
    border-radius: 3px; padding: 0 14px; font-size: 12px;
}
QPushButton#btnScanAll:hover {
    background: #122a1a; border: 1px solid #52b788; color: #95d5b2;
}
QPushButton#btnScanAll:disabled {
    background: #1a1a1a; border: 1px solid #2a2a2a; color: #3a3a3a;
}
QPushButton#btnPrimary {
    background: #003d29; border: 1px solid #00e5a0; color: #00e5a0;
}
QPushButton#btnPrimary:hover  { background: #005238; }
QPushButton#btnPrimary:disabled {
    background: #1a1a1a; border: 1px solid #2a2a2a; color: #3a3a3a;
}
QPushButton#btnSecondary {
    background: #1a1a1a; border: 1px solid #2e2e2e; color: #888888;
}
QPushButton#btnSecondary:hover { background: #242424; color: #aaaaaa; }
QPushButton#btnDanger {
    background: #1a1a1a; border: 1px solid #2e2e2e; color: #555555;
}
QPushButton#btnDanger:hover {
    background: #2a1010; border: 1px solid #ff6b6b; color: #ff6b6b;
}
QPushButton#btnAI {
    background: #1a0a2e; border: 1px solid #9b59b6; color: #c39bd3;
}
QPushButton#btnAI:hover {
    background: #2d1050; border: 1px solid #bb8fce; color: #e8daef;
}
QPushButton#btnAI:disabled {
    background: #1a1a1a; border: 1px solid #2a2a2a; color: #3a3a3a;
}
QPushButton#btnGear {
    background: #161616;
    border: 1px solid #2a2a2a;
    color: #555555;
    font-size: 14px;
    padding: 0;
}
QPushButton#btnGear:hover {
    background: #1e1e1e; border: 1px solid #444444; color: #aaaaaa;
}

/* -- Filter input -------------------------------------------------------- */
QTextEdit#filterInput {
    background: #161616; border: 1px solid #2a2a2a; color: #c8c8c8;
    padding: 4px 8px; border-radius: 3px; font-size: 12px;
}
QTextEdit#filterInput:focus { border: 1px solid #00e5a0; }

/* -- Splitter ------------------------------------------------------------ */
QSplitter::handle { background: #1e1e1e; }
QSplitter::handle:hover { background: #00e5a0; }

/* -- Frames -------------------------------------------------------------- */
QFrame#tableFrame, QFrame#rightFrame {
    background: #0e0e0e; border: 1px solid #1a1a1a; border-radius: 4px;
}

/* -- Tab widget ---------------------------------------------------------- */
QTabWidget#outputTabs::pane { border: none; background: #0e0e0e; }
QTabBar::tab {
    background: #111111; color: #444444;
    border: 1px solid #1e1e1e; border-bottom: none;
    padding: 6px 18px; font-size: 11px; letter-spacing: 2px; margin-right: 2px;
}
QTabBar::tab:selected {
    background: #0e0e0e; color: #00e5a0;
    border-top: 1px solid #00e5a0;
    border-left: 1px solid #1e1e1e; border-right: 1px solid #1e1e1e;
}
QTabBar::tab:hover:!selected { background: #181818; color: #888888; }
QWidget#tabPage { background: #0e0e0e; }

/* -- Table --------------------------------------------------------------- */
QTableWidget#processTable {
    background: #0e0e0e; alternate-background-color: #111111;
    gridline-color: transparent; border: none;
    font-size: 12px; selection-background-color: #003d29;
    selection-color: #00e5a0; outline: none;
}
QHeaderView::section {
    background: #161616; color: #555555; border: none;
    border-bottom: 1px solid #2a2a2a; padding: 6px 8px;
    font-size: 10px; letter-spacing: 2px;
}
QTableWidget#processTable::item { padding: 3px 6px; border: none; color: #c0c0c0; }
QTableWidget#processTable::item:selected { background: #003d29; color: #00e5a0; }

/* -- Scrollbars ---------------------------------------------------------- */
QScrollBar:vertical { background: #0e0e0e; width: 8px; border: none; }
QScrollBar::handle:vertical {
    background: #2a2a2a; border-radius: 4px; min-height: 20px;
}
QScrollBar::handle:vertical:hover { background: #00e5a0; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

/* -- Consoles ------------------------------------------------------------ */
QTextEdit#console {
    background: #080808; border: none; color: #a0a0a0;
    font-size: 12px; padding: 8px;
}
QTextEdit#llmConsole {
    background: #080808; border: none; color: #c8c8c8;
    font-size: 13px; padding: 10px 14px;
}

/* -- Settings panel ------------------------------------------------------ */
QWidget#settingsPanel { background: #0a0a0a; }

QWidget#settingsHeader {
    background: #111111;
    border-bottom: 1px solid #1e1e1e;
}
QLabel#settingsTitle {
    font-size: 13px; font-weight: bold;
    letter-spacing: 4px; color: #555555;
}

QScrollArea#settingsScroll {
    background: #0a0a0a;
    border: none;
}
QScrollBar:vertical {
    background: #0a0a0a;
    width: 6px;
    border: none;
}
QScrollBar::handle:vertical {
    background: #2a2a2a;
    border-radius: 3px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover { background: #444444; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QWidget#settingsContent { background: #0a0a0a; }

QLabel#settingsSectionLabel {
    font-size: 10px; letter-spacing: 3px;
    color: #00e5a0; padding-bottom: 4px;
    border-bottom: 1px solid #1a1a1a;
}
QLabel#settingItemLabel { font-size: 12px; color: #c8c8c8; }
QLabel#settingItemDesc  { font-size: 11px; color: #555555; }
QLabel#csvStatusLabel    { font-size: 11px; }
QLabel#buildStatusLabel  { font-size: 11px; }
QLabel#featurePrefix     { font-size: 11px; color: #00e5a0; }

QPushButton#btnBuild {
    background: #0a1a2e;
    border: 1px solid #4a9fd4;
    color: #74c0fc;
    font-size: 12px;
    border-radius: 3px;
}
QPushButton#btnBuild:hover {
    background: #0d2540;
    border: 1px solid #74c0fc;
    color: #a8d8f8;
}
QPushButton#btnBuild:disabled {
    background: #1a1a1a;
    border: 1px solid #2a2a2a;
    color: #3a3a3a;
}

QPushButton#btnSynth {
    background: #1a1a0a;
    border: 1px solid #b8860b;
    color: #ffd700;
    font-size: 12px;
    border-radius: 3px;
}
QPushButton#btnSynth:hover {
    background: #2a2a0d;
    border: 1px solid #ffd700;
    color: #ffe55c;
}
QPushButton#btnSynth:disabled {
    background: #1a1a1a;
    border: 1px solid #2a2a2a;
    color: #3a3a3a;
}

QLabel#synthStatusLabel { font-size: 11px; }

QSlider#splitSlider::groove:horizontal {
    height: 4px;
    background: #2a2a2a;
    border-radius: 2px;
}
QSlider#splitSlider::handle:horizontal {
    background: #00e5a0;
    border: 1px solid #00e5a0;
    width: 14px;
    height: 14px;
    margin: -5px 0;
    border-radius: 7px;
}
QSlider#splitSlider::handle:horizontal:hover { background: #00ffb3; }
QSlider#splitSlider::sub-page:horizontal {
    background: #003d29;
    border-radius: 2px;
}
QSlider#splitSlider:disabled::handle:horizontal { background: #333333; }
QSlider#splitSlider:disabled::sub-page:horizontal { background: #1a1a1a; }

QCheckBox#settingsToggle {
    background: transparent;
}
QCheckBox#settingsToggle::indicator {
    width: 18px; height: 18px;
    border: 1px solid #333333; border-radius: 3px;
    background: #161616;
}
QCheckBox#settingsToggle::indicator:checked {
    background: #003d29; border: 1px solid #00e5a0;
}
QCheckBox#settingsToggle::indicator:checked:hover { background: #005238; }

QLineEdit#settingsLineEdit {
    background: #161616; border: 1px solid #2a2a2a;
    color: #c8c8c8; padding: 4px 8px; border-radius: 3px;
    font-size: 11px; height: 26px;
}
QLineEdit#settingsLineEdit:focus { border: 1px solid #00e5a0; }

/* -- Verify panel metric cards ---------------------------------------- */
QWidget#verifyCard {
    background: #111111;
    border: 1px solid #1e1e1e;
    border-radius: 6px;
}
QLabel#verifyCardLabel {
    font-size: 10px; letter-spacing: 2px;
    color: #444444; text-align: center;
}
QLabel#verifyCardValue {
    font-size: 22px; font-weight: 500;
    color: #c8c8c8; text-align: center;
}

QPushButton#btnTrain {
    background: #1a0a0a;
    border: 1px solid #cc4400;
    color: #ff7043;
    font-size: 12px;
    border-radius: 3px;
}
QPushButton#btnTrain:hover {
    background: #2a1010;
    border: 1px solid #ff7043;
    color: #ffab91;
}
QPushButton#btnTrain:disabled {
    background: #1a1a1a;
    border: 1px solid #2a2a2a;
    color: #3a3a3a;
}

QProgressBar#ifProgressBar {
    background: #161616;
    border: 1px solid #2a2a2a;
    border-radius: 3px;
    text-align: center;
    color: transparent;
}
QProgressBar#ifProgressBar::chunk {
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 #cc4400, stop:1 #ff7043
    );
    border-radius: 2px;
}
"""

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():

    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":

    main()