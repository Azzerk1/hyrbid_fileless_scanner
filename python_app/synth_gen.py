"""
synth_gen.py
============
Generates synthetic process scan samples by applying Gaussian perturbations
to real rows from the training CSV, guided by the stats JSON.

Generation methods
------------------
  Noise-based (default):
    new_value = real_value + normal(0, std * scale)

  Distribution-based (part of split):
    new_value = normal(mean, std)

  Both paths clamp to [min, max] from the stats JSON.

Parameters
----------
  scale          : fixed noise scale (0.1-0.5), used when adaptive=False
  adaptive_noise : if True, per-sample scale = uniform(0.1, 0.5)
                   (static scale input is ignored)
  noise_pct      : int 0-100. Percentage of variants using noise-based method.
                   Remaining (100 - noise_pct)% use distribution-based.
                   noise_pct=100 -> all noise-based
                   noise_pct=70  -> 70/30 split
  inject_anomalies : if True, randomly flag anomaly_rate fraction of synthetic
                     rows and inject extreme values into key features
  anomaly_rate   : 0.01-0.05 (1%-5% of rows become anomalies)

Anomaly injection
-----------------
Injected anomaly features (all others keep normal perturbation):
  num_threads                  -> col_max * uniform(1.5, 3.0)
  entropy_mean                 -> uniform(7.0, 8.0)
  entropy_max                  -> uniform(6.5, 8.0)
  cross_process_writes_count   -> randint(5, 20)
  api_writeprocessmemory_count -> randint(8, 15)   [well above baseline of 4, ~3x separation]
  api_createremotethread_count -> 1
  num_executable_regions       -> randint(1, 5)
  has_mz_header                -> 1 (70% of anomaly rows)
  has_pe_header                -> 1 (60% of anomaly rows)

Physical clamps
---------------
Hard upper bounds prevent physically impossible values from noise overshooting
observed col_max (e.g. io_write_kb reaching 16 GB).  Clamps are applied after
Gaussian perturbation and before type casting.
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

import csv
import json
import os
import random

from typing import Dict, List, Tuple

from data_prep import TRAINING_COLUMNS, ALL_OUTPUT_COLUMNS, MISSING

# ---------------------------------------------------------------------------
# Column type classification
# ---------------------------------------------------------------------------

# set of columns that should always be integers
# this is needed beacuse when guassian perturbation is added, it can produce outputs like threads = 12.7
# and you cannot have a 0.7 of a thread

# uses a set due to its speed
# list would be slower here

INT_COLUMNS = {

    "num_modules", "num_memory_regions", "num_private_regions",
    "num_executable_regions", "num_rw_regions", "num_rx_regions",
    "num_threads", "num_handles",
    "cross_process_writes_count",
    "api_writeprocessmemory_count",
    "api_createremotethread_count",
}

# subset of INT_COLUMNS that are impossible to be zero in a live process
# noise can push small real values negative after rounding
# clamping these to 1 (not 0) prevents meaningless rows

# this is because every running process has at least some loaded modules, memory regions etc
# later these get rounded to minimum 1 because you cannot have -2 number of modules etc

NON_ZERO_INT_COLUMNS = {

    "num_modules", "num_memory_regions", "num_private_regions",
    "num_rw_regions", "num_threads", "num_handles",
}

# binrary values that need to be either 0 or 1
# once noise is added to these, it can produce a value like 0.3
# thats not a 1 or 0 so later it gets rounded to either

BINARY_COLUMNS = {

    "has_mz_header",
    "has_pe_header",
    "ntqueueapc_present",
}

# for entropy features only, the stats col_min is the smallest *observed* value
# (e.g. 0.029 from the KUSER_SHARED_DATA page), which would create an artificial
# cluster at the minimum if used as the clamp floor

# this is overwrited to 0.0 so noise can reach any value instead of being capped at the 0.029 floor
# and realistically processes can have 0.0 entropy

# perf features (working_set_mb etc.) are NOT in this set because they use observed col_min from stats as their floor
# this is laways set to > 0 for a running process, preventing the zero inflation caused by noise
# it would be impossible for a running process to have 0 working mb memory

FLOAT_ZERO_FLOOR_COLUMNS = {

    "entropy_mean",
    "entropy_max",
    "cpu_usage_percent",
}

# hard physical upper bounds applied AFTER Gaussian perturbation, BEFORE type casting
# prevents noise from overshooting col_max into physically impossible data
# for example: io_write_kb reaching 16 GB for a single process scan window

# values after guassian perturbation can overshoot into impossible values

# dictonary is used here because it can also store a value pair

# uses _ between numbers for readability

PHYSICAL_MAX_CLAMPS: dict = {

    "io_write_kb": 5_242_880, # 5 GB expressed in KB, 10 GB caused pile-up at ceiling
    "io_read_mb": 20_480, # 20 GB expressed in MB
    "working_set_mb": 32_768, # 32 GB
    "private_bytes_mb": 32_768, # 32 GB
    "num_modules": 2_000,
    "num_memory_regions": 100_000,
    "num_private_regions": 100_000,
    "num_rw_regions": 100_000,
    "num_threads": 2_000,
    "num_handles": 100_000,
    "num_executable_regions": 500,
    "num_rx_regions": 500,
    "cross_process_writes_count": 100,
    "api_writeprocessmemory_count": 50,
}

# features injected with anomalous values during anomaly injection
# the features in this dataset get injected with extreme values that are suspicious on purpose instead of normal guassian noise

# binary features (has_mz_header, has_pe_header) are included so anomaly rows can have MZ/PE headers present
# making them meaningfully different from the constant-zero normal distribution and giving IF a real signal to learn from

# these are choosen beacuse they are the strongest indicators of malware

ANOMALY_FEATURES = {

    "num_threads", # high thread count is risky
    "entropy_mean", # high entropy = encrypted payload
    "entropy_max", # same applies 
    "cross_process_writes_count", # writes from another process = injection
    "api_writeprocessmemory_count", # if above the baseline = activley writing to a process
    "api_createremotethread_count", # any value over 0 = remote thread
    "num_executable_regions", # private executeable memory = shellcode
    "has_mz_header", # MZ file hiding in memory
    "has_pe_header", # same applies
}

# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------

# this function applies all of the clamps from above
# it uses all of the sets to the data

def _post_process(col: str, value: float, col_min: float, col_max: float) -> object:

    """Clamp to [eff_min, col_max] then apply physical clamps, then type cast.

    Floor selection:
      - FLOAT_ZERO_FLOOR_COLUMNS (entropy): use 0.0, not observed col_min.
      - Perf float features: use observed col_min (always > 0 for a live process).
      - NON_ZERO_INT_COLUMNS: rounded int clamped to min 1.
      - All other INT_COLUMNS: clamped to min 0.
    Physical clamps (PHYSICAL_MAX_CLAMPS) are applied AFTER the stats-driven
    clamp to prevent noise from producing physically impossible values such as
    a 16 GB io_write_kb for a single process.
    The -1 sentinel is preserved before this function is ever called.
    """

    # decide which column is being used
    # if column is in float_zero_floor_columns use 0
    # otherwise the minimum from the data

    eff_min = 0.0 if col in FLOAT_ZERO_FLOOR_COLUMNS else col_min

    # clamp to the dataset range
    # it caps at the maximum / minimum
    # 1st clamp

    # both calmps are needed in this code
    # first clamp caps the data based on the max range from the scans
    # second clamp uses a hard code that camps everything despite the first clamp
    # both are needed beacuse they serve different things
    # the second clamp can't only be used otherwise some rows of data would be without a clamp at all

    value = max(min(value, col_max), eff_min)

    # hard physical ceiling
    # overrides the stats col_max when necessary

    # 2nd clamp

    if col in PHYSICAL_MAX_CLAMPS:

        value = min(value, PHYSICAL_MAX_CLAMPS[col])

    # if binary: snap to 0 or 1
    # if integer: round and clamp to 0 or 1 minimum
    # everything else: float rounded to 4 places

    if col in BINARY_COLUMNS:

        return 1 if value >= 0.5 else 0

    if col in INT_COLUMNS:

        v = int(round(value))

        return max(1, v) if col in NON_ZERO_INT_COLUMNS else max(0, v)

    return round(value, 4) # keep as float

# this function generates the anomoly values for fields which define fileless malware the most
# these values directly trigger the rule check engine thresholds
# test1

def _anomaly_value(col: str, col_stats: Dict) -> object:

    """Return a clearly anomalous value for an anomaly row feature.

    Values are chosen to be well outside the normal distribution so the
    Isolation Forest has clear separation to learn from.  The goal is not
    to be subtle — injected anomalies should be obviously weird.
    """

    # store the max value from the observed scans
    # used as a reference here

    col_max = float(col_stats.get("max", 10))

    if col == "num_threads":

        # 1.5-3x the observed maximum — unmistakably high thread count

        return int(max(col_max * random.uniform(1.5, 3.0), 100))

    if col == "entropy_mean":

        # high-entropy mean = packed/encrypted memory throughout

        return round(random.uniform(7.0, 8.0), 4)

    if col == "entropy_max":

        # full range 6.5-8.0 — clear separation from normal 3-6 range

        return round(random.uniform(6.5, 8.0), 4)

    if col == "cross_process_writes_count":

        # raised from 1-10 to 5-20: clearly above the baseline of 1

        return random.randint(5, 20)

    if col == "api_writeprocessmemory_count":

        # normal baseline is 4 (KUSER_SHARED_DATA); 8-15 gives ~3x separation vs normal mean

        return random.randint(8, 15)

    if col == "api_createremotethread_count":

        # any value > 0 is already anomalous; leave at 1

        return 1

    if col == "num_executable_regions":

        # normal processes have 0; >0 indicates private exec memory (shellcode staging)

        return random.randint(1, 5)

    if col == "has_mz_header":

        # present in 70% of anomaly rows — MZ header in private memory is a strong signal

        return 1 if random.random() < 0.70 else 0

    if col == "has_pe_header":

        # present in 60% of anomaly rows — correlated with has_mz_header

        return 1 if random.random() < 0.60 else 0

    # caller falls back to normal perturbation
    # meaning normal noise is applied
    # the above noise is only for anomolies

    return None

# ---------------------------------------------------------------------------
# Single-row variant generator
# ---------------------------------------------------------------------------

# this function generates one synthetic data row from 1 real row

def _perturb_row(

    row: Dict,
    stats: Dict,
    scale: float,
    adaptive_noise: bool,
    noise_pct: int,
    is_anomaly: bool,

) -> Dict:

    """
    Generate one synthetic variant of a real row.

    noise_pct controls the split:
      random.random() < noise_pct/100  -> noise-based
      otherwise -> distribution-based
    """

    # make synthetic rows with the timestamp syntethic and pid -1
    # this makes it easy to tell which are synthetic from real ones

    new_row = {}

    # resolve effective noise scale for this sample.
    # adaptive range tightened to 0.3 because the old upper bound of 0.5 was too aggressive

    # if on, pick a random sample between the range for this row
    # otherwise use the fixed scale found in settings

    # this happens ONCE PER ROW
    # all scales in A CLOUMN ARE THE SAME

    effective_scale = random.uniform(0.1, 0.3) if adaptive_noise else scale

    # loop through each training column

    for col in TRAINING_COLUMNS:

        raw = row.get(col)

        # preserve missing sentinel

        try:

            original = float(raw)

        except (ValueError, TypeError):

            new_row[col] = MISSING
            continue

        if original == MISSING:

            new_row[col] = MISSING
            continue

        # retreive the stats calculated from compute functions

        col_stats = stats.get(col, {})

        col_std = float(col_stats.get("std",  0.0))
        col_mean = float(col_stats.get("mean", original))
        col_min = float(col_stats.get("min",  0.0))
        col_max = float(col_stats.get("max",  original))

        # anomaly injection for flagged features

        if is_anomaly and col in ANOMALY_FEATURES:

            # if the row is flagged as anomaly AND column is in anomaly features
            # use the extreme value from _anomaly_value instead of noise

            forced = _anomaly_value(col, col_stats)

            if forced is not None:

                new_row[col] = forced
                continue

        # handle the error of 0 std instead of crashing

        if col_std == 0.0:

            new_row[col] = _post_process(col, original, col_min, col_max)
            continue

        # split: noise-based vs distribution-based

        # noise adds a small random variation to the original value
        # distrubtion completes a completly new value from the overall distribtuion

        use_noise = (random.random() * 100) < noise_pct

        if use_noise:

            value = original + random.gauss(0.0, col_std * effective_scale)

        else:

            value = random.gauss(col_mean, col_std)

        # applies all clamping and type casting from the earlier fucntion

        new_row[col] = _post_process(col, value, col_min, col_max)

    return new_row

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

# similar to build training csv

def generate_synthetic(
    training_path:    str,
    stats_path:       str,
    dest_path:        str,
    variants:         int   = 10,
    scale:            float = 0.2,
    adaptive_noise:   bool  = False,
    noise_pct:        int   = 100,
    inject_anomalies: bool  = False,
    anomaly_rate:     float = 0.02,
) -> Tuple[int, str]:

    """

    Generate synthetic rows and write to dest_path.

    Returns (row_count, status_message).
    """

    # saftey checks
    # both of the files need to exist before the syth generator runs

    if not os.path.isfile(training_path):

        return 0, f"Training CSV not found: {training_path}"

    if not os.path.isfile(stats_path):

        return 0, (
            f"Stats JSON not found: {stats_path}  |  "
            f"Build the training CSV with 'Compute statistics' enabled first."
        )

    # build a handle to read the files

    try:

        with open(stats_path, "r", encoding = "utf-8") as fh:

            stats = json.load(fh)

    except Exception as exc:

        return 0, f"Failed to read stats JSON: {exc}"

    real_rows = []

    try:

        with open(training_path, "r", newline = "", encoding = "utf-8") as fh:

            real_rows = list(csv.DictReader(fh))

    except Exception as exc:

        return 0, f"Failed to read training CSV: {exc}"

    if not real_rows:

        return 0, "Training CSV has no data rows."

    # determine how many anomaly rows to inject

    # works out how many real rows with variant
    # then if inject anomolies is true, use the anomoly % to workout how many rows will actually be anomoly based

    total_synthetic = len(real_rows) * variants
    anomaly_count = int(round(total_synthetic * anomaly_rate)) if inject_anomalies else 0

    # build set of random indices that will be anomalies

    # once the number is worked out, lets say 2% anaomly of 500 which is 10
    # it places the 10 anomoly rows at random positions in the csv

    anomaly_indices = set(random.sample(range(total_synthetic), min(anomaly_count, total_synthetic)))

    synthetic: List[Dict] = []

    idx = 0

    # outeloop goes through each real row in the csv
    # inner loop generates the variants number of synthetic versions of it
    # each gets checked against the anomoly indicies to decide if it should become anamalous

    for row in real_rows:

        for _ in range(variants):

            is_anomaly = (idx in anomaly_indices)

            synthetic.append(_perturb_row( row, stats, scale, adaptive_noise, noise_pct, is_anomaly))

            idx += 1

    # same applies as before
    # create directory, write header, write all rows

    try:

        os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok = True)

        with open(dest_path, "w", newline="", encoding="utf-8") as fh:

            writer = csv.DictWriter(fh, fieldnames=ALL_OUTPUT_COLUMNS, extrasaction="ignore")

            writer.writeheader()

            writer.writerows(synthetic)

    # catch error to avoid crash

    except Exception as exc:

        return 0, f"Failed to write synthetic CSV: {exc}"

    # build summary
    # returns count and readable summary message

    noise_note = "adaptive noise" if adaptive_noise else f"scale = {scale}"

    if noise_pct == 100:

        split_note = "100% noise-based"

    else:

        split_note = f"{noise_pct}% noise / {100 - noise_pct}% distribution"

    anomaly_note = f"  |  {anomaly_count} anomaly rows injected" if anomaly_count else ""

    msg = (
        f"{len(real_rows)} real rows x {variants} variants = "
        f"{len(synthetic)} synthetic rows  |  "
        f"{noise_note}  |  {split_note}"
        f"{anomaly_note}  ->  {dest_path}"
    )

    return len(synthetic), msg

# same applies
# find location, create folder if needed
# return path

def _get_output_dir() -> str:

    """Return (and create if needed) the output/ folder next to this script."""

    base = os.path.dirname(os.path.abspath(__file__))

    out  = os.path.join(base, "output")

    os.makedirs(out, exist_ok = True)

    return out

# returns default path for the synthetic data csv

def get_default_synth_path() -> str:

    return os.path.join(_get_output_dir(), "synthetic_data.csv")

# takes the training csv path and derives the stats json path from it

def get_default_stats_path(training_path: str) -> str:

    """Stats JSON sits alongside the training CSV, inside output/ by default."""

    base = os.path.splitext(training_path)[0]

    return base + "_stats.json"