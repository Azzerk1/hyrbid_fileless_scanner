"""
data_prep.py
============
Reads the raw_scan_data.csv produced by csv_logger.py and remaps it to a
clean, model-ready CSV with 21 per-process features.

Dataset structure
-----------------
Each ROW  = one scanned process.
Each COLUMN = one feature of that process.

No aggregate/global statistics are stored in the training CSV.
That would mix per-sample data with dataset-level constants, which adds
no information and can confuse the model.

Compute mode
------------
When compute=True, per-column statistics (mean, std, min, max) are computed
across the full dataset and saved to a SEPARATE stats.json file alongside
the training CSV. These stats are NOT written into the training CSV.

They are saved for a later step: synthetic data generation, where:
    new_value = normal(mean, std)  clamped to [min, max]

Column mapping (raw CSV -> training CSV)
-----------------------------------------
  Training column              Source column(s)
  ---------------------------  -------------------------------------------
  num_modules                  proc_module_count
  num_memory_regions           proc_region_count
  num_private_regions          alloc_total_private_committed
  num_executable_regions       mem_exec_private_count
  num_rw_regions               alloc_total_private_committed - alloc_exec_count
  num_rx_regions               alloc_exec_count
  num_threads                  thread_total
  num_handles                  perf_handle_count
  cpu_usage                    perf_cpu_percent
  working_set_mb               perf_working_set_mb
  private_bytes_mb             perf_private_bytes_mb
  io_read_mb                   perf_io_read_mb
  io_write_kb                  perf_io_write_mb * 1024
  entropy_mean                 mem_avg_exec_entropy
  entropy_max                  mem_max_exec_entropy
  has_mz_header                mem_mz_in_private_count > 0  -> 1 / 0
  has_pe_header                alloc_mz_or_pe_count > 0     -> 1 / 0
  cross_process_writes_count   write_changed_region_count
  api_writeprocessmemory_count api_write_memory_count
  api_createremotethread_count api_create_thread_count
  ntqueueapc_present           nt_high_value_import_count > 0 -> 1 / 0

Missing data
------------
Sentinel -1 in the source is preserved as -1 in the output.
Sentinel values are excluded from stats.json calculations.
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

import csv
import json
import math
import os

from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------

# csv logger produced 57 feature columns
# it is too many for the IF ml
# this module takes the 57 and reduces it down to 21 clean features
# it is litterally the data preperation step

# 3 metadata columns that are dropped later

META_OUT = [

    "meta_timestamp",
    "meta_process_name",
    "meta_pid",
]

# 21 clean per-process features - this is all that goes in the training CSV

TRAINING_COLUMNS = [

    "num_modules",
    "num_memory_regions",
    "num_private_regions",
    "num_executable_regions",
    "num_rw_regions",
    "num_rx_regions",
    "num_threads",
    "num_handles",
    "cpu_usage",
    "working_set_mb",
    "private_bytes_mb",
    "io_read_mb",
    "io_write_kb",
    "entropy_mean",
    "entropy_max",
    "has_mz_header",
    "has_pe_header",
    "cross_process_writes_count",
    "api_writeprocessmemory_count",
    "api_createremotethread_count",
    "ntqueueapc_present",
]

# combine both lists and use a -1 if missing

ALL_OUTPUT_COLUMNS = TRAINING_COLUMNS

MISSING = -1

# ---------------------------------------------------------------------------
# Row-level helpers
# ---------------------------------------------------------------------------

# convert value to float
# catch the error to avoid crash

def _safe_float(val, default = MISSING):

    try:

        return float(val)

    except (ValueError, TypeError):

        return default

# convert value to integer
# catch the error to avoid crash

def _safe_int(val, default = MISSING):

    f = _safe_float(val, default)

    return MISSING if f == MISSING else int(round(f))

# convert value to binary / boolean
# catch the error to avoid crash

# some fields contain a count, but sometimes a true or false is needed
# this function takes the value and converts it to true or false based on the input passed

def _to_binary(val):

    f = _safe_float(val, MISSING)

    if f == MISSING:

        return MISSING

    return 1 if f > 0 else 0

def transform_row(src):

    # src is the dictonary that represents one row from the raw csv before transormation
    # src.get is the method that actually reads the value from the row
    # stores the result as g

    g = src.get

    # read the total counts

    total_private = _safe_float(g("alloc_total_private_committed", ""))
    exec_count = _safe_float(g("alloc_exec_count", ""))

    if total_private != MISSING and exec_count != MISSING:

        # rw_regions does not exist in the raw csv, this is computed here
        # it computes the total private regions - executeable regions
        # prevents negative numbers if something doesn't work out in the calculation
        # this is pre calculated since 2 rows are neeeded

        rw_regions = int(round(max(0.0, total_private - exec_count)))

    else:

        rw_regions = MISSING

    # calculates MB TO KB by X by 1024
    # calculated before because it is used for storing data in the new training

    # get the value and convert to float

    io_write_mb = _safe_float(g("perf_io_write_mb", ""))

    io_write_kb = round(io_write_mb * 1024, 4) if io_write_mb != MISSING else MISSING # handle error if missing, don't crash

    # RETURN DICTONARY MAIN MAPPING
    # every line maps one TRAINING column to ONE OR MORE raw CSV columns

    return {

        "meta_timestamp": g("meta_timestamp", ""),
        "meta_process_name": g("meta_process_name", ""),
        "meta_pid": g("meta_pid", ""),

        "num_modules": _safe_int(g("proc_module_count", "")), # raw column on the right, clean training column on the left
        "num_memory_regions": _safe_int(g("proc_region_count", "")),
        "num_private_regions": _safe_int(g("alloc_total_private_committed", "")),
        "num_executable_regions": _safe_int(g("mem_exec_private_count", "")),
        "num_rw_regions": rw_regions,
        "num_rx_regions": _safe_int(g("alloc_exec_count", "")),
        "num_threads": _safe_int(g("thread_total", "")),
        "num_handles": _safe_int(g("perf_handle_count", "")),
        "cpu_usage": _safe_float(g("perf_cpu_percent", "")),
        "working_set_mb": _safe_float(g("perf_working_set_mb", "")),
        "private_bytes_mb": _safe_float(g("perf_private_bytes_mb", "")),
        "io_read_mb": _safe_float(g("perf_io_read_mb", "")),
        "io_write_kb": io_write_kb,
        "entropy_mean": _safe_float(g("mem_avg_exec_entropy", "")),
        "entropy_max": _safe_float(g("mem_max_exec_entropy", "")),
        "has_mz_header": _to_binary(g("mem_mz_in_private_count", "")),
        "has_pe_header": _to_binary(g("alloc_mz_or_pe_count", "")),
        "cross_process_writes_count": _safe_int(g("write_changed_region_count", "")),
        "api_writeprocessmemory_count": _safe_int(g("api_write_memory_count", "")),
        "api_createremotethread_count": _safe_int(g("api_create_thread_count", "")),
        "ntqueueapc_present": _to_binary(g("nt_high_value_import_count", "")),
    }

# ---------------------------------------------------------------------------
# Stats (saved separately - NOT in the training CSV)
# ---------------------------------------------------------------------------

# creates statistics to be used later by the synthetic data generation module
# for example if real data shows has a mean of 12 and std of 3, synthetic data can use this to create realistic counts using distribution

def compute_stats(rows):

    """
    Compute per-column mean, std, min, max across all rows.
    Sentinel values (-1) are excluded.

    Returns:
        {
            "num_threads": {"mean": 12.4, "std": 3.1, "min": 2.0, "max": 40.0, "count": 50},
            ...
        }

    These are for synthetic data generation later:
        new_value = clamp(normal(mean, std), min, max)

    They are written to stats.json alongside the training CSV.
    They are NOT columns in the training CSV.
    """

    result = {}

    # outer loop
    # for the 21 columns it builds a list of values across every row

    for col in TRAINING_COLUMNS:

        values = []

        # inner loop
        # loops through all of the data rows
        # each data row, read the column value
        # skip NONE and MISSING

        for r in rows:

            raw = r.get(col)

            if raw is None: # catch error

                continue

            try:

                f = float(raw)

                if f != MISSING:

                    # append the data IF NOT EMPTY to the list as a float

                    values.append(f) 

            except (ValueError, TypeError): # catch error

                continue

        # if missing, score MISSING for everything

        if not values:

            result[col] = {"mean": MISSING, "std": MISSING, "min":  MISSING, "max": MISSING, "count": 0}

            continue

        # compute the statistics
        
        n = len(values) # holds the number of total data

        mean = sum(values) / n # mean
        std = math.sqrt(sum((v - mean) ** 2 for v in values) / n) # stanrdard deveiation

        # store the 5 statistics per column 
        # EXAMPLE OUTPUT
        # "num_threads": {"mean": 12.4, "std": 3.1, "min": 2.0, "max": 40.0, "count": 50}

        result[col] = {

            "mean": round(mean, 6),
            "std": round(std,  6),
            "min": min(values),
            "max": max(values),
            "count": n,
        }

    # return the result

    return result

# function that splits the filename into 2 parts, the name and the extension
# [0] causes the function to only capture the name
# it then adds _stats.json which will be the path of the computed stats
# its an important function because it always makes sure it is in the same path of the training csv

def _stats_path(training_csv_path):

    base = os.path.splitext(training_csv_path)[0]

    return base + "_stats.json"

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

# main function to bundle everything together

def build_training_csv(source_path, dest_path, compute = False):

    """
    Remap source_path (raw scan CSV) to 21-feature training CSV at dest_path.

    compute=True  -> also writes stats.json next to dest_path (NOT in CSV).
    Returns (row_count, message).
    """

    # handle error
    # if original csv from csv.logger is not there, stop

    if not os.path.isfile(source_path):

        return 0, f"Source file not found: {source_path}"

    transformed = []

    skipped = 0

    # open the csv file from csv.logger (scan.results)

    try:

        with open(source_path, "r", newline = "", encoding = "utf-8") as fh:

            # loop through each row
            # if there is data, transform is fired off
            # this remaps the data to 21 features, save the result into transformed list
            # if a row fails, skip

            # transform_row turns everything into int / float etc
            # 57 columns become 21

            for raw_row in csv.DictReader(fh):

                try:

                    transformed.append(transform_row(raw_row))

                except Exception:

                    skipped += 1

    except Exception as exc:

        return 0, f"Failed to read source CSV: {exc}"

    if not transformed:

        return 0, "Source CSV has no data rows."

    # write training CSV - raw features only, no stat columns

    try:

        # create output directory if needed, otherwise don't

        os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok = True)

        with open(dest_path, "w", newline = "", encoding = "utf-8") as fh: # open the file with write permissions

            # write all the transformed rows into trading_data.csv
            # the ignore means if a row as an extra key, it gets ignored

            # the writier auto uses the header (left) row as dictonary keys so each raw_row is already a dictonary

            writer = csv.DictWriter(fh, fieldnames = ALL_OUTPUT_COLUMNS, extrasaction = "ignore")

            writer.writeheader()

            writer.writerows(transformed) # uses the rows fron transformed to write the actual data

    except Exception as exc:

        return 0, f"Failed to write training CSV: {exc}"

    # write stats.json separately if compute is on

    stats_msg = ""

    if compute: # must be true (passed from gui)

        # calls transformed and compute stats together once all rows are done

        stats = compute_stats(transformed)

        sp = _stats_path(dest_path)

        # save the result as json next to the training csv path
        # catch any errors without crashing

        try:

            with open(sp, "w", encoding = "utf-8") as fh:

                json.dump(stats, fh, indent = 2)

            stats_msg = f"  |  stats -> {os.path.basename(sp)}"

        except Exception as exc:

            stats_msg = f"  |  stats write failed: {exc}"

    # returns row count and a human readable summary

    n = len(transformed)

    skip_note = f"  ({skipped} skipped)" if skipped else ""

    msg = (

        f"{n} rows  |  {len(TRAINING_COLUMNS)} features"
        f"{stats_msg}{skip_note}"
        f"  ->  {dest_path}"
    )

    return n, msg

# same applies as csv logger
# find script location, create output folder if it doesnt exist

def _get_output_dir() -> str:

    """Return (and create if needed) the output/ folder next to this script."""

    base = os.path.dirname(os.path.abspath(__file__))

    out = os.path.join(base, "output") # create filename

    os.makedirs(out, exist_ok = True) # check to see if it already exists, don't crash if it does

    # return path

    return out

# same applies as csv logger
# create filename

# named training_scan_data.csv (not just training_data.csv) to make it clearly
# distinct from the raw_scan_data.csv produced by csv_logger — these used to
# share too-similar default names which let the training builder overwrite
# the raw collection if the user did not explicitly change paths

def get_default_training_path():

    return os.path.join(_get_output_dir(), "training_scan_data.csv")