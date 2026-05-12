"""
csv_logger.py
=============
Extracts a flat numerical feature vector from a ScanBundle and appends it
to a CSV file suitable for training an Isolation Forest (or any other
anomaly detection model that expects a fixed-width numerical matrix).

Design principles
-----------------
- Every feature is a plain number (int or float). No strings in the feature
  columns so the CSV can be fed directly to sklearn without encoding.
- Metadata columns (timestamp, name, pid, path) sit at the LEFT of the row
  and are clearly prefixed so they can be trivially dropped before training.
- Missing / unavailable data (e.g. perf snapshot not collected) fills with
  sentinel value -1 rather than NaN so the row is always complete.
- The file is created with a header on first write; subsequent writes just
  append rows. Thread-safe for the single-writer GUI use case (one scan
  at a time).

Feature groups
--------------
  meta_*          Non-numeric identifiers (drop before training)
  proc_*          Process-level attributes
  mod_*           Module list observations
  mem_*           Memory region statistics
  alloc_*         VirtualAlloc region observations
  prot_*          Protection change observations
  write_*         WriteProcessMemory detection
  nt_*            NT syscall / ntdll analysis
  thread_*        Thread start address audit
  rthread_*       Remote / newly created thread detection
  mmap_*          Manually mapped / hidden module detection
  handle_*        External handle audit
  api_*           API activity snapshot (inferred call counts)
  perf_*          Performance metrics
  sample_*        Memory sample highlights
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

import csv
import datetime
import os

from typing import List

# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------

# metadata columns (not features - drop before training)
# they indentify the scan but are not used in training

# _meta at the start is added to make it easy to filter out before training

META_COLUMNS = [

    "meta_timestamp", # ISO-8601 string
    "meta_process_name", # e.g. "notepad.exe"
    "meta_pid", # integer PID
    "meta_process_path", # full path string
]

# numeric feature columns (these are what the IF trains on)

# this brings the entire pipeline together from process_data
# each column is prefixed from process_data objects: proc_ comes from the processInfo object

# this list is created so later on the CSV writer appends these as headings
# it tells the writer what columns exist and in what order to draw the table

FEATURE_COLUMNS = [

    # -- Process basics --------------------------------------------------

    "proc_integrity", # 0=unknown 1=low 2=medium 3=high 4=system
    "proc_elevated", # 0 / 1
    "proc_enabled_privilege_count", # number of enabled token privileges
    "proc_module_count", # loaded modules
    "proc_region_count", # total memory regions

    # -- Module observations ---------------------------------------------

    "mod_non_file_backed_count", # modules with no file backing

    # -- Memory region statistics ----------------------------------------

    "mem_exec_private_count", # private committed regions with exec protect
    "mem_mz_in_private_count", # exec private regions containing MZ header
    "mem_high_entropy_exec_count", # exec private regions with entropy >= 7.0
    "mem_max_exec_entropy", # highest entropy across exec private regions
    "mem_avg_exec_entropy", # mean entropy across exec private regions

    # -- VirtualAlloc scan -----------------------------------------------

    "alloc_total_private_committed", # total private committed regions
    "alloc_exec_count", # private committed with exec protection
    "alloc_mz_or_pe_count", # private committed with MZ or PE header

    # -- Protection change detection -------------------------------------

    "prot_total_changes", # total protection changes in window
    "prot_gained_exec_count", # changes that gained execute permission
    "prot_lost_write_count", # changes that lost write (RW->RX pattern)

    # -- Write-detect ----------------------------------------------------

    "write_changed_region_count", # private regions whose content changed
    "write_confirmed_writer_count", # changed regions with identified writer PID

    # -- NT syscall analysis ---------------------------------------------

    "nt_direct_import_count", # direct Nt*/Zw* imports in non-system DLLs
    "nt_high_value_import_count", # subset: watched high-value functions
    "nt_syscall_stub_count", # SYSCALL/SYSENTER stubs in private exec mem
    "nt_hook_count", # ntdll exports with detected hooks

    # -- Thread audit ----------------------------------------------------

    "thread_total", # total threads in process
    "thread_in_private_exec", # threads starting in private exec region

    # -- Remote thread detection -----------------------------------------

    "rthread_new_count", # new threads observed in window
    "rthread_from_external", # new threads created by external process

    # -- Mapped / hidden module detection --------------------------------

    "mmap_anomalous_count", # image regions with at least one anomaly flag
    "mmap_no_file_backing", # subset: no file backing at all
    "mmap_not_in_win32", # subset: absent from EnumProcessModulesEx
    "mmap_not_in_ldr", # subset: absent from PEB LDR lists

    # -- Handle audit ----------------------------------------------------

    "handle_external_total", # total external handles to this process
    "handle_dangerous_count", # handles with VM_WRITE or CREATE_THREAD
    "handle_has_vm_write", # 1 if any external handle has VM_WRITE
    "handle_has_create_thread", # 1 if any external handle has CREATE_THREAD
    "handle_has_all_access", # 1 if any external handle has ALL_ACCESS

    # -- API activity snapshot -------------------------------------------

    "api_virtual_alloc_count", # inferred VirtualAllocEx calls
    "api_virtual_protect_count", # inferred VirtualProtect calls
    "api_protect_exec_count", # subset: VirtualProtect gaining exec
    "api_write_memory_count", # inferred WriteProcessMemory calls
    "api_create_thread_count", # inferred CreateRemoteThread calls
    "api_total_events", # total inferred API events

    # -- Performance metrics ---------------------------------------------

    "perf_cpu_percent", # CPU% over observation window
    "perf_working_set_mb", # physical RAM in MB
    "perf_private_bytes_mb", # private bytes in MB
    "perf_handle_count", # open handle count
    "perf_thread_count", # thread count from perf snapshot
    "perf_io_read_mb", # total bytes read (MB)
    "perf_io_write_mb", # total bytes written (MB)

    # -- Memory sample highlights ----------------------------------------

    "sample_total_captured", # total memory samples taken
    "sample_mz_header_count", # samples starting with MZ
    "sample_syscall_stub_count", # samples with MOV EAX / MOV R10,RCX pattern
    "sample_shellcode_hint_count", # samples with CALL/JMP or NOP sled
]

ALL_COLUMNS = META_COLUMNS + FEATURE_COLUMNS

# replacement for unavailable numeric data

MISSING = -1

# ---------------------------------------------------------------------------
# Integrity level encoder
# ---------------------------------------------------------------------------

# converter for integirty level that turns the outout into a number

_INTEGRITY_MAP = {

    "low": 1,
    "medium": 2,
    "high": 3,
    "system": 4,
}

# simple function which uses the integirty map to convert to a number
# a string integirty gets fed and outputs a number for return
# error handling is also there if S is unknown

def _encode_integrity(s: str) -> int:

    return _INTEGRITY_MAP.get((s or "").lower(), 0)

# ---------------------------------------------------------------------------
# Helper: exec-protect check (mirrors llm_analysis._exec_protect / rule_engine._is_exec_protect)
# ---------------------------------------------------------------------------

# function to check the protect string
# returns true if there is any executeable permission

# similar function is in rule_engine

def _is_exec(protect: str) -> bool:

    for x in ("RX", "WX", "RWX", " X"):

        if x in protect:

            return True

    return False

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

# reads from all the objects passed from the gui scan bundle
# converts each object into a numeric data form
# uses a flat dictonary to store the results

def extract_features(bundle) -> dict:

    """
    Convert a ScanBundle into a flat dict of {column_name: value}.

    Returns ALL_COLUMNS keys. Meta columns contain strings; feature columns
    contain ints or floats. Missing data is represented as MISSING (-1).

    Parameters
    ----------
    bundle : ScanBundle
        Populated after a completed scan (from gui._on_scan_done).

    Returns
    -------
    dict
        Flat row ready to be written by csv.DictWriter.
    """

    proc = bundle.proc
    
    # empty dict to store all of the feature columns

    row: dict = {}

    # -- Metadata --------------------------------------------------------

    # reads directly from the processInfo object
    # only strings in the row

    row["meta_timestamp"] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    row["meta_process_name"] = proc.name
    row["meta_pid"] = proc.pid
    row["meta_process_path"] = proc.path

    # -- Process basics --------------------------------------------------

    # the basic workflow here is the result of these is already decided by the collector, set from the process_data module
    # this is because it created object instances from the dataclass
    # these objects are passed through to here by scan bundle from the gui
    # the code below is simply accessing the objects and checking the boolean
    # if true append to a variable
    # this variable is then looped through by len and counted
    # the final count is then added to the dict

    row["proc_integrity"] = _encode_integrity(proc.integrity) # string to number
    row["proc_elevated"] = int(proc.elevated) # convert to boolean 0/1
    row["proc_enabled_privilege_count"] = sum(1 for p in proc.privileges if p.enabled) # count enabled privileges

    row["proc_module_count"] = len(proc.modules) # count module count
    row["proc_region_count"] = len(proc.memory_regions) # count region count

    # -- Module observations ---------------------------------------------

    row["mod_non_file_backed_count"] = sum(1 for m in proc.modules if not m.file_backed) # count non file backed modules

    # -- Memory region statistics ----------------------------------------

    private_committed = [

        r for r in proc.memory_regions

        if r.type == "Private" and r.state == "Commit" # count for regions that are private and commit, stores length as a number
    ]

    exec_private = [r for r in private_committed if _is_exec(r.protect)] # count for regions that are protected with execute permissions
    mz_in_private = [r for r in exec_private if r.has_mz] # count for regions that are protected with execute permissions AND have an MZ header
    high_ent_exec = [r for r in exec_private if r.entropy >= 7.0] # count for regions that are protected with execute permissions AND have entropy over 7

    entropies = [r.entropy for r in exec_private if r.entropy >= 0] # count for regions that are protected with execute permissions that have any entropy

    max_ent = round(max(entropies), 4) if entropies else MISSING # compute max entropy
    avg_ent = round(sum(entropies) / len(entropies), 4) if entropies else MISSING # compute average entropy

    # count the length of each result and store as a number

    row["mem_exec_private_count"] = len(exec_private)
    row["mem_mz_in_private_count"] = len(mz_in_private)
    row["mem_high_entropy_exec_count"] = len(high_ent_exec)
    row["mem_max_exec_entropy"] = max_ent
    row["mem_avg_exec_entropy"] = avg_ent

    # -- VirtualAlloc scan -----------------------------------------------

    exec_allocs = [a for a in bundle.allocs if _is_exec(a.protect)] # count for allocs with execute permissions 
    mz_allocs = [a for a in bundle.allocs if a.has_mz or a.has_pe] # count for allocs with MZ or PE headers

    # count the length of each result and store as a number

    row["alloc_total_private_committed"] = len(bundle.allocs) 
    row["alloc_exec_count"] = len(exec_allocs)
    row["alloc_mz_or_pe_count"] = len(mz_allocs)

    # -- Protection change detection -------------------------------------

    gained_exec = [c for c in bundle.protect_changes if c.gained_exec] # count if a process gained execute changes
    lost_write = [c for c in bundle.protect_changes if c.lost_write and not c.gained_exec] # count if a process lost write and didn't gain execute changes

    # count the length of each result and store as a number

    row["prot_total_changes"] = len(bundle.protect_changes)
    row["prot_gained_exec_count"] = len(gained_exec)
    row["prot_lost_write_count"] = len(lost_write)

    # -- Write-detect ----------------------------------------------------

    confirmed_writer = [e for e in bundle.write_events if e.writer_pids] # count for all processes that have writer permissions and a pid

    # count the length of each result and store as a number

    row["write_changed_region_count"]   = len(bundle.write_events)
    row["write_confirmed_writer_count"] = len(confirmed_writer)

    # -- NT syscall analysis ---------------------------------------------

    if bundle.nt_info:

        # same applies here
        # but store a -1 if data is missing
        # this -1 is later computed to 0 by the IF

        ni = bundle.nt_info
        high_val = [i for i in ni.direct_nt_imports if i.watched]
        hooks = [h for h in ni.hooked_functions if h.hooked]

        row["nt_direct_import_count"] = len(ni.direct_nt_imports)
        row["nt_high_value_import_count"] = len(high_val)
        row["nt_syscall_stub_count"] = len(ni.syscall_stubs)
        row["nt_hook_count"] = len(hooks)

    else:

        row["nt_direct_import_count"] = MISSING
        row["nt_high_value_import_count"] = MISSING
        row["nt_syscall_stub_count"] = MISSING
        row["nt_hook_count"] = MISSING

    # -- Thread audit ----------------------------------------------------

    priv_exec_threads = [t for t in bundle.threads if t.in_private_exec] # count for threads that are private executeables

    # count the length of each result and store as a number

    row["thread_total"] = len(bundle.threads)
    row["thread_in_private_exec"] = len(priv_exec_threads)

    # -- Remote thread detection -----------------------------------------

    truly_remote = [t for t in bundle.remote_threads if t.remote] # count for threads that are remote

    # count the length of each result and store as a number

    row["rthread_new_count"] = len(bundle.remote_threads)
    row["rthread_from_external"] = len(truly_remote)

    # -- Mapped / hidden module detection --------------------------------

    no_file = [m for m in bundle.mapped_modules if m.no_file_backing] # count for modules with no file backing
    not_win32 = [m for m in bundle.mapped_modules if m.not_in_win32_list] # count for modules that do NOT appear in win32 list
    not_ldr = [m for m in bundle.mapped_modules if m.not_in_ldr and m.ldr_available] # count for moudles that are not NOT in loader and it's still available

    # count the length of each result and store as a number

    row["mmap_anomalous_count"] = len(bundle.mapped_modules)
    row["mmap_no_file_backing"] = len(no_file)
    row["mmap_not_in_win32"] = len(not_win32)
    row["mmap_not_in_ldr"] = len(not_ldr)

    # -- Handle audit ----------------------------------------------------

    dangerous = [

        h for h in bundle.handles

        if h.has_vm_write or h.has_create_thread or h.has_all_access # if any are true, append
    ]

    # count the length of each result and store as a number

    row["handle_external_total"] = len(bundle.handles)
    row["handle_dangerous_count"] = len(dangerous)

    row["handle_has_vm_write"] = int(any(h.has_vm_write for h in bundle.handles))
    row["handle_has_create_thread"] = int(any(h.has_create_thread for h in bundle.handles))
    row["handle_has_all_access"] = int(any(h.has_all_access for h in bundle.handles))

    # -- API activity snapshot -------------------------------------------

    if bundle.api_snapshot:

        c = bundle.api_snapshot.counts

        #  simple counts for each api call

        # if any are empty, replace with missing (-1)

        row["api_virtual_alloc_count"] = c.virtual_alloc
        row["api_virtual_protect_count"] = c.virtual_protect
        row["api_protect_exec_count"] = c.protect_exec
        row["api_write_memory_count"] = c.write_memory
        row["api_create_thread_count"] = c.create_thread
        row["api_total_events"] = c.total

    else:

        for col in ("api_virtual_alloc_count", "api_virtual_protect_count",
                    "api_protect_exec_count", "api_write_memory_count",
                    "api_create_thread_count", "api_total_events"):

            row[col] = MISSING

    # -- Performance metrics ---------------------------------------------

    if bundle.perf and bundle.perf.sample_ok:

        p = bundle.perf

        # same applies

        row["perf_cpu_percent"] = round(p.cpu_percent, 3)
        row["perf_working_set_mb"] = round(p.working_set_kb / 1024, 2)
        row["perf_private_bytes_mb"] = round(p.private_bytes_kb / 1024, 2)
        row["perf_handle_count"] = p.handle_count
        row["perf_thread_count"] = p.thread_count
        row["perf_io_read_mb"] = round(p.io_read_bytes / (1024 * 1024), 4)
        row["perf_io_write_mb"] = round(p.io_write_bytes / (1024 * 1024), 4)

    else:

        for col in ("perf_cpu_percent", "perf_working_set_mb", "perf_private_bytes_mb",
                    "perf_handle_count", "perf_thread_count",
                    "perf_io_read_mb", "perf_io_write_mb"):

            row[col] = MISSING

    # -- Memory sample highlights ----------------------------------------

    # count variables set up

    mz_count = 0
    stub_count = 0
    shellcode_count = 0

    # loop through samples in the MemorySample object

    for s in bundle.memory_samples:

        # early exit

        if not s.read_ok or not s.data_hex:

            continue

        raw = bytes.fromhex(s.data_hex)

        # early exit if too short

        if len(raw) < 2:

            continue

        # count for MZ header by checking the bytes

        if raw[0] == 0x4D and raw[1] == 0x5A:

            mz_count += 1

        # count for syscall stub patterns: MOV R10,RCX (4C 8B D1) or MOV EAX (B8) 
        # if found, move counter up

        if (len(raw) >= 3 and raw[0] == 0x4C and raw[1] == 0x8B and raw[2] == 0xD1):

            stub_count += 1

        elif raw[0] == 0xB8:

            stub_count += 1

        # count for shellcode hints: CALL/JMP rel32 or NOP sled
        # if found, move counter up
        # looks for x64 / x86 calls

        if raw[0] in (0xE8, 0xE9, 0x90):

            shellcode_count += 1

    # count the length of each result and store as a number

    row["sample_total_captured"] = len(bundle.memory_samples)
    row["sample_mz_header_count"] = mz_count
    row["sample_syscall_stub_count"] = stub_count
    row["sample_shellcode_hint_count"] = shellcode_count

    return row

# ---------------------------------------------------------------------------
# CSV writer
# ---------------------------------------------------------------------------

# this call is made in the gui, so filepath comes from gui
# in the gui, the path comes from the output path from the settings panel csv path input
# path is not decided here, this function simply does the writing only

def append_to_csv(bundle, filepath: str) -> None:

    """
    Extract features from bundle and append one row to filepath.

    Creates the file with a header row if it does not yet exist.
    Appends silently if it does.

    Parameters
    ----------
    bundle   : ScanBundle
    filepath : str   Absolute or relative path to the target CSV file.

    Raises
    ------
    OSError  If the file cannot be opened or written.
    """

    # calls the function above with bundle which contains all of the objects
    # returns a dictonary with 61 columns with their values

    row = extract_features(bundle)

    # 2 checks
    # 1. check if the file already exists
    # 2. is the size of the file more than 0?

    # designed this way to prevent writing to a file without headers AND can write to a file that already contains data

    file_exists = os.path.isfile(filepath) and os.path.getsize(filepath) > 0

    # with the file open in append moode meaning it writes at the bottom, never overwrites data
    # filepath gets inserted by the caller

    with open(filepath, "a", newline = "", encoding = "utf-8") as fh:

        # writes to the file with all the columns, this includes the metadata and the actual data in the order
        # writes the dictonary as rows

        writer = csv.DictWriter(fh, fieldnames = ALL_COLUMNS)

        # if the file is new, write headings only at first call
        # then write the actual data rows

        if not file_exists:

            writer.writeheader()

        writer.writerow(row)

# simple function to create the output folder is needed

def _get_output_dir() -> str:

    """Return (and create if needed) the output/ folder next to this script."""

    # finds the directory of the current path the files lives in
    # uses __file__ which stores this location

    base = os.path.dirname(os.path.abspath(__file__))

    # the path is joined and an output folder is created in the path

    out = os.path.join(base, "output")

    os.makedirs(out, exist_ok = True) # check to see if it already exists, don't crash if it does

    return out

# retrieves the file path from the above function ^^
# then join with the file name of the output (raw_scan_data.csv)
# this returns the complete path of the file, returned to the gui

# gui uses this in multiple places but for example it places it at the output path in the settings pages

# named raw_scan_data.csv (not just scan_data.csv) to make it clearly distinct
# from the training_scan_data.csv produced by data_prep — these used to share
# the same default name which caused the training builder to overwrite the
# raw collection if the user did not explicitly change paths

def get_default_csv_path() -> str:

    """Return the default raw scan data CSV path inside the output/ folder."""

    return os.path.join(_get_output_dir(), "raw_scan_data.csv")

# ---------------------------------------------------------------------------
# JSON writer
# ---------------------------------------------------------------------------
# saves the entire raw scan bundle as a JSON file, one file per scan
# uses build_context_dict from llm_analysis which already produces the
# structured dict that gets sent to the LLM, so the JSON file contains
# exactly the same view of the scan that the LLM sees

# unlike the CSV which appends rows to a single file, JSON uses one file
# per scan because each scan is a structured object not a flat row
# the filename includes the process name, pid and timestamp so files
# from multiple scans never overwrite each other

def append_to_json(bundle, dirpath: str) -> str:

    """
    Save bundle's scan data as a JSON file inside dirpath.

    Each scan produces one file named  <process>_<pid>_<timestamp>.json
    so multiple scans never overwrite each other.

    Parameters
    ----------
    bundle  : ScanBundle
    dirpath : str   Absolute or relative directory to write the JSON into.
                    Created automatically if it does not exist.

    Returns
    -------
    str  The full path of the JSON file that was written.

    Raises
    ------
    OSError  If the directory cannot be created or the file cannot be written.
    """

    import json as _json

    # import here to avoid a circular import (llm_analysis imports from process_data)
    # circular imports happen when 2 files try to import each other at startup
    # by importing inside the function, this only runs when the function is called

    from llm_analysis import build_context_dict

    # build the same structured dict that gets sent to the LLM
    # this gives a clean human readable view of the scan, with addresses
    # formatted as hex strings, entropy labelled, suspicious entries grouped etc

    ctx = build_context_dict(bundle)

    # create the directory if it does not exist already
    # exist_ok = True means do not crash if the folder is already there

    os.makedirs(dirpath, exist_ok = True)

    # build the filename from process name + pid + timestamp
    # uses dashes between the time parts because windows file names cannot contain colons

    proc = bundle.proc

    # sanitise the process name for use in a filename
    # replace any character that is not alphanumeric, dash, dot or underscore
    # this stops process names with weird characters from breaking the filename

    safe_name = "".join(

        c if (c.isalnum() or c in ("-", "_", ".")) else "_"

        for c in proc.name
    )

    # timestamp format: 2026-04-26T15-30-45
    # dashes used in the time so it works on every operating system

    timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")

    filename = f"{safe_name}_{proc.pid}_{timestamp}.json"
    filepath = os.path.join(dirpath, filename)

    # write the dict as pretty printed JSON with 2 space indentation
    # this makes the file easy to read manually and easy to diff

    with open(filepath, "w", encoding = "utf-8") as fh:

        _json.dump(ctx, fh, indent = 2)

    # return the full path so the caller can show it in the status label

    return filepath

# default JSON output directory
# all scans share the same folder, the per-scan filename keeps them separate

def get_default_json_path() -> str:

    """Return the default JSON output directory inside the output/ folder."""

    return os.path.join(_get_output_dir(), "json_scans")