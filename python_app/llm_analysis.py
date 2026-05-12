"""
Layer 3 - LLM Contextual Analysis
==================================
Sends structured scan results to Claude for holistic threat assessment.

The key differentiator over rule-based and ML approaches: the LLM can
reason about COMBINATIONS of indicators that together describe a kill chain,
even when each individual indicator appears benign in isolation.

Example: NtQueueApcThread import alone is unremarkable (mswsock.dll uses it).
But combined with high-entropy private exec memory  +  RW->RX protection
change  +  a thread starting in that private region  +  an external handle
carrying PROCESS_VM_WRITE  =  complete shellcode injection kill chain.

Usage
-----
Requires the `anthropic` Python package and an ANTHROPIC_API_KEY environment
variable (or key passed via anthropic.Anthropic(api_key=...)).

    pip install anthropic
"""

# third and final detection layer
# rule engine -> IF mL -> llm analysis

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

from __future__ import annotations

import json

from dataclasses import dataclass, field
from typing import List, Optional

# try to import antropic
# if not installed, module still loads but llm button will not work
# the flag antrophic available gets checked before every call

try:

    import anthropic
    _ANTHROPIC_AVAILABLE = True

except ImportError:

    _ANTHROPIC_AVAILABLE = False

from PyQt5.QtCore import QThread, pyqtSignal

# import all dataclasses from proces_data
# the data objects are needed here beacuse scanbundle needs to know the required import types

# scan bundle is created later below
# this is because the llm analysis actaully views all of the data from the scan, making it a good place to declare scan bundle class

# to create the scan bundle class, it needs to know all of the types it will hold, so they are imported below
# python needs to know what process info, virtual alloc etc actually is

from process_data import (

    ProcessInfo,
    VirtualAllocRegion,
    ProtectChange,
    WriteEvent,
    NtSyscallInfo,
    ThreadInfo,
    RemoteThread,
    MappedModule,
    HandleEntry,
    ApiActivitySnapshot,
    PerfSnapshot,
    MemorySample,
)

# rule engine is imported lazily to avoid imports
# its imported so the llm can generate a summary of the rule engine
# if rule engine is missing or doesn't work, then llm continues but without the rule engine summary

try:

    from rule_engine import RuleResult, format_llm_prefix
    _RULE_ENGINE_AVAILABLE = True

except ImportError:
    _RULE_ENGINE_AVAILABLE = False

# ---------------------------------------------------------------------------
# ScanBundle - aggregates every collector output for one scan session
# ---------------------------------------------------------------------------

# the dataflow is simple
# llm analysis defines scan bundle -> gui imports scan bundle and creates it -> gui passes scan bundle to rule engine and csv logger -> they can read from it without importing

# simple dataclass that holds all of the scan data in 1 single container
# the objects created in process_data wrappers

@dataclass

class ScanBundle:

    """
    All outputs from a single process scan, ready for LLM analysis.

    Fields mirror the outputs of the Layer-1 collectors in process_data.py.
    Any field left as None / empty will simply be omitted from the LLM prompt,
    so partial bundles are fine.
    """

    # some fields are optional with none beacuse if the c++ collector is not compiled or if a result genuinely doesn't come from a process
    # process is required, because there always have to be a process otherwise the scan cannot happen

    proc: ProcessInfo
    allocs: List[VirtualAllocRegion] = field(default_factory = list)
    protect_changes: List[ProtectChange] = field(default_factory = list)
    write_events: List[WriteEvent] = field(default_factory = list)
    nt_info: Optional[NtSyscallInfo] = None
    threads: List[ThreadInfo] = field(default_factory = list)
    remote_threads: List[RemoteThread] = field(default_factory = list)
    mapped_modules: List[MappedModule] = field(default_factory = list)
    handles:List[HandleEntry] = field(default_factory = list)
    api_snapshot: Optional[ApiActivitySnapshot] = None
    perf: Optional[PerfSnapshot] = None
    memory_samples: List[MemorySample] = field(default_factory = list)

    # these get attached to the LLM analysis layer

    rule_result: Optional[object] = None # RuleResult from rule_engine
    if_result: Optional[dict] = None # IF prediction dict from gui

# ---------------------------------------------------------------------------
# Context builder - converts ScanBundle to a compact, LLM-readable dict
# ---------------------------------------------------------------------------

# these functions help to build the context to the llm
# llm cannot read numbers and understand them too well
# it has to be human readable format

# function to convert memory address to a readable hex string
# makes addresses readable in the json sent to the llm agent

def _addr(v: int) -> str:

    return f"0x{v:X}"

# function to convert entropy to readable label

def _entropy_label(e: float) -> str:

    if e < 0:    return "unread"
    if e < 3.5:  return "low"
    if e < 6.0:  return "medium"
    if e < 7.2:  return "high"

    return "very_high (packed/encrypted)"

# function to determine if a protect string has execute permissions

def _exec_protect(protect: str) -> bool:

    return any(x in protect for x in ("RX", "WX", "RWX", " X"))

# function to take entire scan bundle with all objects and convert to clean dict
# the dict then gets converted to json format
# this json is then sent to the llm

def build_context_dict(bundle: ScanBundle) -> dict:

    """
    Distil a ScanBundle into a compact structured dict for the LLM prompt.

    Design goals:
    - Include every indicator that meaningfully affects threat assessment.
    - Truncate long lists to preserve token budget; always keep the most
      suspicious entries.
    - Annotate entropy values with human labels so the LLM can reason
      about them without needing domain knowledge of entropy thresholds.
    """

    proc = bundle.proc

    # ------------------------------------------------------------------ #
    # 1.  Process basics
    # ------------------------------------------------------------------ #

    # create ctx dict and read directly from processinfo object

    ctx: dict = {

        "process": {
            "name": proc.name,
            "pid": proc.pid,
            "path": proc.path,
            "integrity": proc.integrity,
            "elevated": proc.elevated,
            "enabled_privileges": [
                p.name for p in proc.privileges if p.enabled
            ],

            "module_count": len(proc.modules),
            "region_count": len(proc.memory_regions),
        }
    }

    # ------------------------------------------------------------------ #
    # 2.  Modules - flag any without file backing
    # ------------------------------------------------------------------ #

    # same applies
    # filters down to files with no backing
    # stores up to 10 of them
    # uses the addr() to format the base address to hex

    non_backed = [m for m in proc.modules if not m.file_backed]

    ctx["modules"] = {

        "total": len(proc.modules),
        "non_file_backed_count": len(non_backed),
        "non_file_backed": [

            {"base": _addr(m.base), "path": m.path or "<none>"}
            for m in non_backed[:10]
        ],
    }

    # ------------------------------------------------------------------ #
    # 3.  Memory region summary - focus on private exec / high entropy
    # ------------------------------------------------------------------ #

    # same applies

    private_committed = [

        r for r in proc.memory_regions
        if r.type == "Private" and r.state == "Commit"
    ]

    exec_private = [r for r in private_committed if _exec_protect(r.protect)]

    mz_private = [r for r in exec_private if r.has_mz]

    # sorted entropy by descending
    # filters to high entropy only then sorts them from highest first
    # reverse going true means highest is already first
    # capped at 6 meaning the llm sees the highest ones

    high_ent = sorted(

        [r for r in exec_private if r.entropy >= 7.0], key = lambda r: r.entropy, reverse = True
    )

    ctx["memory_regions"] = {

        "exec_private_count": len(exec_private),
        "mz_header_in_private_count": len(mz_private),
        "high_entropy_exec_count": len(high_ent),

        "top_high_entropy_exec": [

            {
                "base":    _addr(r.base),
                "size_kb": r.size // 1024,
                "entropy": round(r.entropy, 3),
                "label":   _entropy_label(r.entropy),
                "protect": r.protect,
                "has_mz":  r.has_mz,
                "has_pe":  r.has_pe,
            }

            for r in high_ent[:6]
        ],
    }

    # ------------------------------------------------------------------ #
    # 4.  Virtual alloc regions - private committed, no file backing
    # ------------------------------------------------------------------ #

    # same applies

    exec_allocs = [a for a in bundle.allocs if _exec_protect(a.protect)]
    mz_allocs   = [a for a in bundle.allocs if a.has_mz or a.has_pe]

    # de-duplicate (an exec alloc can also have MZ)

    # the problem is a region can be executeable and have an mz header means getting sent to the llm twice
    # to fix this the dictonary is keyed by a.base the memory address
    # since the address is unqiue, if it appears twice it just overwrites itself with the same value
    # capped at 10

    interesting_allocs: dict[int, VirtualAllocRegion] = {}

    for a in exec_allocs + mz_allocs:
        interesting_allocs[a.base] = a

    ctx["virtual_allocs"] = {
        "total_private_committed": len(bundle.allocs),
        "exec_protect_count":  len(exec_allocs),
        "mz_or_pe_count": len(mz_allocs),
        "suspicious_entries": [
            {

                "base": _addr(a.base),
                "size_kb": a.size // 1024,
                "protect": a.protect,
                "entropy": round(a.entropy, 3) if a.entropy >= 0 else None,
                "entropy_label": _entropy_label(a.entropy),
                "has_mz": a.has_mz,
                "has_pe": a.has_pe,
            }

            for a in list(interesting_allocs.values())[:10]
        ],
    }

    # ------------------------------------------------------------------ #
    # 5.  Protection changes - RW->RX is the shellcode staging signature
    # ------------------------------------------------------------------ #

    # same applies

    gained_exec = [c for c in bundle.protect_changes if c.gained_exec]

    # excludes changed that already happend in gained_exec
    # keeps the list clean and results do not overlap

    lost_write  = [c for c in bundle.protect_changes if c.lost_write and not c.gained_exec]

    ctx["protect_changes"] = {

        "total": len(bundle.protect_changes),
        "gained_exec_count": len(gained_exec),
        "lost_write_count": len(lost_write),
        "gained_exec_details": [

            {
                "base":        _addr(c.base),
                "transition":  f"{c.protect_old} -> {c.protect_new}", # format to send like this : "RW -> RX"
            }

            for c in gained_exec[:10]
        ],
    }

    # ------------------------------------------------------------------ #
    # 6.  Write-detect events - changed private regions
    # ------------------------------------------------------------------ #

    # same applies

    ctx["write_events"] = {

        "changed_regions_count": len(bundle.write_events),
        "with_confirmed_writer_pid": len([e for e in bundle.write_events if e.writer_pids]),

        "events": [
            {
                "base": _addr(e.base),
                "protect": e.protect,
                "writer_pids": e.writer_pids,

                # hex samples stay at 32 beacuse they can be very long
                # but 32 is enough for the llm to understand

                "before_hex": e.sample_before[:32],
                "after_hex": e.sample_after[:32],
            }

            for e in bundle.write_events[:8]
        ],
    }

    # ------------------------------------------------------------------ #
    # 7.  NT syscall analysis - imports, stubs, ntdll hooks
    # ------------------------------------------------------------------ #

    # same applies

    if bundle.nt_info:

        ni = bundle.nt_info

        # seperate import lists
        # split into high value and everything else

        watched = [i for i in ni.direct_nt_imports if i.watched] # displays all
        all_imps = [i for i in ni.direct_nt_imports if not i.watched] # displays only 5
        hooks = [h for h in ni.hooked_functions if h.hooked]

        # this sections covers all nt checks in 1 dictonary
        # the llm gets all 3 of them so it can reason and link the dots together

        ctx["nt_syscall"] = {

            # WHO IS IMPORTING DANGEROUS CALLS

            "direct_nt_imports_total": len(ni.direct_nt_imports),

            "high_value_imports": [
                {"module": i.importing_module, "function": i.function} for i in watched
            ],

            "other_nt_imports_sample": [

                {"module": i.importing_module, "function": i.function} for i in all_imps[:5]
            ],

            # RAW SYSCALL OPCODES IN MEMORY

            "syscall_stubs_in_private_exec": len(ni.syscall_stubs),
            "stubs": [

                {
                    "address": _addr(s.address),
                    "opcode":  s.opcode,
                    "protect": s.protect,
                    "context_bytes": s.context,
                }

                for s in ni.syscall_stubs[:5]
            ],

            # NTDLL PATCHED EXPORT FUCNTIONS

            "ntdll_exports_checked":  len(ni.hooked_functions),
            "ntdll_hooks_found":      len(hooks),

            "hooks": [

                {"function": h.function, "hook_type": h.hook_type, "bytes": h.bytes}
                for h in hooks
            ],
        }

    # error handle
    # if empty let the llm know instead of crashing

    else:

        ctx["nt_syscall"] = {"note": "NT syscall data unavailable"}

    # ------------------------------------------------------------------ #
    # 8.  Thread start addresses
    # ------------------------------------------------------------------ #

    # same applies

    # this focues on private threads beacuse they are most suspicious

    priv_threads = [t for t in bundle.threads if t.in_private_exec]

    ctx["threads"] = {

        "total": len(bundle.threads),
        "starting_in_private_exec": len(priv_threads),

        "private_exec_threads": [

            {
                "tid": t.tid,
                "start_address": _addr(t.start_address) if t.start_address else "unknown", # if 0 or none, show unknown, more helpful for llm
                "module": t.start_module or "<private exec region>", # show private excuteable region because it shows llm the thread is running from memory with no file backing
            }

            for t in priv_threads[:6]
        ],
    }

    # ------------------------------------------------------------------ #
    # 9.  Remote / newly created threads
    # ------------------------------------------------------------------ #
    truly_remote = [t for t in bundle.remote_threads if t.remote]

    ctx["remote_threads"] = {
        "new_threads_observed":  len(bundle.remote_threads),
        "from_external_process": len(truly_remote),
        "details": [
            {
                "tid":              t.tid,
                "creator_pid":      t.creator_pid,
                "start_address":    _addr(t.start_address) if t.start_address else "unknown",
                "in_private_exec":  t.in_private_exec,
            }
            for t in truly_remote[:6]
        ],
    }

    # ------------------------------------------------------------------ #
    # 10.  Manually mapped / hidden modules
    # ------------------------------------------------------------------ #

    # same applies 

    ctx["mapped_modules"] = {

        "anomalous_image_regions": len(bundle.mapped_modules),

        "entries": [

            {
                "base": _addr(m.base),
                "size_kb": m.size // 1024,
                "path": m.device_path or "<no file backing>",
                "has_mz": m.has_mz,
                "missing_win32": m.not_in_win32_list,
                "missing_peb_ldr": m.not_in_ldr if m.ldr_available else "N/A",
                "no_file_backing": m.no_file_backing,
            }

            for m in bundle.mapped_modules[:10]

        ],
    }

    # ------------------------------------------------------------------ #
    # 11.  External handles - injection pre-requisite
    # ------------------------------------------------------------------ #

    # same applies

    dangerous = [

        h for h in bundle.handles
        if h.has_vm_write or h.has_create_thread or h.has_all_access
    ]

    ctx["handles"] = {

        "external_handles_total": len(bundle.handles),
        "dangerous_access_count": len(dangerous),
        "dangerous_handles": [

            {

                # the llm here gets boolean values
                # this is useful for the llm because it can put things together and reason

                # for example, vm_write = true and create_thread = true is required for process injection

                "owner_pid": h.owner_pid,
                "owner_name": h.owner_name or "<unknown>",
                "rights": h.access_decoded,
                "vm_write": h.has_vm_write,
                "vm_read": h.has_vm_read,
                "create_thread": h.has_create_thread,
                "suspend_resume": h.has_suspend,
                "all_access": h.has_all_access,
            }

            for h in dangerous[:10]

        ],
    }

    # ------------------------------------------------------------------ #
    # 12.  API activity snapshot (inferred from memory diffs)
    # ------------------------------------------------------------------ #

    # same applies

    if bundle.api_snapshot:

        s = bundle.api_snapshot

        ctx["api_activity"] = {

            "observation_window_ms": s.window_ms,

            # internal names like write process memory get remapped to the actual windows api calls
            # WriteProcessMemory
            # it makes it cleaner and easier to understand for the llm beacuse the windows API is well known

            "inferred_calls": {
                "VirtualAllocEx": s.counts.virtual_alloc,
                "VirtualProtect": s.counts.virtual_protect,
                "VirtualProtect_exec": s.counts.protect_exec,
                "WriteProcessMemory": s.counts.write_memory,
                "CreateRemoteThread": s.counts.create_thread,
            },

            "total_events": s.counts.total,
            "event_sequence": s.event_sequence,

            # prompt engineering built into the contezt
            # tells the llm what to look for
            # its useful because instead of hoping the llm can link the dots, the program embeds knowledge directly into it

            "note": (
                "event_sequence shows DISTINCT event types in first-seen order. "
                "alloc->write->protect_exec->create_thread is the classic injection chain."
            ),
        }

    else:

        ctx["api_activity"] = {"note": "API activity snapshot unavailable"}

    # ------------------------------------------------------------------ #
    # 13.  Performance metrics
    # ------------------------------------------------------------------ #

    # same applies

    # both of these conditions must be true

    if bundle.perf and bundle.perf.sample_ok:

        p = bundle.perf

        ctx["performance"] = {

            # all of the values are converted and rounded
            # smaller numbers is easier for the llm to understand rather than multi digit long numbers

            "cpu_percent": round(p.cpu_percent, 2),
            "working_set_mb": round(p.working_set_kb  / 1024, 1),
            "private_bytes_mb": round(p.private_bytes_kb / 1024, 1),
            "handle_count": p.handle_count,
            "thread_count": p.thread_count,
            "io_read_mb": round(p.io_read_bytes  / (1024*1024), 2),
            "io_write_mb": round(p.io_write_bytes / (1024*1024), 2),
        }

    else:

        ctx["performance"] = {"note": "Performance data unavailable"}

    # ------------------------------------------------------------------ #
    # 14.  Memory sample highlights - annotated interesting bytes
    # ------------------------------------------------------------------ #

    # same applies

    interesting: list = []

    # loop to convert hex to raw bytes

    for s in bundle.memory_samples:

        if not s.read_ok or not s.data_hex:

            continue

        raw = bytes.fromhex(s.data_hex)

        # this section builds human readable strings
        # each flag contains the name and what it does
        # super easy for the llm to understand

        flags: list[str] = []

        if len(raw) >= 2 and raw[0] == 0x4D and raw[1] == 0x5A:

            flags.append("MZ_HEADER - PE image embedded in process memory")

        if len(raw) >= 3 and raw[0] == 0x4C and raw[1] == 0x8B and raw[2] == 0xD1:

            flags.append("MOV_R10_RCX - x64 Nt* syscall stub preamble")

        if raw[0] == 0xB8:

            flags.append("MOV_EAX - possible syscall ID stub")

        if raw[0] in (0xE8, 0xE9):

            flags.append("CALL/JMP - possible shellcode trampoline")

        if raw[0] == 0x55 and len(raw) > 1 and raw[1] == 0x48:

            flags.append("PUSH_RBP - x64 function prologue")

        if raw[0] == 0x90:

            flags.append("NOP - possible NOP sled")

        # only fags that are suspicous make it to the llm
        # otherwise do not add

        if flags:

            interesting.append({
                "address": _addr(s.address),
                "trigger": s.trigger,
                "flags": flags,
                "first_32B": s.data_hex[:64], # sends the raw bytes to the llm for understadning
            })

    ctx["memory_sample_highlights"] = {
        "total_samples_captured": len(bundle.memory_samples),
        "interesting_count": len(interesting),
        "interesting": interesting[:8],
    }

    # end of fucntion
    # returns the whole dict
    # this is the json which gets sent to the llm

    return ctx

# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

# prompt which gets passed to the llm before the json
# these are the insturctions to tell calude how to behave as an analyst

# SUPER IMPORTANT
# the calibration - tells claude what looks suspiocus but is not actually. for example, google chrome browser processes flag up many rules in the hard coded section but this is known and its not risky
# this is useful because it can use reasoning to actually link the dots and understand whats going on instead of panicking

# also forces the response back format

SYSTEM_PROMPT = """\
You are an expert Windows malware analyst reviewing automated memory scan results
produced by a usermode process inspection tool (no kernel driver).
 
Your task: reason holistically about the combination of indicators present and
assess whether this process shows signs of compromise, process injection,
or other malicious activity.
 
Key domain knowledge to apply:
------------------------------
- FILELESS MALWARE PATTERN: Allocate private RW memory -> write shellcode/PE ->
  change protection to RX -> start thread from that region.  Each step alone
  can be benign; the sequence together is the kill chain.
 
- PROCESS INJECTION leaves artifacts:
  - High-entropy private exec regions (packed shellcode / reflective PE)
  - MZ/PE header in private memory (reflective DLL staging)
  - Threads starting in private exec regions (post-injection execution)
  - Remote threads from an unexpected creator PID
  - External handles with PROCESS_VM_WRITE + PROCESS_CREATE_THREAD
  - Hidden modules (not in Win32 list or PEB LDR)
 
- DIRECT SYSCALL EVASION (to bypass AV/EDR hooks):
  - SYSCALL opcodes in private exec memory (manual syscall stubs)
  - Direct Nt*/Zw* imports in non-system modules
  - ntdll export hooks (can be AV hooking OR malware self-patching)
 
- CALIBRATION - these are NORMAL in legitimate processes:
  - High-entropy regions in .NET, JVM, V8/Node.js (JIT compiled code)
  - Private exec memory in browser / scripting engine processes
  - Some direct NT imports in certain media / game engine DLLs
  - ntdll hooks by security products (CrowdStrike, SentinelOne etc.)
  - SeDebugPrivilege enabled in admin tools and debuggers
 
RESPONSE FORMAT (use exactly these section headers):
--------------------------------------------------
 
## SUSPICION SCORE
[0-10]
 
## KEY INDICATORS
- (bullet list, max 10, most significant first)
 
## ANALYSIS
(2-4 paragraphs.  Connect the dots.  Name the specific attack technique if
indicators are consistent with one.  Explain why combinations are more
meaningful than individual findings.  If clean, clearly explain why the
indicators are benign for this process type.)
 
## VERDICT
[Normal | Suspicious | Likely malicious | Highly malicious]
 
The VERDICT tier should align with the SUSPICION SCORE on the same scale
used by the rule engine and Isolation Forest layers, so all three layers
can be compared directly:
  0 - 2  -> Normal              (no concerning indicators)
  2 - 5  -> Suspicious          (some indicators, warrants attention)
  5 - 8  -> Likely malicious    (multiple indicators, probable threat)
  8 - 10 -> Highly malicious    (kill chain confirmed)
 
## RECOMMENDED ACTIONS
1. ...
2. ...
3. ...
"""

# this function assembels the user prompt that is sent to calude
# combines all detection layers into 1

def build_analysis_prompt(bundle: ScanBundle) -> str:

    # call the function above
    # create the dict
    # then dump into json

    ctx = build_context_dict(bundle)
    body = json.dumps(ctx, indent = 2)

    # --- Block 1: Rule engine pre-assessment ----------------------------
    # gives the LLM the weighted rule scoring BEFORE it sees raw data, anchoring its analysis to what the hardcoded engine already flagged
    
    rule_prefix = ""

    # if rule engine runs successfully, add the result into the prompt before the raw data

    if _RULE_ENGINE_AVAILABLE and bundle.rule_result is not None:

        try:

            rule_prefix = format_llm_prefix(bundle.rule_result) + "\n\n"

        except Exception:

            rule_prefix = ""

    # --- Block 2: Isolation Forest result --------------------------------
    # Gives the LLM the ML anomaly prediction and score so it can factor unsupervised structural isolation into its holistic assessment

    if_block = ""

    # convert the raw IF score into a human readable version
    # calude gets both the number and what it means

    if bundle.if_result is not None:

        r = bundle.if_result
        verdict = r.get("verdict",   "UNKNOWN")
        score = r.get("score",     0.0)
        pred_raw = r.get("pred_raw",  1)
        n_trees = r.get("n_trees",   "?")
        contam = r.get("contamination", "?")

        score_interp = (

            "well below decision boundary — strongly isolated from normal cluster"
            if score < -0.05 else
            "near decision boundary — marginal anomaly signal"
            if score < 0 else
            "above decision boundary — consistent with normal behaviour"
        )

        if_block = (

            "=== ISOLATION FOREST RESULT ===\n"
            f"Verdict      : {verdict}\n"
            f"Anomaly score: {score:.4f}  ({score_interp})\n"
            f"Raw prediction: {pred_raw}  (-1 = anomaly, 1 = normal)\n"
            f"Model config : {n_trees} trees, contamination={contam}\n"
            "\n"
            "Interpretation: The Isolation Forest was trained on ~6,000 synthetic "
            "behavioural samples from real process observations. It detects structural "
            "outliers — processes whose combination of features is statistically "
            "isolated from the learned normal distribution, regardless of whether "
            "individual features cross a hardcoded threshold.\n"
            "=== END ISOLATION FOREST RESULT ===\n\n"
        )

    # --- Block 3: Raw scan data (JSON) -----------------------------------

    # assemble final prompt together

    return (

        rule_prefix

        + if_block

        + f"Analyze the following memory scan results for process "
          f"'{bundle.proc.name}' (PID {bundle.proc.pid}):\n\n"
          f"```json\n{body}\n```\n\n"
          "Provide your malware analysis assessment."
    )

_TIER_ORDER = ["Normal", "Suspicious", "Likely malicious", "Highly malicious"] # severity ranks
 
 
# function which takes a number and turns it into a human readable severity case

def _tier_index(label):

    """Return the severity rank of a verdict label (0 = Normal, 3 = Highly)."""

    if label in _TIER_ORDER:

        return _TIER_ORDER.index(label)

    # anything unrecognised is treated as Normal to avoid spurious escalation

    return 0

# function which takes a suspicion score from the IF and rule engine
# and turns it into an overall suspicion score

# rule engine is the biggest factor, the IF is the booster
 
def _suspicion_score_from(rule_confidence, if_verdict):

    """
    Map (rule_confidence, IF verdict) to an integer 0-10 suspicion score
    that aligns with the same score bands the LLM uses:

        0-2  -> Normal
        2-5  -> Suspicious
        5-8  -> Likely malicious
        8-10 -> Highly malicious
 
    Rule confidence is the primary signal (already a 0-1 weighted score),
    multiplied by 10 to get a base.  The IF verdict adds a small bump
    when it escalates above the rule verdict.
    """

    base = int(round(rule_confidence * 10))

    # boost by IF severity so the score reflects both layers

    if_bump = _tier_index(if_verdict)   # 0..3

    return min(10, base + (if_bump // 2))   # max +1 from IF, capped at 10
 
# predefined outcomes for recommended actions label
# these actions are ficed and are choosen based on the final verdict
 
def _recommended_actions_for(tier_label):

    """Three concrete actions per verdict tier — deterministic, no LLM."""

    if tier_label == "Highly malicious":

        return [

            "Isolate the affected host from the network immediately to prevent "
            "lateral movement.",
            "Capture a full memory dump of the suspect process for offline "
            "forensic analysis before any cleanup.",
            "Escalate to incident response and preserve scan evidence (CSV / "
            "JSON exports) for chain-of-custody.",
        ]

    if tier_label == "Likely malicious":

        return [

            "Treat the host as suspect: restrict outbound network access and "
            "monitor for further indicators.",
            "Acquire a memory snapshot of the process and any child processes "
            "it has spawned during the observation window.",
            "Re-scan the process after 30 seconds to confirm the indicators "
            "persist rather than being a transient artefact.",
        ]

    if tier_label == "Suspicious":

        return [

            "Re-scan the process to confirm whether the indicators persist or "
            "were transient.",
            "Cross-check the process path and signature against known-good "
            "binaries on this host.",
            "Capture a JSON export of the current scan for later comparison "
            "if behaviour evolves.",
        ]

    return [

        "No immediate action required.",
        "Continue routine scanning of the process during the current "
        "monitoring window.",
        "Retain the scan output in the standard log if a baseline of normal "
        "behaviour is being collected.",
    ]
 
# function which puts everything together and builds the fallback report
 
def build_fallback_analysis(bundle): # takes full scan bundle

    """
    Build a complete five section analysis from the deterministic detector
    layers, formatted identically to the LLM's output so the GUI can render
    it without any special-case handling.
 
    Returns a multi-line string ready to be streamed to the console.
 
    Combination logic
    -----------------
    - rule verdict ∈ {Highly malicious, Likely malicious} → keep rule verdict
    - rule verdict == Normal AND IF verdict == Normal → Normal
    - rule and IF disagree → escalate to higher tier and say so
    """

    # --- pull what there is from the bundle -----

    rule = getattr(bundle, "rule_result", None)
    if_r = getattr(bundle, "if_result", None)
 
    # defaults so the fallback never crashes even if a layer didnt run

    # try / expect prevents crashes if data is missing

    if rule is not None:

        rule_verdict = getattr(rule, "label", "Normal")
        rule_confidence = getattr(rule, "confidence", 0.0)

        try:

            fired = [h for h in rule.hits if h.triggered]

        except Exception:

            fired = []
    else:

        rule_verdict = "Normal"
        rule_confidence = 0.0
        fired = []
 
    if if_r is not None:

        if_verdict = if_r.get("verdict", "Normal")
        if_score   = if_r.get("score", 0.0)

    else:

        if_verdict = "Normal"
        if_score = 0.0

    # --- resolve the combined verdict per spec into a number ------------------------------------------------------

    rule_idx = _tier_index(rule_verdict)
    if_idx = _tier_index(if_verdict)
    disagree = (rule_idx != if_idx)
 
    # spec rule 1: strong rule signal must never collapse to Normal
    # spec rule 2: both normal -> Normal
    # spec rule 3: disagreement -> take the higher tier

    final_idx = max(rule_idx, if_idx)
    final_verdict = _TIER_ORDER[final_idx]
 
    # --- suspicion score 0 to 10 ---

    score = _suspicion_score_from(rule_confidence, if_verdict)
 
    # --- KEY INDICATORS ---------------

    indicator_lines = []

    # order fired rules by weight desc so the strongest signals appear first

    fired_sorted = sorted(fired, key = lambda h: -getattr(h, "weight", 0))

    for hit in fired_sorted[:10]: # max 10

        rid = getattr(hit, "rule_id", "R??")
        name = getattr(hit, "name",    "rule")
        detail = getattr(hit, "detail",  "").replace("\n", " ").strip()

        if detail:

            indicator_lines.append(f"- {rid} {name}: {detail}")

            # - R03 Private executable memory: RWX MEM_PRIVATE region found for example

        else:

            indicator_lines.append(f"- {rid} {name}")

    # add the IF observation as its own indicator so it always shows up

    indicator_lines.append(

        f"- Isolation Forest: {if_verdict.lower()} "
        f"(anomaly score {if_score:+.4f})"
    )

    if not fired:
        indicator_lines.insert(
            0,
            "- No rule engine indicators triggered."
        )
 
    # --- ANALYSIS paragraph deterministic template -------------------

    strongest = fired_sorted[0] if fired_sorted else None

    strongest_line = (

        f"The strongest rule indicator is "
        f"{getattr(strongest, 'rule_id', '?')} "
        f"({getattr(strongest, 'name', '?')}), "
        f"contributing {getattr(strongest, 'weight', 0)} points to a total "
        f"rule confidence of {rule_confidence * 100:.1f}%."

        if strongest else

        "No rule engine indicators were triggered for this process."
    )

    if disagree:

        agreement_line = (

            f"The rule engine and Isolation Forest DISAGREE on this scan: "
            f"rule engine reports {rule_verdict.upper()} while the Isolation "
            f"Forest reports {if_verdict.upper()}.  The fallback has "
            f"escalated to the higher tier ({final_verdict}) so the stronger "
            f"signal is not lost; the LLM would normally reconcile this with "
            f"context, but is unavailable here."
        )

    else:

        agreement_line = (

            f"The rule engine and Isolation Forest agree on this scan: both "
            f"report {final_verdict.upper()}, increasing confidence in the "
            f"deterministic verdict."
        )
 
    analysis = (

        f"{strongest_line}  {agreement_line}  This output was generated by "
        f"the local fallback because the LLM reasoning layer could not be "
        f"reached; the verdict is therefore based only on the deterministic "
        f"rule engine and Isolation Forest layers, without the contextual "
        f"reconciliation the LLM normally provides."
    )
 
    # --- RECOMMENDED ACTIONS ---------------------------------------------

    actions = _recommended_actions_for(final_verdict)

    action_lines = "\n".join(f"{i + 1}. {a}" for i, a in enumerate(actions))
 
    # --- Assemble the five section output ---------------------------------

    # same headers the SYSTEM_PROMPT asks the LLM to use
    # this is exactly the same as the structure using the real API call when working

    out = (

        "[LOCAL FALLBACK — LLM API unreachable; verdict derived from rule "
        "engine and Isolation Forest only]\n\n"
        "## SUSPICION SCORE\n"
        f"{score}\n\n"
        "## KEY INDICATORS\n"
        + "\n".join(indicator_lines)
        + "\n\n"
        "## ANALYSIS\n"
        f"{analysis}\n\n"
        "## VERDICT\n"
        f"{final_verdict}\n\n"
        "## RECOMMENDED ACTIONS\n"
        f"{action_lines}\n"
    )

    return out

# RESULT:

#=== RULE ENGINE PRE-ASSESSMENT ===    ← rule engine verdict first

#=== END PRE-ASSESSMENT ===

#=== ISOLATION FOREST RESULT ===       ← ML verdict second

#=== END ISOLATION FOREST RESULT ===

#Analyze the following memory scan results for process 'notepad.exe':

#```json
#{...all 14 sections of scan data...}
#```

#Provide your malware analysis assessment.

# ---------------------------------------------------------------------------
# Background worker - streams the LLM response back to the GUI
# ---------------------------------------------------------------------------

# function to send scan bundle to claude in the background to avoid freezes
# starts a new thread instead of running the main one

# the gui calls this function with a new thread
# this thread runs the main function "run" instantly

class LLMAnalysisWorker(QThread):

    """
    Calls the Anthropic API in a background thread and streams the response.

    Signals
    -------
    chunk(str)   : a fragment of streamed text (append to console)
    done()       : streaming complete
    error(str)   : error message
    """

    # every few words claude sends, chunks stores this and sends it to the home console window for printing

    chunk = pyqtSignal(str) # each fragment of streamed text
    done = pyqtSignal() # when streaming complete
    error = pyqtSignal(str) # if anything goes wrong

    # configurable - override before calling start() if needed

    MODEL = "claude-opus-4-6"
    MAX_TOKENS = 2048

    # constructor
    # stores the bundle

    def __init__(self, bundle: ScanBundle, parent = None):

        super().__init__(parent)
        self.bundle = bundle

    # the method to run the llm analysis
    # first check if the library is installed

    def run(self) -> None:

        if not _ANTHROPIC_AVAILABLE:

            self._emit_fallback(

                reason = ("anthropic package not installed.  Run "
                          "`pip install anthropic` and set "
                          "ANTHROPIC_API_KEY to enable LLM analysis.")
            )
            return

        try:

            # reads the api client from windows environment variable control
            # then build the entire prompt from bundle running all the other functions

            client = anthropic.Anthropic() # reads ANTHROPIC_API_KEY from env
            prompt = build_analysis_prompt(self.bundle)

            # open streaming connection to the api
            # as text comes through, each fragment calls self.chunk.emit(text)
            # this is appended to the home console

            with client.messages.stream(

                model = self.MODEL,
                max_tokens = self.MAX_TOKENS,
                system = SYSTEM_PROMPT,
                messages = [{"role": "user", "content": prompt}],

            ) as stream:

                for text in stream.text_stream:
                    self.chunk.emit(text)
 
            self.done.emit()
 
        except Exception as exc:

            # any api error passes through here
            # emits the fallback method instead of an error

            self._emit_fallback(

                reason = f"{type(exc).__name__}: {exc}"
            )
 
    def _emit_fallback(self, reason):

        """
        Build the local fallback analysis from the rule and IF results
        attached to the bundle.
        """

        try:

            text = build_fallback_analysis(self.bundle)

            # prefix with the actual reason so the user can see WHY the fallback ran
            # for example, it will say when a key is invalid which is useful for debugging

            self.chunk.emit(f"[Reason for fallback: {reason}]\n\n")
            self.chunk.emit(text)
            self.done.emit()

        except Exception as exc:

            # if even the fallback fails, fall back to the original error path

            self.error.emit(

                f"Fallback builder failed: {type(exc).__name__}: {exc}\n"
                f"Original error: {reason}"
            )