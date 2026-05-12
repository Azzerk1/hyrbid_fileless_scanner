"""
rule_engine.py
==============
Hardcoded weighted behavioural rule engine for the memory scanner.

Each rule inspects one specific indicator from the ScanBundle and returns
a binary triggered / clean result.  The results are combined into a
weighted confidence score and a 4-tier verdict label.

Architecture
------------
Rules  →  quick detection + explainable score
ML     →  anomaly confirmation (Isolation Forest)
LLM    →  holistic reasoning + narrative explanation

Scoring
-------
confidence = triggered_weight_sum / max_weight_sum

0.0 – 0.20  →  Normal
0.20 – 0.50 →  Suspicious
0.50 – 0.80 →  Likely malicious
0.80 – 1.00 →  Highly malicious
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

# annotations: simple labels, they just explain what type a variable should be, what a function should return etc
# easier readability

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# address of KUSER_SHARED_DATA — kernel-written page that is in every process
# this is always detected by cross process write and API snapshot even though it is 100% normal within a process
# it is excluded from the rules that would mark it as malicious

KUSER_SHARED_DATA = 0x7FFE0000

# helper function: returns true if execute is found

# private function
# collected by convertProtect / allocProtectStr from the collector

# created as a helper fucntion to avoid writing many if statements 

def _is_exec_protect(protect: str) -> bool:

    p = protect.upper() # works with both upper / lower case

    return ("RX" in p or "WX" in p or "RWX" in p or " X" in p or p in ("X", "RX", "RWX", "RWC"))

# Known-benign (module, function) pairs for watched NT imports.
# These always appear in normal Windows processes and do not indicate attack.

# tuple containg module and function for watched NT imports
# this shows a legit use of dangerous NT calls

# this is needed because some of these calls do appear in normal applications like Windows DLL files
# but they would otherwise be flagged for dangerous behaviour
# both fields in the tuple have to match exactly to be considered safe

KNOWN_BENIGN_NT_IMPORTS: set[tuple[str, str]] = {

    ("sechost.dll",  "NtQueueApcThread"), # async I/O in service host
    ("mswsock.dll",  "NtQueueApcThread"), # Winsock async I/O
    ("apphelp.dll",  "NtProtectVirtualMemory"), # compatibility shim layer
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

# simple dataclass storing the 1 result

@dataclass
class RuleHit:
    rule_id: str
    name: str
    description: str
    weight: int
    triggered: bool
    detail: str = "" # extra context shown in display and LLM prompt


# dataclass with calculated properties
# properties are used here for connivence, a function can be accessed like a field

# this is used over a traditional dataclass because of the calculations it peforms
# it can work stuff out and store the result and create an object
# where as traditional dataclasses simply store the raw result and require a parser

@dataclass

class RuleResult:

    process_name: str = ""
    pid: int = 0
    hits: List[RuleHit] = field(default_factory = list)

    # sum of triggered rules weights

    @property

    def score(self) -> int:
        return sum(h.weight for h in self.hits if h.triggered)

    # sum of all score weights

    @property

    def max_score(self) -> int:
        return sum(h.weight for h in self.hits)

    # score / max score = 0.0 to 1.0

    @property

    def confidence(self) -> float:
        return self.score / self.max_score if self.max_score > 0 else 0.0

    # normal / suspicious / likely malicious / highly malicious

    @property

    def label(self) -> str:

        c = self.confidence
        if c < 0.20: return "Normal"
        if c < 0.50: return "Suspicious"
        if c < 0.80: return "Likely malicious"

        return "Highly malicious"

    # green / yellow / orange / red for the gui

    @property

    def label_colour(self) -> str:

        """Qt-compatible colour string for the verdict label."""

        c = self.confidence

        if c < 0.20: return "#00e5a0" # green
        if c < 0.50: return "#ffd43b" # yellow
        if c < 0.80: return "#ffa94d" # orange

        return "#ff6b6b" # red

    # filtered list of only triggered hits

    @property

    def triggered_rules(self) -> List[RuleHit]:
        return [h for h in self.hits if h.triggered]

    # filtered list of only clean hits

    @property

    def clean_rules(self) -> List[RuleHit]:
        return [h for h in self.hits if not h.triggered]

# ---------------------------------------------------------------------------
# Helper – safe attribute / key access for both dataclass objects and dicts
# ---------------------------------------------------------------------------

# function to read from a dataclass or dic without crashing

# when checking for rules hits in the engine, the program accesses either a dic or dataclass
# and for this to happen, it would need to check which one it is first
# thats why this function is created, to replace this process and simplify the code

# the *key allows to check multiple objects in a single call

# if at any point the object is empty, return default, this avoids crashes
# and they can be empty quite often if the can doesn't find anything

def _get(obj, *keys, default=None):

    """Traverse a chain of attribute or dict keys safely."""

    for key in keys:

        if obj is None:

            return default

        if isinstance(obj, dict):

            obj = obj.get(key, default)

        else:

            obj = getattr(obj, key, default)

    return obj

# takes api snapshot object and a key like write_memory and returns count for that event type
# uses the _get function from above ^^ incase the data is not an objet and a dic instead

# accesses the count from the collector which was already produced

def _api_count(api_snapshot, key: str) -> int:

    if api_snapshot is None:

        return 0

    counts = _get(api_snapshot, "counts")

    if counts is None:

        return 0

    if isinstance(counts, dict):

        return counts.get(key, 0)

    return getattr(counts, key, 0)

# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

# 1. legit code lives in memory that is backed by file. 
# private memory regions with no file backing is a strong sign of fileless malware

def _r01(bundle) -> RuleHit:

    """R01 — Executable private memory regions present."""

    # get list from allocs or use empty is nothing returned

    allocs = bundle.allocs or []

    # creates a loop that loops through each alloc and checks if it has executeable permissions
    # uses _get to read the protect field
    # creates a new list with the results

    exec_allocs = [a for a in allocs if _is_exec_protect(_get(a, "protect") or "")]

    # if ANY are found, triggered is fired

    triggered = len(exec_allocs) > 0

    # builds a human readable string

    detail = (f"{len(exec_allocs)} region(s): "
              + ", ".join(hex(_get(a, "base", default=0)) for a in exec_allocs[:3])
              if triggered else "")

    # returns rulehit object with weight of 3

    return RuleHit(

        "R01",
        "Executable private memory",
        "Private committed memory with execute protection (RX/RWX). "
        "Injected shellcode or reflective PE loaders always produce this.",
        weight = 3, triggered = triggered, detail = detail,
    )


# 2. checks for executeable files hiding in private memory
# looks for MZ / PE headers

def _r02(bundle) -> RuleHit:

    """R02 — MZ or PE header found in private (non-file-backed) memory."""

    # same applies

    allocs = bundle.allocs or []

    # reads the alloc list and loops through
    # put the result in list IF it contains an MZ / PE header

    mz = [a for a in allocs if _get(a, "has_mz") or _get(a, "has_pe")]
    triggered = len(mz) > 0

    detail = (f"{len(mz)} region(s) with MZ/PE header at "
              + ", ".join(hex(_get(a, "base", default=0)) for a in mz[:3])
              if triggered else "")

    # returns rulehit object with weight of 3

    return RuleHit(

        "R02",
        "MZ/PE header in private memory",
        "A portable executable image was found in private memory with no "
        "file backing — consistent with reflective DLL injection or manual PE mapping.",
        weight = 3, triggered = triggered, detail = detail,
    )

# 3. meassure for randomness in private memory
# high randomess suggests encrpytion or compresion is used
# normal programs often have low entropy scores while encrypted payloads have higher scores
# often they provide entropy aove 6.5

def _r03(bundle) -> RuleHit:

    """R03 — High entropy private region (>6.5 bits) — possible packed/encrypted code."""

    allocs = bundle.allocs or []

    # same applies but looks for entropy
    # entropy must be read okay and higher than 6.5 to be high risk

    high = [a for a in allocs
            if (_get(a, "entropy", default=-1) or -1) > 6.5
            and _get(a, "entropy_read", default=False)]

    triggered = len(high) > 0

    # finds the region with the highest entropy if the region is not empty

    if high:

        best = max(high, key = lambda a: _get(a, "entropy", default=0))

    else:

        best = None

    detail = (f"max entropy {_get(best, 'entropy', default=0):.3f} "
              f"at {hex(_get(best, 'base', default=0))}"
              if triggered else "")

    # returns rulehit object with weight of 1

    return RuleHit(

        "R03",
        "High-entropy private region",
        "A private committed region has Shannon entropy > 6.5, "
        "suggesting packed, compressed, or encrypted payload data.",
        weight = 1, triggered = triggered, detail = detail,
    )

# 4. detects a process writing into antoher process memory
# strong indicator of process injection

# it finds the actual memory content changes between 2 snapshots

def _r04(bundle) -> RuleHit:

    """R04 — Genuine cross-process memory write (excl. KUSER_SHARED_DATA)."""

    writes = bundle.write_events or []

    # retreives all the writes that are NOT the kuser_shared_data
    # the constant at the top of the page

    real = [w for w in writes if (_get(w, "base", default=0) or 0) != KUSER_SHARED_DATA]

    triggered = len(real) > 0

    detail = (f"{len(real)} write(s) to: "
              + ", ".join(hex(_get(w, "base", default=0)) for w in real[:3])
              if triggered else "")

    # returns rulehit object with weight of 2

    return RuleHit(

        "R04",
        "Cross-process memory write",
        "External memory content changes detected in regions other than the "
        "kernel-shared KUSER_SHARED_DATA page — a prerequisite for process injection.",
        weight = 2, triggered = triggered, detail = detail,
    )

# 5. instead of looking at write acitvity using system calls, it looks at api activtiy snapshot
# it catches write acitvity during the observed window

# 5 and 4 rules are 2 diffetent ways of detecting the same type of attack on memory

def _r05(bundle) -> RuleHit:

    """R05 — WriteProcessMemory activity above baseline in API snapshot."""

    # baseline is 4 = each sub sample interval catches KUSER_SHARED_DATA changing
    # genuine write activity pushes the count above that floor

    wm = _api_count(bundle.api_snapshot, "write_memory")

    # the c++ scanner takes 5 sub samples during the observation window
    # each sample always detects the constant changing = allowing a max change of 4
    # this means anything above 4 is external writes

    triggered = wm > 4

    detail = f"write_memory count: {wm}  (baseline ≤ 4)" if triggered else f"count: {wm}"

    # returns rulehit object with weight of 2

    return RuleHit(

        "R05",
        "WriteProcessMemory activity (above baseline)",
        "The API activity snapshot observed more memory write events than the "
        "expected baseline of 4 KUSER_SHARED_DATA updates, indicating active "
        "external writes to this process.",
        weight = 2, triggered = triggered, detail = detail,
    )

# 6. the final step of most injection attacks is: another process forcing a new thread to run inside the target
# this is what this rule detects

def _r06(bundle) -> RuleHit:

    """R06 — Remote thread creation detected."""

    # remote looks at actual thread objects difference detected by snapshot difference

    remote = [t for t in (bundle.remote_threads or []) if _get(t, "remote")]

    # ct looks at CreateRemoteThread count from the API activtiy snapshot

    ct = _api_count(bundle.api_snapshot, "create_thread")

    triggered = len(remote) > 0 or ct > 0

    parts = []

    # only 1 needs to be true for the rile to be triggered

    if remote:

        parts.append(f"{len(remote)} remote thread(s) from PID(s): " + ", ".join(str(_get(t, "creator_pid", default="?")) for t in remote[:3]))

    if ct > 0:

        parts.append(f"API snapshot: {ct} CreateRemoteThread event(s)")

    detail = "  |  ".join(parts) if parts else ""

    # returns rulehit object with weight of 3

    return RuleHit(

        "R06",
        "Remote thread creation",
        "A new thread was injected into this process from an external PID, "
        "or CreateRemoteThread activity was observed. This is the final step "
        "of most process injection techniques.",
        weight = 3, triggered = triggered, detail = detail,
    )

# 7. detects non system modules importing NT calls
# legit applications do not do this normally suggesting suspicious behaviour

def _r07(bundle) -> RuleHit:

    """R07 — Suspicious watched NT import (excl. known-benign module/function pairs)."""

    ni = bundle.nt_info

    # if empty, instanlty quit with false result

    if not ni:

        return RuleHit("R07", "Suspicious watched NT import",
                       "Watched NT import from unexpected non-system module.",
                       weight = 2, triggered = False, detail = "nt_info unavailable")
    imports = _get(ni, "direct_nt_imports") or []

    # 2 conditons to meet
    # the NT call must be watched
    # and function pair must not be in the whitelist at the top of the module

    suspicious = [

        i for i in imports

        if _get(i, "watched")

        and (_get(i, "importing_module", default="").lower(),
             _get(i, "function",         default=""))
           not in KNOWN_BENIGN_NT_IMPORTS
    ]

    triggered = len(suspicious) > 0

    # prints back to the home console which module is importing which dangerous function
    # for example : evil.dll → NtCreateThreadEx, evil.dll → NtWriteVirtualMemory

    detail = (", ".join(
                f"{_get(i, 'importing_module', default='?')} → {_get(i, 'function', default='?')}"
                for i in suspicious[:4])
              if triggered else "")

    # returns rulehit object with weight of 2

    return RuleHit(

        "R07",
        "Suspicious watched NT import",
        "A non-system module directly imports a high-risk NT syscall "
        "(NtCreateThreadEx, NtQueueApcThread, NtWriteVirtualMemory, "
        "or NtProtectVirtualMemory) that is not explained by known-benign DLLs.",
        weight = 2, triggered = triggered, detail = detail,
    )

# 8. detects threads that started in priv executeable memory
# this shows code running without a file backing it on the disk
# = strong sign of fileless malware

def _r08(bundle) -> RuleHit:

    """R08 — Thread starting from private executable memory."""

    # filter for threads that confirm a start was in private executeable memory

    priv = [t for t in (bundle.threads or []) if _get(t, "in_private_exec")]

    triggered = len(priv) > 0

    detail = (f"{len(priv)} thread(s) — TIDs: "
              + ", ".join(str(_get(t, "tid", default="?")) for t in priv[:4])
              if triggered else "")

    # returns rulehit object with weight of 2

    # weight 2 but actually it becomes 5
    # this is because a thread running in private executeable memory requires private memory to start with
    # this is defined by rule 1
    
    # this rule can be thought of confirmation for rule 1 and together they are very suspicous producing a weight of 5

    return RuleHit(

        "R08",
        "Thread starting in private exec memory",
        "One or more thread start addresses fall inside a private, non-image "
        "executable region — the execution stage of shellcode or reflective PE injection.",
        weight = 2, triggered = triggered, detail = detail,
    )

# 9. checks for modified bytes at the start of a nt function
# this suggests inlike hooks are active on ntdll exports
# this can cause the tunnel to be skipped allowing malicious calls to be executed

# rule number 9 and 10 needed early exit calls with false if empty because they need nt_info specifically
# nt_info is a single object and not a list, therefore it cannot loop through nothing

def _r09(bundle) -> RuleHit:

    """R09 — ntdll export hook detected."""

    ni = bundle.nt_info

    # same applies

    if not ni:
        return RuleHit("R09", "ntdll export hook",
                       "Inline hook on ntdll Nt* export stubs.",
                       weight=2, triggered=False, detail="nt_info unavailable")

    # filters down to fucntions which have been modified

    hooks = [h for h in (_get(ni, "hooked_functions") or []) if _get(h, "hooked")]

    triggered = len(hooks) > 0

    # shows which fucntion was hooked and what type of hook
    # for example: NtCreateThreadEx (JMP rel32), NtWriteVirtualMemory (JMP [rip+off])

    detail = (", ".join(
                f"{_get(h, 'function', default='?')} ({_get(h, 'hook_type', default='?')})"
                for h in hooks[:4])
              if triggered else "")

    # returns rulehit object with weight of 2

    return RuleHit(

        "R09",
        "ntdll export hook",
        "An Nt* syscall export in ntdll.dll has been patched inline. "
        "Can indicate a security product's hook OR malware self-patching to "
        "intercept or bypass syscall monitoring.",
        weight = 2, triggered = triggered, detail = detail,
    )

# 10. detects raw syscall oppcodes found in private executeble memory
# these insutrctions only ever exist in ntdll.dll and finding them is priv executeable memory is used to bypass security

# this is high weight because it is very suspicous in a normal process
# only known exception is google chrome chrmoium process which is documented online

def _r10(bundle) -> RuleHit:

    """R10 — SYSCALL/SYSENTER stubs in private executable memory."""

    # if ni exists, use it otherwise use an empty list

    ni = bundle.nt_info

    stubs = (_get(ni, "syscall_stubs") or []) if ni else []

    triggered = len(stubs) > 0

    # shows the address of the first stub 
    # [0] is used beacuse it is guranteed that there is at least 1 item in the list

    detail = (f"{len(stubs)} stub(s) — first at "
              + hex(_get(stubs[0], "address", default=0))
              if triggered else "")

    # returns rulehit object with weight of 3

    return RuleHit(

        "R10",
        "Syscall stubs in private exec memory",
        "Raw SYSCALL / SYSENTER opcodes found in private (non-image) executable "
        "memory. Used for direct-syscall EDR evasion or as part of a manually "
        "assembled shellcode stub. Legitimate in Chrome's sandbox layer.",
        weight = 3, triggered = triggered, detail = detail,
    )

# 11. detects modules that are hidden from the file system
# missing in win32 list, PEB, loader etc
# this is commonly found in DLL reflection attacks because it is a file that loaded directly into memory without being addressed by the windows loader

def _r11(bundle) -> RuleHit:

    """R11 — Truly hidden module (no file backing at all)."""

    # if no file backing is true, add to the list

    hidden = [m for m in (bundle.mapped_modules or []) if _get(m, "no_file_backing")]

    triggered = len(hidden) > 0

    # same applies

    detail = (f"{len(hidden)} module(s) at: "
              + ", ".join(hex(_get(m, "base", default=0)) for m in hidden[:3])
              if triggered else "")

    # returns rulehit object with weight of 2

    return RuleHit(

        "R11",
        "Truly hidden module (no file backing)",
        "An executable image region was found with no associated file path — "
        "not in the Win32 module list, not in the PEB LDR, and no mapped file. "
        "This is the fingerprint of reflective injection or manual PE mapping.",
        weight = 2, triggered = triggered, detail = detail,
    )

# 12. detects external processes having handles to another process with dangerous permissions
# this is part of the injection attack because before any process can do anything, they need to open a handle with sufficient permissions

def _r12(bundle) -> RuleHit:

    """R12 — External handle with dangerous access rights."""

    dangerous = [

        # filter uses 3 conditons
        # any of these is sufficent to peform injection attacks

        h for h in (bundle.handles or [])
        if (_get(h, "has_vm_write") or _get(h, "has_create_thread")
            or _get(h, "has_all_access"))]

    triggered = len(dangerous) > 0

    # shows which process has what handle with what permissions
    # for example : PID 1234 (suspicious.exe) [VM_WRITE|CREATE_THREAD]

    detail = (", ".join(
                f"PID {_get(h, 'owner_pid', default='?')} "
                f"({_get(h, 'owner_name', default='?')}) "
                f"[{_get(h, 'access_decoded', default='?')}]"
                for h in dangerous[:3])
              if triggered else "")

    # returns rulehit object with weight of 2
    # its suspicous but not enough alone, must align with other rules as legit programs can have open handles, like debuggers

    return RuleHit(

        "R12",
        "External handle with dangerous access",
        "An external process holds an open handle to this process with "
        "PROCESS_VM_WRITE, PROCESS_CREATE_THREAD, or PROCESS_ALL_ACCESS — "
        "the minimum rights required for injection.",
        weight = 2, triggered = triggered, detail = detail,
    )

# 13. detects memory regions that changed from writeable to executeable permissons during the observation window
# this is a form of fileless malware that can execute shellcode attacks

# for example, allocating read write memory, caught by rule 4, and filping permissions to execute, caught by this rule 13

def _r13(bundle) -> RuleHit:

    """R13 — Protection change gaining execute rights (RW → RX staging)."""

    # added to the list if the protect changes to executeable

    gained = [c for c in (bundle.protect_changes or []) if _get(c, "gained_exec")]

    triggered = len(gained) > 0

    # shows what permission changed from what and to 
    # produces: RW→RX @ 0x1a2b, RW→RX @ 0x3c4d for example

    detail = (f"{len(gained)} change(s): "
              + ", ".join(
                  f"{_get(c, 'protect_old', default='?')}→{_get(c, 'protect_new', default='?')} "
                  f"@ {hex(_get(c, 'base', default=0))}"
                  for c in gained[:3])
              if triggered else "")

    # returns rulehit object with weight of 3
    # strong indication of fileless malware as payloads usually do this
    # legit programs very rarley switch permissions at run time

    return RuleHit(

        "R13",
        "Protection change gaining exec (RW→RX)",
        "A region's protection changed to include execute permission during the "
        "observation window — the classic write-then-execute shellcode staging "
        "pattern used in fileless malware.",
        weight = 3, triggered = triggered, detail = detail,
    )

# 14. this rule is a combination rule
# other rules checked for a single fact, this rule checks for a pattern of multiple rules

# it runs simplfied versions of rules 1, 4 and 5
# they are simplfied checks 

# this is done so a combination of these rules is scored higher as its far more dangerous, thats why 2 more points are assigned if the combo is true

def _r14(bundle) -> RuleHit:

    """R14 — Combined: exec private memory + write activity (injection pattern)."""

    # R1 equivalent

    allocs = bundle.allocs or []
    has_exec = any(_is_exec_protect(_get(a, "protect") or "") for a in allocs)

    # R5 equivalent

    wm = _api_count(bundle.api_snapshot, "write_memory")
    has_writes = wm > 4

    # R4 equivalent

    real_writes = [w for w in (bundle.write_events or [])
                   if (_get(w, "base", default=0) or 0) != KUSER_SHARED_DATA]
    has_cross = len(real_writes) > 0

    triggered = has_exec and (has_writes or has_cross)

    detail = "exec memory present + external write activity detected" if triggered else ""

    # returns rulehit object with weight of 2

    return RuleHit(

        "R14",
        "Combined: exec memory + write activity",
        "Executable private memory is present AND external write activity was "
        "detected. Together these represent the payload-staging phase of fileless "
        "injection — shellcode was written then made executable.",
        weight=2, triggered=triggered, detail=detail,
    )

# 15. similar combo pattern to rule 14

# it detects a cross process write combined with nt calls
# this looks for attackers which use more advanced techniques like ntwritevirtualmemory instead of more obvious calls like writeprocessmemory

# essentially it catches out the methods used and attackers who try be stealthy by using low level system calls

def _r15(bundle) -> RuleHit:

    """R15 — Combined: cross-process write + APC/NT import (stealth injection)."""

    # R4 equivalent

    real_writes = [w for w in (bundle.write_events or [])
                   if (_get(w, "base", default=0) or 0) != KUSER_SHARED_DATA]

    has_cross = len(real_writes) > 0

    # R7 equivalent

    ni = bundle.nt_info

    imports = (_get(ni, "direct_nt_imports") or []) if ni else []

    has_suspicious_nt = any(
        _get(i, "watched") and
        (_get(i, "importing_module", default="").lower(),
         _get(i, "function",         default=""))
        not in KNOWN_BENIGN_NT_IMPORTS
        for i in imports
    )

    triggered = has_cross and has_suspicious_nt
    detail = ("cross-process write + suspicious NT import combination"
              if triggered else "")

    # returns rulehit object with weight of 2

    return RuleHit(
        "R15",
        "Combined: cross-process write + suspicious NT import",
        "A genuine cross-process memory write was detected alongside a suspicious "
        "direct NT syscall import — consistent with an APC-queue injection or "
        "NtWriteVirtualMemory-based stealth injection technique.",
        weight = 2, triggered = triggered, detail = detail,
    )

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

# list of all 15 rules
# allows the list to be quickly looped

# new rules in the future need to be added here

_RULE_FUNCS = [
    _r01, _r02, _r03, _r04, _r05, _r06, _r07, _r08,
    _r09, _r10, _r11, _r12, _r13, _r14, _r15,
]

def evaluate_rules(bundle) -> RuleResult:

    """
    Run all rules against the ScanBundle and return a RuleResult.

    Safe to call with a partially-populated bundle — each rule handles
    missing fields gracefully and returns triggered=False.
    """
    # list that creates the ruleresult object with process name and pid
    # the getattr reads the bundle.proc.name

    result = RuleResult(

        process_name = getattr(getattr(bundle, "proc", None), "name", "unknown"),
        pid = getattr(getattr(bundle, "proc", None), "pid", 0),)

    # loop through every rule function
    # each result joins the result.hits

    # the try and exepect catches any errors from the rules, replaces the weights with 0 and doesn't let the rule engine to crash

    # by this point, the bundle from the gui is already loaded in
    # bundle contains all the objects from the dataclasses found in process_data created by the wrappers and returned back to the gui
    # the bundle gets passed onto here with a list of objects and the objects containing all of the data
    # this bundle is then accessible to the rules as they get looped through
    # they pick out what data is needed and return results
    # the results then create the objects with results

    for fn in _RULE_FUNCS:

        try:

            result.hits.append(fn(bundle))

        except Exception as exc:

            # loop throuh the 

            # never let a rule crash the whole scan

            result.hits.append(RuleHit(
                fn.__name__.upper(), fn.__name__,
                "Rule evaluation error.",
                weight=0, triggered=False,
                detail=f"ERROR: {exc}",
            ))

    # return the result
    # result.hits will contain 15 objects
    # the property methods calulcate the scores, colours, cateogry etc

    return result

# ---------------------------------------------------------------------------
# Text formatters (used by GUI console and LLM prompt builder)
# ---------------------------------------------------------------------------

# funtion which builds a detailed string and returns it
# doesn't directly print

# this is because the string will be going to the home screen and also the LLM

# this is the version going to the home console, formatted for readability

def format_console(result: RuleResult) -> str:

    """
    Returns the full rule engine output as a string for the HOME console.
    Always printed regardless of quiet-mode setting.
    """

    W = 62
    lines = []
    lines.append("=" * W)
    lines.append(f"  RULE ENGINE ANALYSIS  —  {result.process_name}  (PID {result.pid})")
    lines.append("=" * W)

    triggered = result.triggered_rules
    clean     = result.clean_rules

    if triggered:

        lines.append(f"\n  TRIGGERED  ({len(triggered)} rule{'s' if len(triggered)!=1 else ''} fired)")
        lines.append("  " + "─" * (W - 2))

        for h in triggered:

            pts = f"+{h.weight} pt{'s' if h.weight != 1 else ''}"
            lines.append(f"  [!]  {h.rule_id:<4}  {h.name:<40} {pts}")
            if h.detail:

                lines.append(f"            {h.detail}")
    else:

        lines.append("\n  TRIGGERED  — none")

    if clean:

        lines.append(f"\n  CLEAN  ({len(clean)} rule{'s' if len(clean)!=1 else ''} passed)")
        lines.append("  " + "─" * (W - 2))

        for h in clean:

            lines.append(f"  [✓]  {h.rule_id:<4}  {h.name}")

    lines.append("\n  " + "─" * (W - 2))
    pct = f"{result.confidence * 100:.1f}%"
    lines.append(f"  SCORE    {result.score} / {result.max_score}"
                 f"          CONFIDENCE   {pct}")
    lines.append(f"  VERDICT  {result.label.upper()}")
    lines.append("=" * W)

    return "\n".join(lines)

# same applies, build string and return

# this is the version going to the llm, formatted for the llm so its easier to undetstand
# this goes in with the raw data collected by the collector, but this goes in first
# so the llm knows whats suspicous before it makes any verdict by itself

# there are also prompts inside the string itself for the llm

def format_llm_prefix(result: RuleResult) -> str:

    """
    Returns a compact rule-engine summary to be prepended to the LLM prompt.
    Gives the model the pre-computed assessment before it sees the raw data.
    """

    triggered = result.triggered_rules
    clean     = result.clean_rules
    pct = f"{result.confidence * 100:.1f}%"

    lines = [
        "=== RULE ENGINE PRE-ASSESSMENT ===",
        f"Confidence : {pct}  |  Score : {result.score} / {result.max_score}"
        f"  |  Verdict : {result.label.upper()}",
        "",
    ]

    if triggered:

        lines.append("Rules TRIGGERED — examine these indicators closely:")

        for h in triggered:

            lines.append(f"  [!] {h.rule_id}  {h.name}  (+{h.weight} pt{'s' if h.weight!=1 else ''})")

            if h.detail:

                lines.append(f"       Detail: {h.detail}")

    else:

        lines.append("Rules TRIGGERED — none (no suspicious indicators detected)")

    lines.append("")
    lines.append("Rules CLEAN — normal behaviour confirmed for:")

    for h in clean:

        lines.append(f"  [✓] {h.rule_id}  {h.name}")

    lines.append("")
    lines.append(
        "The triggered rules above are your primary analytical focus. "
        "The clean rules provide exculpatory context. "
        "Consider how triggered rules combine into a plausible attack sequence."
    )

    lines.append("=== END PRE-ASSESSMENT ===")
    lines.append("")

    return "\n".join(lines)