# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

from dataclasses import dataclass, field
from typing import List, Optional

import base64
import datetime
import memory_scanner

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

# Dataclasses that hold structured data
# Comes with __init__ and __repr__
# They hold data observed during an observation window
# Blueprint for parsers

@dataclass
class Privilege:
    name: str # Name of privilege
    enabled: bool # Is it enabled?

@dataclass
class Module:
    base: int # Memory address
    size: int # Size in bytes
    path: str # Path to the module
    file_backed: bool # True or false whether file is on the disk

@dataclass
class MemoryRegion:
    base: int # Memory address 
    size: int # Size in bytes
    state: str # Commited, active or reserved?
    protect: str # R/RW/X?
    type: str # Private to the app? Mapped to a file? Or shared?
    mapped_file: str # If the file is mapped, return path here
    entropy: float # Randomness score showing encrpyiton / compression
    entropy_sample_size: int # How much memory scanned to show entropy
    entropy_read: bool # True or false if entropy read
    has_mz: bool # Does it contain a MZ header?
    has_pe: bool # Does it contain a PE header?

# Private commited memory region
# Stores raw observations for the rule engine
# MZ, PE, Protect, Entropy etc
# Stores specifically foot prints of VirtualAllocEX / VirtualAlloc
# Calls which indicate that memory was manually injected by a program, behaviour of fileless attack

@dataclass
class VirtualAllocRegion:
    base: int # Memory address
    size: int # Size in bytes
    protect: str # R/RW/X? Human version
    protect_raw: int # Windows version
    entropy: float # Randomness score showing encryption / compression
    entropy_sample_size: int # How much memory scanned to show entropy
    entropy_read: bool # True or false if entropy read
    has_mz: bool # Does it contain a MZ header?
    has_pe: bool # Does it contain a PE header?
    scan_ts_us: int = 0 # Time in unix seconds when scan was started
    event_ts_us: int = 0 # Time in unix seconds when the event was observed
    trace_id: str = "" # Grouped events in a single call

# Memory permission changes
# Malware often starts at write to download the payload
# After it switches to execute to run it

@dataclass
class ProtectChange:
    base: int # Memory address
    protect_old: str # Old permissions before change
    protect_new: str # New permissions after change
    protect_raw_old: int # Old Windows version
    protect_raw_new: int # New Windows version
    gained_exec: bool # Gained execute permission
    lost_write: bool # Lost write permission
    scan_ts_us: int = 0 # Time in unix seconds when scan was started
    event_ts_us: int = 0 # Time in unix seconds when the event was observed
    trace_id: str = "" # Grouped events in a single call

# Process Memory Snapshots
# Takes a snapshot of a process and looks for changes
# If a change occurs, it displays a list of PIDS that had permission to write
# For example, if a change was done by a process not in PID list, it's suspicious

@dataclass
class WriteEvent:
    base: int # Memory address
    size: int # Size in bytes
    protect: str # R/RW/X? Human version
    protect_raw: int # Windows version
    sample_before: str # HEX snippet before a change
    sample_after: str # HEX snipper after a change
    writer_pids: list # A list of PIDS that had permission to write in the memory
    scan_ts_us: int = 0 # Time in unix seconds when scan was started
    event_ts_us: int = 0 # Time in unix seconds when the event was observed
    trace_id: str = "" # Grouped events in a single call

# Import detector
# NT / ZW calls are low level language calls to Windows
# It is done through the Windows API
# Legit applications usually do not import NT calls directly
# For example, if a non system application imports NT calls, it's suspicious
# Offical way to use the API calls

@dataclass
class NtImport:
    importing_module: str # Name of file trying to use the call
    function: str # The low level command being called
    from_dll: str # Source of the function
    watched: bool # True if the call is on the list often used for malware
    scan_ts_us: int = 0 # Time in unix seconds when the scan was started
    event_ts_us: int = 0 # Time in unix seconds when the event was observed
    trace_id: str = "" # Grouped events in a single call

# Direct call detector
# Another way to use low level language calls
# Unofficial way to use the API calls
# Instead of importing the library, it simply copies the oppcode of a call and sends to CPU register
# Much harder to detect by antiviruses since the behaviour is hidden
# Usually only exists in ntdll.dll but once found in private memory, it's risky

@dataclass
class SyscallStub:
    base: int # Memory address
    offset: int # Number of bytes in that address where the instruction sits
    address: int # Exact location of the instruction
    opcode: str # The machine code for the opcode
    context: str # Snippet of the surrounding machine code
    protect: str # # R/RW/X?
    scan_ts_us: int = 0 # Time in unix seconds when the scan was started
    event_ts_us: int = 0 # Time in unix seconds when the event was observed
    trace_id: str = "" # Grouped events in a single call

# Checks ntdll.dll channel
# ntdll.dll is a channel where Windows API calls pass through to kernel
# This channel is watched by antiviruses but malware can hook functions to disable security
# This dataclass stores changes in the ntdll.dll to see if security functions have been altered
# A clean x64 ntdll export channel starts with '4C 8B D1'
# For example, tampered ntdll channel may contain a jump function to skip past security tests

@dataclass
class NtHook:
    function: str # Name of low level function being checked
    address: int # Location of the function
    hook_type: str # Describes what the scan found at the start (clean OR jump to location)
    bytes: str # HEX snippet of nearby code
    hooked: bool # Confirms if ntdll has been tampered
    scan_ts_us: int = 0 # Time in unix seconds when the scan was started
    event_ts_us: int = 0 # Time in unix seconds when the event was observed
    trace_id: str = "" # Grouped events in a single call

# Final report
# Report for a single process listing all results
@dataclass
class NtSyscallInfo:
    direct_nt_imports: list # List[NtImport]
    syscall_stubs: list # List[SyscallStub]
    hooked_functions: list # List[NtHook]
    scan_ts_us: int = 0 # Time in unix seconds when the scan was started
    trace_id: str = "" # Grouped events in a single call

# Threads
# = Single path of execution within a process, who is doing work
# Stores data on workers and where they started
# For example, it's very risky if a thread is not started by a known file or image like a DLL/EXE
# and lives in private memory
# This suggests the running thread is not on a file drive and lives only in memory
# Strong indication of fileless malware running shellcode

@dataclass
class ThreadInfo:
    tid: int # Thread ID
    start_address: int # Memory location of start of thread
    start_module: str # Name of module that started thread, if file started by image (DLL/EXE)
    in_private_exec: bool # True if thread starts in private memory
    in_image: bool # True if started by a known, loaded file
    resolved: bool # Indicates if scanner mapped memory address to a module
    scan_ts_us: int = 0 # Time in unix secnds when the scan was started
    event_ts_us: int = 0 # Time in unix seconds when the event was observed
    trace_id: str = "" # Grouped events in a single call

# Remote thread execution
# One process attacks another process and forces thread creation to execute code
# If another process started a thread in a process, it suggests process injection attack
# Remote thread is true when creator PID is different from the target PID

@dataclass
class RemoteThread:
    tid: int # New thread ID
    start_address: int # Address of new thread
    in_private_exec: bool # True if thread starts in private memory
    in_image: bool # True if started by a known, loaded file
    creator_pid: int # Highlights PID that gave the command to execute the new thread, if 0 no source
    remote: bool # If true, another process started this thread
    scan_ts_us: int = 0 # Time in unix secnds when the scan was started
    event_ts_us: int = 0 # Time in unix seconds when the event was observed
    trace_id: str = "" # Grouped events in a single call

# Hidden modules detector
# Detects code that tries to act as a DLL but hides from Windows checks
# When a DLL is loaded it registers in multiple places in the system
# This dataclass stores information on DLLs that skip the registration

# EnumProcessModuleEx is a Windows API call that enumerates all processes and produces a list
# If the file is missing from the list, it is hiding

# The loader is internal structure in Windows that keeps track of loaded modules
# If not in the loader, it is hidden deep in windows files where most tools do not check

# For example, there is no reason to hide modules deep in Windows files
# If true that a module is hiding, it is likley hiding away from basic security tools

# PEB tracks loaded modules and cotains information about every process, like name, path etc
# ^^ Process Enviroment Block

# This can find fileless malware by finding hidden modules that try and mask their location from the PEB
# This happens because my tool ensures the file path is checked, and if it returns an error (fake path provided),
# then it's discovered a file that is hidding from the system, and is not backed up a file on the disk (fileless) 

@dataclass
class MappedModule:
    base: int # Memory Address
    size: int # Size in bytes
    device_path: str # Location on hard drive where file lives
    has_mz: bool # True is MZ header (EXE)
    not_in_win32_list: bool # True if missing from EnumProcessModuleEx list
    not_in_ldr: bool # If true, module is hiding deep in the system files like PEB
    ldr_available: bool 
    no_file_backing: bool # True if the OS can't find a related file to the disk
    scan_ts_us: int = 0 # Time in unix secnds when the scan was started
    event_ts_us: int = 0 # Time in unix seconds when the event was observed
    trace_id: str = "" # Grouped events in a single call

# Process access check
# Tracks what process has a open handle to another process
# Looks through the relevant permissions too and if they can be abused

@dataclass
class HandleEntry:
    owner_pid: int # PID of the external process
    owner_name: str # Name of the external process
    handle_value: int # ID of the Windows permission
    access_mask: int # Code of all permissions combined
    access_decoded: str # Human version of all permissons combied (R/RW/X)
    has_vm_write: bool # Change process memory?
    has_vm_read: bool # Steal data from memory?
    has_create_thread: bool # Force run new code?
    has_suspend: bool # Freeze the process?
    has_dup_handle: bool # Backup handle?
    has_all_access: bool # Total control?
    scan_ts_us: int = 0 # Time in unix secnds when the scan was started
    event_ts_us: int = 0 # Time in unix seconds when the event was observed
    trace_id: str = "" # Grouped events in a single call

# Order of events
# Program computes the events that took place and in what order and stores here
# Potential events: virtual_alloc" "virtual_protect" "protect_exec" "write_memory" "create_thread"

# Takes the Window start time as anchor (scan_ts_us)
# Uses relative time until something happens (ts_ms)
# Uses absolute time until it finishes (event_ts_us)
# Computes (scan_ts_us + ts_ms * 1000)

@dataclass
class ApiTimelineEvent:
    ts_ms: int # Time to when window started, used for sorting events
    event_ts_us: int # Unix second timestamp (scan_ts_us + ts_ms * 1000)
    event_type: str # Actions the malware took
    detail: str # Text desc of the event
    trace_id: str = "" # Grouped events in a single call

# Count of events
@dataclass
class ApiActivityCounts:
    virtual_alloc: int # Total times a process asked for memory
    virtual_protect: int # Total times a process changed permissions
    protect_exec: int # Total times a permission change results in execute permissions obtained
    write_memory: int # Total times data was modified
    create_thread: int # Total times a new thread was started
    total: int # Total of everything combined above ^^

# API activtiy report
# Stores everything the scanner collected
# Combines how many and in what order
@dataclass
class ApiActivitySnapshot:
    pid: int # Process ID
    window_ms: int # Time the scanner was watching
    samples_taken: int # Number of times the collector scanner during the window_ms
    counts: ApiActivityCounts # Count of events 
    timeline: list # List[ApiTimelineEvent]
    event_sequence: list # List[str] list of events, easy for rule engine
    scan_ts_us: int = 0 # Second timestamp of this observation window start
    trace_id: str = "" # Grouped events in a single call

# Raw data out of RAM
# This dataclass stores the actual raw data in HEX
# The scan can capture part of the malware, convert to hex, store it in this dataclass
# Even if the malware only exists in memory, it will still capture some data about it and with reason

@dataclass
class MemorySample:
    address: int # Location of memory
    size_req: int # How many bytes asked for
    size_read: int # How many bytes received
    data_hex: str # Content of memory in HEX format
    read_ok: bool # Memory ready okay?
    error_code: int # If false ^^ what was the error?
    trigger: str # Reason for taking sample
    context_pid: int # PID of sample process
    scan_ts_us: int = 0 # Second timestamp of this observation window start
    event_ts_us: int = 0 # Time in unix seconds when the event was observed
    trace_id: str = "" # Grouped events in a single call

# Computer hardware usage
# For example, if Notepad.exe suddenly jumps to 50% CPU usgae and has 20 threads open
# with heavy io_write activity, it's being used for something malicious like encrpyting files etc

@dataclass
class PerfSnapshot:
    pid: int # PID of process
    cpu_percent: float # The % of CPU usage
    working_set_kb: int # How much RAM process is using
    private_bytes_kb: int # How much RAM process is using
    peak_ws_kb: int 
    page_faults: int
    io_read_bytes: int # Data moving from / to disk / network
    io_write_bytes: int # Data moving from / to disk / network
    io_read_ops: int  
    io_write_ops: int 
    io_other_bytes: int 
    io_other_ops: int # Tracks malware communcating with hardware drivers
    handle_count: int 
    thread_count: int  
    sample_ok: bool # Success in getting this data from collector?
    scan_ts_us: int = 0
    trace_id: str = "" 

@dataclass
class ProcessInfo:
    pid: int # PID of process
    name: str # Name of process
    path: str # Where on the disk
    integrity: str # Windows trust level (System, HIGH, MEDIUM, LOW)
    elevated: bool # Admin rights?
    privileges: List[Privilege] # The actual list of the previous privileges
    modules: List[Module] # Every DLL/EXE loaded
    memory_regions: List[MemoryRegion] # Complete view of all of the RAM
    kernel_time: int  
    user_time: int
    creation_time: int # When process opened

# ---------------------------------------------------------------------------
# Timestamp utilities
# ---------------------------------------------------------------------------
# Convert a unix timestamp from microseconds to a formatted time
# Unix timestap is returned by nowUs() in c++

# Return empty string if time is 0
# Divide time by 1,000,000 to get seconds
# Convert seconds into the Y/M/D/H/M/S format
# Handle exception incase and return original

def ts_us_to_iso(ts_us: int) -> str:

    if not ts_us:
        return ""

    try:

        dt = datetime.datetime.fromtimestamp(ts_us / 1_000_000)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}"

    except Exception:
        return str(ts_us)

# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------
# Parser functions to assign raw data to the blueprint dataclass
# Parser create an instance of a dataclass with the relevant data

# Dataclass template setup -> parser which assigns fields in the dataclass and returns the instance -> wrapper
# which starts the scan and passes data to the parser -> print function which displays objects from the
# dataclass to the home console

# takes raw dictonary from collector and returns a ProcessInfo dataclass

def parse_process(raw: dict) -> ProcessInfo:
    return ProcessInfo (

        # pulls values from dictonary by key and puts together by matching fields in the dataclass

        pid = raw["pid"],
        name = raw["name"],
        path = raw["path"],
        integrity = raw["integrity"],
        elevated = raw["elevated"],

        # loops through lists
        # gets data from raw data from collector, but exits without crash if empty
        # create dataclass for each relevant object

        privileges = [
            Privilege(p["name"], p["enabled"])
            for p in raw.get("privileges", [])
        ],

        modules = [
            Module(
                base = m["base"],
                size = m["size"],
                path = m["path"],
                file_backed = m["file_backed"],
            )
            for m in raw.get("modules", [])
        ],

        memory_regions = [
            MemoryRegion(
                base = r["base"],
                size = r["size"],
                state = r["state"],
                protect = r["protect"],
                type = r["type"],
                mapped_file = r["mapped_file"],
                entropy = r["entropy"],
                entropy_sample_size = r["entropy_sample_size"],
                entropy_read = r["entropy_read"],
                has_mz = r["has_mz"],
                has_pe = r["has_pe"],
            )
            for r in raw.get("memory_regions", [])
        ],

        kernel_time = raw["kernel"],
        user_time = raw["user"],
        creation_time = raw["creation"],
    )

# takes raw dictonary from collector and returns a VirtualAllocRegion dataclass

def parse_virtual_alloc(raw: dict) -> VirtualAllocRegion:

    return VirtualAllocRegion(
        base = raw["base"],
        size = raw["size"],
        protect = raw["protect"],
        protect_raw = raw["protect_raw"],
        entropy = raw["entropy"],
        entropy_sample_size = raw["entropy_sample_size"],
        entropy_read = raw["entropy_read"],
        has_mz = raw["has_mz"],
        has_pe = raw["has_pe"],

        # these fields are optional if collector is able to return
        # otherwise use the default / leave empty

        scan_ts_us = int(raw.get("scan_ts_us",  0)),
        event_ts_us = int(raw.get("event_ts_us", 0)),
        trace_id = str(raw.get("trace_id", "")),
    )

# creates instance of ProtectChange dataclass
# parser

def parse_protect_change(raw: dict) -> ProtectChange:

    # changes in memory worked out already by collector
    # it's better because the rule engine doesn't have to compare old vs new permissions
    # It's simply a boolean that tracks if change occured

    return ProtectChange(
        base = raw["base"],
        protect_old = raw["protect_old"],
        protect_new = raw["protect_new"],
        protect_raw_old = raw["protect_raw_old"],
        protect_raw_new = raw["protect_raw_new"],
        gained_exec = raw["gained_exec"],
        lost_write = raw["lost_write"],
        scan_ts_us = int(raw.get("scan_ts_us",  0)),
        event_ts_us = int(raw.get("event_ts_us", 0)),
        trace_id = str(raw.get("trace_id", "")),
    )

# call for collector to find protect changes
# gui calls for a scan -> this call is passed here to launch scan -> scan for protectchanges
# done by c++ -> data    gets passed back here to parse -> instance of dataclass created

# this is setup this way so the gui never handels raw data
# wraper

def get_protect_changes(pid: int, delay_ms: int = 500) -> list:

    """
    Detect VirtualProtect activity by diffing two memory snapshots of the
    given PID separated by delay_ms milliseconds.
    Returns a list of ProtectChange objects for every region whose protection
    flags changed between the two samples.
    """

    # call to launch collector to look for protect changes
    # targets pid and waits the delay
    # takes snapshot at start, then at end of delay

    raw_list = memory_scanner.get_protect_changes(pid, delay_ms)

    # loops through every raw item in the list
    # converts it into a ProtectChange dataclass
    # collcets all results into a new list

    # isolated by pid so there is no chance of data mix up

    return [parse_protect_change(r) for r in raw_list] # EACH RETURN IN WRAPPER RETURNS DATA OBJECTS BACK TO GUI TO CREATE SCANBUNDLE

# print function for protect changes
# uses the information from earlier created dataclass objects

def print_protect_changes(pid: int, name: str, delay_ms: int = 500):

    print(f"\nProtection change scan for {name} (PID {pid})")
    print(f"  Snapshot interval : {delay_ms} ms")

    # call to function above to return protect changes

    changes = get_protect_changes(pid, delay_ms)
    gained_exec = [c for c in changes if c.gained_exec] # filters through gained execution

    # prints the counts in the home console

    print(f"  Total changes detected : {len(changes)}")
    print(f"  Gained exec            : {len(gained_exec)}")
    print()

    if not changes:
        print("No protection changes detected in the snapshot window.")
        return

    # if the list is empty, it would stop above ^^
    # if list NOT empty, continue

    # every object that was looped through in "changes", print out its details here
    # and the objects are the dataclasses instances

    print(
        f"  {'Base':<14} " # <14 etc is padding for style in home screen
        f"{'Old':<8} "
        f"{'New':<8} "
        f"{'GainedExec':<11} "
        f"{'LostWrite'}"
    )

    print("  " + "-" * 55) # prints out ----------- for looks

    for c in changes:
        print(
            f"  {hex(c.base):<14} "
            f"{c.protect_old:<8} "
            f"{c.protect_new:<8} "
            f"{str(c.gained_exec):<11} "
            f"{str(c.lost_write)}"
        )

# creates insance of write events dataclass
# parser

def parse_write_event(raw: dict) -> WriteEvent:

    return WriteEvent(
        base = raw["base"],
        size = raw["size"],
        protect = raw["protect"],
        protect_raw = raw["protect_raw"],
        sample_before = raw["sample_before"], # raw HEX before
        sample_after = raw["sample_after"], # raw HEX after
        writer_pids = list(raw["writer_pids"]), # list of pids that had permisson to write in the process
        scan_ts_us = int(raw.get("scan_ts_us",  0)),
        event_ts_us = int(raw.get("event_ts_us", 0)),
        trace_id = str(raw.get("trace_id", "")),
    )

# call to collector to get write detected data
# wraper

def get_write_detect(pid: int, delay_ms: int = 500) -> list:

    """
    Detect cross-process WriteProcessMemory activity against the given PID.
    Takes two content snapshots of private committed regions separated by
    delay_ms milliseconds and reports any region whose bytes changed.
    Also enumerates processes that hold PROCESS_VM_WRITE handles to the
    target to identify likely source PIDs.
    """

    # runs a call to the collector
    # reterives the raw data into list format

    raw_list = memory_scanner.get_write_detect(pid, delay_ms)

    # create instance object of each write event in the list collected
    # and returns them as a list

    return [parse_write_event(r) for r in raw_list]

# print to display write detected
# prints the earlier created dataclass instance

def print_write_detect(pid: int, name: str, delay_ms: int = 500):

    print(f"\nCross-process write scan for {name} (PID {pid})")
    print(f"  Snapshot interval : {delay_ms} ms")

    events = get_write_detect(pid, delay_ms)
    with_writers = [e for e in events if e.writer_pids]

    print(f"  Changed regions detected : {len(events)}")
    print(f"  With confirmed writer PID: {len(with_writers)}")

    if not events:

        print("  No cross-process writes detected in the snapshot window.")
        return

    # loop through every event, then through every pid in the events write_pids list
    # collect all events and remove duplicates
    # sorted puts everything bac in order

    # this happens because if multiple regions are are written by the same attacker pid
    # it will appear only once in the list, not multiple times

    all_writers = sorted({p for e in events for p in e.writer_pids})

    if all_writers:
        print(f"  Writer PIDs with PROCESS_VM_WRITE handle: {all_writers}")

    print()

    print(
        f"  {'Base':<14} "
        f"{'Size':<10} "
        f"{'Prot':<6} "
        f"{'Writers':<20} "
        f"{'Before (hex)':<20} "
        f"After (hex)"
    )

    print("  " + "-" * 80)

    # this loops through events list
    # and prints out the HEX samples

    # if the HEX sample is over 20 characters, it gets cut down and inserts ..
    # this is visually ONLY
    # the actual instance still contains the full HEX sample

    for e in events:

        writers_str = str(e.writer_pids) if e.writer_pids else "none"
        before_str = e.sample_before[:20] + ".." if len(e.sample_before) > 20 else e.sample_before
        after_str = e.sample_after[:20]  + ".." if len(e.sample_after)  > 20 else e.sample_after

        print(
            f"  {hex(e.base):<14} "
            f"{hex(e.size):<10} "
            f"{e.protect:<6} "
            f"{writers_str:<20} "
            f"{before_str:<22} "
            f"{after_str}"
        )

# parser for nt syscalls
# takes raw data from the collector and returns a dataclass

def parse_nt_syscall_info(raw: dict) -> NtSyscallInfo:

    # every direct NT import found from the list created by the collector
    # the list is a list of dictonaries

    # loops through all of the NT imports found and creates an instance of each
    # converts raw dictonaries into a proper NTImport objects
    # imports ends up as a list of NTImport objects

    # direct_nt_imports is the actual list of dictonaires and for every import, it creates an object

    imports = [NtImport(
        
        importing_module = r["importing_module"],
        function = r["function"],
        from_dll = r["from_dll"],
        watched = r["watched"],
        scan_ts_us = int(r.get("scan_ts_us",  0)),
        event_ts_us = int(r.get("event_ts_us", 0)),
        trace_id = str(r.get("trace_id",    "")),
    ) for r in raw["direct_nt_imports"]]

    # the same applies

    stubs = [SyscallStub(

        base = r["base"],
        offset = r["offset"],
        address = r["address"],
        opcode = r["opcode"],
        context = r["context"],
        protect = r["protect"],
        scan_ts_us = int(r.get("scan_ts_us",  0)),
        event_ts_us = int(r.get("event_ts_us", 0)),
        trace_id = str(r.get("trace_id",    "")),
    ) for r in raw["syscall_stubs"]]

    # the same applies

    hooks = [NtHook(

        function = r["function"],
        address = r["address"],
        hook_type = r["hook_type"],
        bytes = r["bytes"],
        hooked = r["hooked"],
        scan_ts_us = int(r.get("scan_ts_us",  0)),
        event_ts_us = int(r.get("event_ts_us", 0)),
        trace_id = str(r.get("trace_id",    "")),
    ) for r in raw["hooked_functions"]]

    # creates an instance of NTSyscallInfo which contains lists of objects from the previous 3 lists
    # so the object stores 3 fields as lists 

    return NtSyscallInfo(

        direct_nt_imports = imports,
        syscall_stubs = stubs,
        hooked_functions = hooks,
        scan_ts_us = int(raw.get("scan_ts_us", 0)),
        trace_id = str(raw.get("trace_id",   "")),
    )

# call to the collector to collect NTSysCall info
# wrapper

def get_nt_syscall_info(pid: int) -> NtSyscallInfo:

    """
    NT syscall analysis: direct Nt* imports, syscall stubs in private memory,
    and ntdll hook detection. Returns an NtSyscallInfo dataclass.
    """

    # call to the collector to return the data

    raw = memory_scanner.get_nt_syscall_info(pid)

    # returns one list with 3 sub lists
    # the lists get sorted at the parser and seperated into seperate objects

    return parse_nt_syscall_info(raw)

# print to display ntsyscall 

def print_nt_syscall_info(pid: int, name: str):

    print(f"\nNT syscall analysis for {name} (PID {pid})")

    # info is the parent of NTSYSCALLINFO
    # because it contains the 3 sublists

    info = get_nt_syscall_info(pid)

    # direct NT imports

    print(f"\n  [1] Direct Nt*/Zw* imports in non-system modules: "
          f"{len(info.direct_nt_imports)}")

    # if true, print out the ----- header and divider lines

    if info.direct_nt_imports:
        print(f"      {'Module':<30} {'Function':<35} {'Watched'}")
        print("      " + "-" * 70)

        # after loop through every NT import and print out
        # if boolean import.watched becomes true flags the NT call as high value
        # else print out the NT call but without high value

        for imp in info.direct_nt_imports:
            flag = " <-- HIGH VALUE" if imp.watched else ""
            print(f"      {imp.importing_module:<30} {imp.function:<35} "
                  f"{str(imp.watched)}{flag}")

    # else the list is empty and none is found

    else:
        print("      None found.")

    # syscall stubs

    # same applies

    print(f"\n  [2] Syscall stubs in executable private memory: "
          f"{len(info.syscall_stubs)}")

    if info.syscall_stubs:
        print(f"      {'Address':<18} {'Opcode':<22} {'Protect':<8} Context")
        print("      " + "-" * 70)

        for s in info.syscall_stubs:
            print(f"      {hex(s.address):<18} {s.opcode:<22} "
                  f"{s.protect:<8} {s.context}")
    else:
        print("      None found.")

    # ntdll hooks

    # same applies

    hooked_count = sum(1 for h in info.hooked_functions if h.hooked)
    print(f"\n  [3] ntdll export hook check: "
          f"{hooked_count} hooked / {len(info.hooked_functions)} checked")

    if info.hooked_functions:
        print(f"      {'Function':<30} {'Hook type':<22} Bytes")
        print("      " + "-" * 70)

        for h in info.hooked_functions:
            status = "HOOKED" if h.hooked else "clean"
            print(f"      {h.function:<30} {h.hook_type:<22} {h.bytes}  [{status}]")
    else:
        print("      Could not read ntdll exports.")

# parser for thread calls
# takes raw data from the collector and returns a dataclass

def parse_thread_info(raw: dict) -> ThreadInfo:
    return ThreadInfo(
        tid = raw["tid"],
        start_address = raw["start_address"],
        start_module = raw["start_module"],
        in_private_exec = raw["in_private_exec"],
        in_image = raw["in_image"],
        resolved = raw["resolved"],
        scan_ts_us = int(raw.get("scan_ts_us",  0)),
        event_ts_us = int(raw.get("event_ts_us", 0)),
        trace_id = str(raw.get("trace_id",    "")),
    )

# call to the collector to collect NTSysCall info
# wrapper

def get_thread_info(pid: int) -> list:

    """Enumerate threads in pid with Win32 start addresses and classification."""

    thread_list = memory_scanner.get_thread_info(pid)

    return [parse_thread_info(r) for r in thread_list]

# print to display thread info
# prints the earlier created dataclass instance

# this function is soley for printing services
# the dataclass object does not see the priority decided below

def print_thread_info(pid: int, name: str):

    # threads list which loops through to find suspicious threads

    threads = get_thread_info(pid)
    in_private = [t for t in threads if t.in_private_exec]

    print(f"\nThread start address audit for {name} (PID {pid})")
    print(f"  Total threads    : {len(threads)}")
    print(f"  In private exec  : {len(in_private)}")

    # if threads not empty, loop through each thread object

    if threads:

        # print divider here

        print(f"\n  {'TID':<8} {'Start Address':<20} {'Module / Region':<30} Flags")
        print("  " + "-" * 72)

        # if threads not empty, loop through each thread object

        for t in threads:

            # for each thread object, take start of address and convert to hex, otherwise unknown
            # unknwon because thread details are private

            addr_str = hex(t.start_address) if t.start_address else "unknown" 

            # priority chains which decides what to show in the region column

            if t.start_module:
                region = t.start_module
            elif t.in_private_exec:
                region = "<private exec>"
            elif t.in_image:
                region = "<image>"
            elif t.resolved:
                region = "<non-exec region>"
            else:
                region = "<unresolved>"

            # if thread in private executeable flag as dangerous

            if t.in_private_exec:
                flags = "private exec"
            elif not t.resolved:
                flags = "unresolved"
            else:
                flags = ""

            print(f"  {t.tid:<8} {addr_str:<20} {region:<30} {flags}")

# parser for remote thread calls
# takes raw data from the collector and returns a dataclass

def parse_remote_thread(raw: dict) -> RemoteThread:

    return RemoteThread(
        tid = raw["tid"],
        start_address = raw["start_address"],
        in_private_exec = raw["in_private_exec"],
        in_image = raw["in_image"],
        creator_pid = raw["creator_pid"],
        remote = raw["remote"],
        scan_ts_us = int(raw.get("scan_ts_us",  0)),
        event_ts_us = int(raw.get("event_ts_us", 0)),
        trace_id = str(raw.get("trace_id",    "")),
    )

# call to the collector to collect remotethreads
# wrapper

def get_remote_threads(pid: int, delay_ms: int = 500) -> list:

    """Detect threads created in pid during observation window, with creator PID."""

    remote_thread_list = memory_scanner.get_remote_threads(pid, delay_ms)

    return [parse_remote_thread(r) for r in remote_thread_list]

# print to display remote thread info
# prints the earlier created dataclass instance

def print_remote_threads(pid: int, name: str, delay_ms: int = 500):

    print(f"\nRemote thread detector for {name} (PID {pid})  [{delay_ms}ms window]")

    # returns a remote thread list

    events = get_remote_threads(pid, delay_ms)

    # return the print statment, no new threads detected

    if not events:
        print("  No new threads detected during observation window.")
        return

    # loops through events and prints out only new remote threads

    remote = [e for e in events if e.remote]
    print(f"  New threads : {len(events)}")
    print(f"  Remote      : {len(remote)}")

    # prints divider

    print(f"\n  {'TID':<8} {'Start Address':<20} {'Creator PID':<14} Flags")
    print("  " + "-" * 65)

    for e in events:

        # print out the start of the address in HEX

        addr_str = hex(e.start_address) if e.start_address else "unknown"
        creator_str = str(e.creator_pid) if e.creator_pid else "self / unknown"

        # builds an empty list
        # then assings flags to the list which is linked to the object
        # this ensures a single object can have multiple flags
        # for example can be remote and private

        flags = []

        if e.remote:
            flags.append("remote")
        if e.in_private_exec:
            flags.append("private exec start")

        # print out column to the console

        print(f"  {e.tid:<8} {addr_str:<20} {creator_str:<14} {', '.join(flags)}")


# parser for remote mapped module calls
# takes raw data from the collector and returns a dataclass

def parse_mapped_module(raw: dict) -> MappedModule:

    return MappedModule(
        base = raw["base"],
        size = raw["size"],
        device_path = raw["device_path"],
        has_mz = raw["has_mz"],
        not_in_win32_list = raw["not_in_win32_list"],
        not_in_ldr = raw["not_in_ldr"],
        ldr_available = raw["ldr_available"],
        no_file_backing = raw["no_file_backing"],
        scan_ts_us = int(raw.get("scan_ts_us",  0)),
        event_ts_us = int(raw.get("event_ts_us", 0)),
        trace_id = str(raw.get("trace_id",    "")),
    )

# call to the collector to collect mappedmodules
# wrapper

def get_mapped_modules(pid: int) -> list:

    """Detect manually mapped / hidden modules in a process."""

    mapped_module_list = memory_scanner.get_mapped_modules(pid)

    return [parse_mapped_module(r) for r in mapped_module_list]

# print to display  mapped modules
# prints the earlier created dataclass instance

def print_mapped_modules(pid: int, name: str):

    """Cross-reference MEM_IMAGE regions against Win32 and PEB LDR module lists."""

    # returns a list of mapped modules

    mods = get_mapped_modules(pid)

    print(f"\nManually mapped / hidden module scan for {name} (PID {pid})")

    # if false, no regions are found and output

    if not mods:
        print("  No anomalous image regions found.")
        return

    ldr_note = ""

    # if mapped moudle list is not empty, it checks for the first object in the list to see if PEB was ready
    # if not, output the error

    if mods and not mods[0].ldr_available:
        ldr_note = " (PEB walk unavailable - 32-bit target or access denied)"

    # output to home console details from the module and loader notes
    # then print divider

    print(f"  Anomalous image regions: {len(mods)}{ldr_note}")

    print(f"\n  {'Base':<20} {'Size':<12} {'MZ':<5} "
          f"{'!Win32':<8} {'!LDR':<7} {'!File':<7} Path")

    print("  " + "-" * 82)

    # in a module, if there is no file path, it displays no backing

    for m in mods:
        path_str = m.device_path if m.device_path else "<no backing>"

        # if file path is accessible, keep the last 47 characters

        if len(path_str) > 50:
            path_str = "..." + path_str[-47:]

        # if loader is available, print out
        # otherwise N/A

        not_ldr_str = str(m.not_in_ldr) if m.ldr_available else "N/A"

        # column to console

        print(f"  {hex(m.base):<20} {hex(m.size):<12} "
              f"{str(m.has_mz):<5} {str(m.not_in_win32_list):<8} "
              f"{not_ldr_str:<7} {str(m.no_file_backing):<7} {path_str}")

# parser for remote handle entry
# takes raw data from the collector and returns a dataclass

def parse_handle_entry(raw: dict) -> HandleEntry:

    return HandleEntry(
        owner_pid = raw["owner_pid"],
        owner_name = raw["owner_name"],
        handle_value = raw["handle_value"],
        access_mask = raw["access_mask"],
        access_decoded = raw["access_decoded"],
        has_vm_write = raw["has_vm_write"],
        has_vm_read = raw["has_vm_read"],
        has_create_thread = raw["has_create_thread"],
        has_suspend = raw["has_suspend"],
        has_dup_handle = raw["has_dup_handle"],
        has_all_access = raw["has_all_access"],
        scan_ts_us = int(raw.get("scan_ts_us",  0)),
        event_ts_us = int(raw.get("event_ts_us", 0)),
        trace_id = str(raw.get("trace_id",    "")),
    )

# call to the collector to collect handle audit for entires
# wrapper

def get_handle_audit(pid: int) -> list:

    """Enumerate all external handles open to pid. Returns a list of HandleEntry."""

    handle_audit_list = memory_scanner.get_handle_audit(pid)

    return [parse_handle_entry(r) for r in handle_audit_list]

# print to display handle audit
# prints the earlier created dataclass instance

# this works by the target process being scanned and the external processes is the ones that opended a handle
# scanner checks the target and who else has open permissions to interact

def print_handle_audit(pid: int, name: str):

    """Print all external handles open to a process with their decoded access rights."""

    # list to store handle audit for each object

    entries = get_handle_audit(pid)

    print(f"\nHandle / open-access audit for {name} (PID {pid})")

    # if empty (false) print out the early error

    if not entries:
        print("  No external handles with notable access found.")
        return

    # print out the total of external handles

    print(f"  Total external handles: {len(entries)}")

    # loops through the list handle objects
    # groups the handle entires by owner pid

    by_owner: dict = {}

    # if owner pid not in the dict yet, then append

    for e in entries:
        by_owner.setdefault(e.owner_pid, []).append(e)

    print(f"\n  {'Owner PID':<12} {'Owner Name':<25} "
          f"{'Handle':<8} {'Mask':<12} Rights")
    print("  " + "-" * 80)

    # 1st loop: loop goes through each owner pid
    # as in each external process that has an open handle to the target

    # 2nd loop: then it loops through every handle the owner has
    # because one process can have multiple handles with different permissions

    # this is then printed out in the home console

    for owner_pid in sorted(by_owner.keys()):

        for e in by_owner[owner_pid]:

            mask_str = f"0x{e.access_mask:08X}"
            name_str = e.owner_name[:24] if e.owner_name else "<unknown>"
            hval_str = f"0x{e.handle_value:04X}"

            print(f"  {e.owner_pid:<12} {name_str:<25} "
                  f"{hval_str:<8} {mask_str:<12} {e.access_decoded}")

# ---------------------------------------------------------------------------
# API activity snapshot parse / get / print
# ---------------------------------------------------------------------------

def parse_api_activity_snapshot(raw: dict) -> ApiActivitySnapshot:

    # pre extraction code to get counts from the dataclass instance
    # it creates variabales for the most common used data

    rc = raw.get("counts", {})

    # variables that are commonly used set up early 

    scan_ts  = int(raw.get("scan_ts_us", 0))
    trace_id = str(raw.get("trace_id",   ""))

    # actual counts are here
    # creates an object instance of the dataclass and stores the count of each specific call made

    # count objects storing totals

    counts = ApiActivityCounts(
        virtual_alloc = rc.get("virtual_alloc",   0),
        virtual_protect = rc.get("virtual_protect",  0),
        protect_exec = rc.get("protect_exec",     0),
        write_memory = rc.get("write_memory",     0),
        create_thread = rc.get("create_thread",    0),

        total = rc.get("total",            0), # total count
    )

    timeline = [

        # timeline stores each individual event with order and timestamp
        # raw dictonaires are passed through and timeline event objects are created
        # these objects are then stored in the timeline list

        ApiTimelineEvent(
            ts_ms = ev.get("ts_ms",       0),
            event_ts_us = int(ev.get("event_ts_us", scan_ts + ev.get("ts_ms", 0) * 1000)), # if missing
            event_type = ev.get("event_type",  ""),
            detail = ev.get("detail",      ""),
            trace_id = str(ev.get("trace_id", trace_id)),
        )

        for ev in raw.get("timeline", [])
    ]
    
    # parser for APIActivtiySnapshot
    # takes raw data from the collector and returns a dataclass

    return ApiActivitySnapshot(

        pid = raw.get("pid",           0),
        window_ms = raw.get("window_ms",     0),
        samples_taken = raw.get("samples_taken", 0),
        counts = counts,
        timeline = timeline,
        event_sequence = list(raw.get("event_sequence", [])),
        scan_ts_us = scan_ts,
        trace_id = trace_id,
    )

# call to the collector to collect api activtiy
# wrapper

def get_api_activity_snapshot(pid: int, delay_ms: int = 1000, num_samples: int = 5) -> ApiActivitySnapshot:

    raw_api_activity = memory_scanner.get_api_activity_snapshot(pid, delay_ms, num_samples)
    
    # single dictonary returned so no for loop

    return parse_api_activity_snapshot(raw_api_activity)

# simple dictonary that maps raw events to a simple name

_EVENT_LABELS = {
    "virtual_alloc": "ALLOC  ",
    "virtual_protect": "PROTECT",
    "protect_exec": "EXEC+  ",
    "write_memory": "WRITE  ",
    "create_thread": "THREAD ",
}

# print to display API activtiy
# prints the earlier created dataclass instance

def print_api_activity_snapshot(pid: int, name: str, delay_ms: int = 1000, num_samples: int = 5):

    # retreive raw data

    snap = get_api_activity_snapshot(pid, delay_ms, num_samples)

    interval = delay_ms // num_samples

    # print to home console the basic details

    print(f"\nAPI activity snapshot for {name} (PID {pid})")
    print(f"  Window: {snap.window_ms}ms  |  "
          f"{snap.samples_taken} sub-samples  |  ~{interval}ms interval")

    # snap is the api activtiy snapshot object
    # counts is in api activtiy count object
    # count object lives in api activtiy snapshot object because the count is ApiActivityCounts
    # so to access counts, program has to go through 2 objects
    # so its easier to build a shortcut

    c = snap.counts

    # print out the data from dataclass objects

    print(f"\n  Inferred call counts")
    print(f"  {'VirtualAllocEx':<22}: {c.virtual_alloc}")
    print(f"  {'VirtualProtect':<22}: {c.virtual_protect}"
          + (f"  ({c.protect_exec} gained exec)" if c.protect_exec else ""))
    print(f"  {'WriteProcessMemory':<22}: {c.write_memory}")
    print(f"  {'CreateRemoteThread':<22}: {c.create_thread}")
    print(f"  {'Total events':<22}: {c.total}")

    # if timeline is not empty

    if snap.timeline:

        print(f"\n  Timeline  ({len(snap.timeline)} events)")
        print(f"  {'ms':>6}  {'Type':<10}  Detail")
        print("  " + "-" * 60)

        # snap.timeline is the list of apitimeline event objects inside apiactivtiysnapshot
        # so each time ev loops, its a single object in the apitimelineevent

        for ev in snap.timeline:
            
            # ev.event_type = virtual_alloc for example
            # this field is compared against the dictonary to get the clean version
            # otherwise take the 7 last letters

            label = _EVENT_LABELS.get(ev.event_type, ev.event_type[:7])
            print(f"  {ev.ts_ms:>6}ms  {label}  {ev.detail}")

    # print the events

    if snap.event_sequence:

        print(f"\n  Event sequence (distinct, first-seen order)")

        print(f"    {' -> '.join(snap.event_sequence)}") # list of events in order they appeared
        # it connets them in the same list by ->


# call to the collector to collect process data
# wrapper

def get_processes() -> List[ProcessInfo]:

    """
    Fast enumeration of all running processes.
    modules and memory_regions will be empty - call scan_single_process for those.
    """

    raw_list = memory_scanner.list_processes()

    return [parse_process(p) for p in raw_list]

# call to the collector to collect single process data
# wrapper

# gets called once and returns process info which contains a lot of data to print out
# creates object of process info

def scan_single_process(pid: int) -> ProcessInfo:

    """
    Full deep scan of one process by PID.
    Includes module enumeration and memory region scanning with entropy.
    """

    raw_list = memory_scanner.scan_process(pid)

    return parse_process(raw_list)

# call to the collector to collect virtual alloc data
# wrapper

# SCAN 1

def get_virtual_allocs(pid: int) -> List[VirtualAllocRegion]:

    """
    Returns all private committed memory regions for the given PID.
    These are the regions created by VirtualAllocEx / VirtualAlloc calls.
    Suspicious regions (executable protection or MZ/PE header present)
    are flagged for fileless malware detection.
    """

    raw_list = memory_scanner.get_virtual_allocs(pid)

    return [parse_virtual_alloc(r) for r in raw_list]

# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------
# These printers do not have their own wrappers
# Beacuse processinfo is already collected by single scan single process wrapper
# Most of these are just pritning out the objects from the dataclass 

# print process helper

def print_process_summary(proc: ProcessInfo):

    # reading fields directly from the object and printing

    print("=" * 60)
    print(f"Process : {proc.name}  (PID {proc.pid})")
    print(f"Path    : {proc.path}")
    print(f"Integrity : {proc.integrity}")
    print(f"Elevated  : {proc.elevated}")

    # loops through a list of privileges inside processinfo object
    # pulls out names of priv that are enabled currently

    enabled_privs = [p.name for p in proc.privileges if p.enabled]

    # if priv are enabled, print them out
    # otherwise none

    if enabled_privs:
        print("Enabled privileges:")
        for p in enabled_privs:
            print(f"  - {p}")
    else:
        print("Enabled privileges: none")

    print(f"Loaded modules : {len(proc.modules)}")
    print(f"Memory regions : {len(proc.memory_regions)}")

# print module helper

def print_modules(proc: ProcessInfo):

    if not proc.modules:
        print("  No modules visible.")
        return

    print(f"\nModules for {proc.name} (PID {proc.pid})")
    print(f"{'Base':<18} {'Size (KB)':<10} {'File-backed':<12} Path")
    print("-" * 80)

    for m in proc.modules:

        print(
            f"{hex(m.base):<18} "
            f"{m.size // 1024:<10} "
            f"{str(m.file_backed):<12} "
            f"{m.path}"
        )

# print memory regions helper

def print_memory_regions(proc: ProcessInfo, limit: int = 15, max_path: int = 40):

    if not proc.memory_regions:
        print("  No memory regions available.")
        return

    print(f"\nMemory regions for {proc.name} (PID {proc.pid})")

    print(
        f"{'Base':<12} "
        f"{'SizeKB':>8} "
        f"{'State':<8} "
        f"{'Prot':<5} "
        f"{'Type':<8} "
        f"{'Ent':>6} "
        f"{'Samp':>6} "
        f"{'Read':>5} "
        f"{'MZ':>3} "
        f"{'PE':>3} "
        f"MappedFile"
    )
    print("-" * 120)

    # limits the print statment to first 15

    for r in proc.memory_regions[:limit]:

        # entropy gets formatted to 2 decimal places here
        # otherwise cross out

        entropy_str = f"{r.entropy:5.2f}" if r.entropy >= 0 else "  -- "
        path = r.mapped_file or "" # if empty give empty string for error handle

        # cut the path and show only the end

        if len(path) > max_path:
            path = "..." + path[-(max_path - 3):] #.../path/continues
        
        # print out everything

        print(
            f"{hex(r.base):<12} "
            f"{r.size // 1024:8} "
            f"{r.state:<8} "
            f"{r.protect:<5} "
            f"{r.type:<8} "
            f"{entropy_str:>6} "
            f"{r.entropy_sample_size:6} "
            f"{str(r.entropy_read):>5} "
            f"{str(r.has_mz):>3} "
            f"{str(r.has_pe):>3} "
            f"{path}"
        )

    total = len(proc.memory_regions)

    # after the slice it shows how many more were hidden

    if total > limit:
        print(f"  ... and {total - limit} more regions (showing first {limit})")

# print vritual allocs

def print_virtual_allocs(pid: int, name: str):

    allocs = get_virtual_allocs(pid)

    print(f"\nVirtualAlloc regions for {name} (PID {pid})")
    print(f"  Total private committed regions : {len(allocs)}")

    # loops through the list and searches for execute permissions
    # if permission found, count goes up
    # finds total count of execute permissions

    exec_count = 0

    for a in allocs:
        if "X" in a.protect or "WX" in a.protect or "RX" in a.protect or "RWX" in a.protect:
            exec_count += 1

    # same applies
    # just counts for mz headers

    mz_count = 0

    for a in allocs:
        if a.has_mz:
            mz_count += 1

    print(f"  With exec protection            : {exec_count}")
    print(f"  With MZ header                  : {mz_count}")
    print()

    # if nothing in the list, exit here

    if not allocs:

        print("  No private committed regions found.")
        return

    # otherwise print

    print(
        f"  {'Base':<14} "
        f"{'SizeKB':>8} "
        f"{'Protect':<8} "
        f"{'Entropy':>7} "
        f"{'MZ':>3} "
        f"{'PE':>3}"
    )

    print("  " + "-" * 52)

    # print for entropy and other details

    for a in allocs:

        entropy_str = f"{a.entropy:6.3f}" if a.entropy >= 0 else "   -- "

        print(
            f"  {hex(a.base):<14} "
            f"{a.size // 1024:8} "
            f"{a.protect:<8} "
            f"{entropy_str:>7} "
            f"{str(a.has_mz):>3} "
            f"{str(a.has_pe):>3}"
        )

# ---------------------------------------------------------------------------
# Memory sampling  (H. Short memory samples on trigger only)
#
# The C++ layer provides a single primitive: read N bytes from a virtual
# address in a process.  This Python layer decides WHAT is worth sampling
# and WHY, producing MemorySample objects with a human-readable trigger.
#
# Trigger sources:
#   1. VirtualAllocRegion  - sample first 4 KB of executable or MZ/PE regions
#   2. ThreadInfo          - 512 bytes centred on start_address for
#                            in_private_exec threads
#   3. RemoteThread        - same window around start_address
#   4. MappedModule        - first 4 KB of anomalous image regions
#   5. WriteEvent          - re-read 512 bytes of the changed region (current
#                            state after the write; the before/after hex is
#                            already stored in the WriteEvent itself, so this
#                            captures a wider context window)
#
# All trigger functions return List[MemorySample].  The caller (GUI scan
# handler) collects and passes them to print_memory_samples().
# ---------------------------------------------------------------------------

# bytes read per sample for region dumps (first N bytes of the region)
_REGION_SAMPLE_BYTES = 4096

# bytes captured around a thread start address (+/- this many bytes)
_THREAD_CONTEXT_BYTES = 256

# parser for memorysample
# takes raw data from the collector and returns a dataclass

# private parser
# takes additional parameters like trigger and pid, passed from caller

def _parse_sample(raw: dict, trigger: str, pid: int) -> "MemorySample":

    return MemorySample(
        address = raw["address"],
        size_req = raw["size_req"],
        size_read = raw["size_read"],
        data_hex = raw["data_hex"],
        read_ok = raw["read_ok"],
        error_code = raw["error_code"],
        trigger = trigger,
        context_pid = pid,
        scan_ts_us = int(raw.get("scan_ts_us",  0)),
        event_ts_us = int(raw.get("event_ts_us", 0)),
        trace_id = str(raw.get("trace_id",    "")),
    )


# ---------------------------------------------------------------------------
# 1. VirtualAllocRegion triggers
#    Sample executable regions and regions that contain an MZ/PE header.
#    These are the primary indicators of injected shellcode or a reflective
#    loader staging area.
# ---------------------------------------------------------------------------

def sample_virtual_allocs(pid: int, allocs: list, max_samples: int = 20) -> list:

    """
    Given the output of get_virtual_allocs(), return MemorySample objects for
    regions that are executable OR contain an MZ/PE header.

    Parameters
    ----------
    pid         : target process PID
    allocs      : list of VirtualAllocRegion (already parsed)
    max_samples : cap on the number of samples taken (avoids huge dumps for
                  heavily fragmented heaps with many exec regions)
    """

    regions = []

    for a in allocs:

        # determine whether this region is worth sampling

        # loops through virtualallocregion objects
        # checks for executeable permissions or mz pe header
        # otherwise skip past (not suspicious)

        is_exec = any(x in a.protect for x in ("RX", "WX", "RWX", "X"))

        if not (is_exec or a.has_mz or a.has_pe):
            continue

        # joins a list together
        # to provide an explination to why something is considered suspicous
        # for example: virtualalloc: exec protect, MZ header

        parts = []

        if is_exec: parts.append("exec protect")

        if a.has_mz: parts.append("MZ header")

        if a.has_pe: parts.append("PE header")

        trigger = "virtualalloc: " + ", ".join(parts)

        regions.append({"address": a.base, "size": _REGION_SAMPLE_BYTES, "trigger": trigger})

        # caps the regions here
        # done to stop overflood in the home console

        if len(regions) >= max_samples:
            break

    if not regions:

        return []

    # sends all addresses back to c++
    # single batch
    # more efficient than calling once per region

    batch = [{"address": r["address"], "size": r["size"]} for r in regions]

    # SCAN 2
    # the earlier scan (get_virutal_allcos) only returned metadata about the regions
    # this is getting sent back to the c++ collector to return the actual raw bytes

    raw_list = memory_scanner.get_memory_samples(pid, batch)

    # parser for the private memorysample dataclass
    # below an object is being created of that dataclass

    # numbers are produced up to how many results there are in raw_list
    # each number is then looped and it collects the raw bytes from c++ at the position
    # the trigger is simply the position string, always matching the raw result position

    results = []

    for i in range(len(raw_list)):

        sample = _parse_sample(raw_list[i], regions[i]["trigger"], pid)
        results.append(sample)

    return results

# ---------------------------------------------------------------------------
# 2. ThreadInfo triggers
#    Capture bytes around the start address of threads that begin in
#    private executable memory (in_private_exec = True).  The window is
#    centred on the start address so we see the instructions that will
#    execute first and any preamble placed by the injector.
# ---------------------------------------------------------------------------

def sample_threads(pid: int, threads: list) -> list:

    """
    Given the output of get_thread_info(), return MemorySample objects for
    threads starting in private executable memory.
    """

    regions = []

    # same applies

    for t in threads:

        if not t.in_private_exec or not t.start_address:
            continue

        # centre the window on the start address

        # does not read from start of region like sample_vritual_allocs
        # instead it samples the window around the thread start
        # 256 before, 256 after (bytes)

        # this is done to see the insturctions before the thread started and after
        # can be used to see what started a thread

        half = _THREAD_CONTEXT_BYTES # 256 before

        if t.start_address > half:

            start = t.start_address - half

        else:

            start = 0

        size  = half * 2 # 512 total

        # appends the suspicious threads and their informatio to the list

        regions.append({
            "address": start,
            "size": size,
            "trigger": f"thread {t.tid}: start in private exec @ {hex(t.start_address)}",
        })

    # if the list is empty, there are no suspicous regions, end

    if not regions:

        return []

    batch = []

    # for every risky thread, loop appened to the list called batch and their details

    for r in regions:
        batch.append({"address": r["address"], "size": r["size"]})

    # this list is sent back to the c++ to collect and return
    # to find the details of the risky threads

    raw_list = memory_scanner.get_memory_samples(pid, batch)

    results = []

    # this loops through every result returned by the c++ about the risky threads
    # each result is parsed and an object instance is created
    # results are appeend to the list and returned

    for i in range(len(raw_list)):

        sample = _parse_sample(raw_list[i], regions[i]["trigger"], pid)
        results.append(sample)

    return results

# ---------------------------------------------------------------------------
# 3. RemoteThread triggers
#    Same as ThreadInfo but for newly created threads detected during the
#    observation window.
# ---------------------------------------------------------------------------

def sample_remote_threads(pid: int, threads: list) -> list:

    """
    Given the output of get_remote_threads(), sample bytes around the start
    address of threads that started in private exec or were created remotely.
    """

    regions = []

    # same applies

    for t in threads:

        # must be in private executeable OR thread is remote
        # wider condition than sample thread

        if not (t.in_private_exec or t.remote) or not t.start_address:
            continue

        half = _THREAD_CONTEXT_BYTES

        if t.start_address > half:

            start = t.start_address - half

        else:

            start = 0

        parts = []

        # will append creator pid and private executeable is applicable

        if t.remote: 

            parts.append(f"creator={t.creator_pid}")

        if t.in_private_exec: 

            parts.append("private exec")

        # builds the result here that is readable
        # something like: remote thread 5678 (creator=1234, private exec) @ 0x1a2b

        regions.append({
            "address": start,
            "size": half * 2,
            "trigger": f"remote thread {t.tid} ({', '.join(parts)}) @ {hex(t.start_address)}",
        })

    if not regions:

        return []

    batch = []

    # same applies

    for r in regions:

        batch.append({"address": r["address"], "size": r["size"]})

        raw_list = memory_scanner.get_memory_samples(pid, batch)

    results = []

    for i in range(len(raw_list)):
        sample = _parse_sample(raw_list[i], regions[i]["trigger"], pid)
        results.append(sample)

    return results

# ---------------------------------------------------------------------------
# 4. MappedModule triggers
#    Sample the first 4 KB of image regions that are absent from the Win32
#    module list or PEB LDR, or have no file backing.  The MZ/PE header
#    bytes reveal the export table, rich header, compiler, and import
#    information of the hidden module.
# ---------------------------------------------------------------------------

def sample_mapped_modules(pid: int, modules: list) -> list:

    """
    Given the output of get_mapped_modules(), sample the first 4 KB of each
    anomalous image region.
    """

    regions = []

    # no if condition here
    # this is because the sampilng happened earlier already in get_mapped_modules()

    for m in modules:

        parts = []

        if m.not_in_win32_list:           parts.append("!Win32List")
        if m.not_in_ldr and m.ldr_available: parts.append("!PEB-LDR")
        if m.no_file_backing:             parts.append("no file backing")

        # same applies here
        # similar output as before
        # for example: mapped module @ 0x1a2b: !Win32List, !PEB-LDR, no file backing

        regions.append({
            "address": m.base,
            "size":    _REGION_SAMPLE_BYTES,
            "trigger": f"mapped module @ {hex(m.base)}: {', '.join(parts)}",
        })

    if not regions:

        return []

    batch = []

    # same applies

    for r in regions:

        batch.append({"address": r["address"], "size": r["size"]})

    raw_list = memory_scanner.get_memory_samples(pid, batch)

    results = []

    for i in range(len(raw_list)):

        sample = _parse_sample(raw_list[i], regions[i]["trigger"], pid)
        results.append(sample)

    return results

# ---------------------------------------------------------------------------
# 5. WriteEvent triggers
#    Re-read 512 bytes of a region whose content changed between the two
#    write-detect snapshots.  The WriteEvent already stores a 64-byte hex
#    before/after diff; this wider read gives the full surrounding context
#    at scan-completion time for offline PE/shellcode analysis.
# ---------------------------------------------------------------------------

def sample_write_events(pid: int, events: list, context_bytes: int = 512) -> list:

    """
    Given the output of get_write_detect(), re-read `context_bytes` starting
    at each changed region's base address (current state after the write).
    """

    regions = []

    # no if condition either
    # get_write_detect already returned regions that changed

    for e in events:

        # e.writer_pids: list of pids stored in the write event object
        # every process that had a PROCCSS_VM_WRITE will be in this list because they could have attacked
        # this list of pids is simply converted to a string list for further analysis

        if e.writer_pids:

            writers_str = str(e.writer_pids) # convers the list to string format here

        else:

            writers_str = "unknown writer"

        # min() here to focus on either context_bytes or _REGION_SAMPLE_BYTES
        # this is done because it never reads more than 512 bytes focusing on the changed area

        regions.append({
            "address": e.base,
            "size": min(context_bytes, _REGION_SAMPLE_BYTES),
            "trigger": f"write-detect change @ {hex(e.base)} writers={writers_str}",
        })

    if not regions:

        return []

    batch = []

    # same applies

    for r in regions:

        batch.append({"address": r["address"], "size": r["size"]})

    raw_list = memory_scanner.get_memory_samples(pid, batch)

    results = []

    for i in range(len(raw_list)):

        sample = _parse_sample(raw_list[i], regions[i]["trigger"], pid)
        results.append(sample)

    return results

# ---------------------------------------------------------------------------
# Combined trigger dispatcher
# ---------------------------------------------------------------------------
# Every parameter here is defaul to none
# This means the function accepts what is ready, is something has no result, the function skips

def collect_memory_samples(pid: int, allocs: list = None, threads: list = None, remote_threads: list = None, mapped_modules: list = None, write_events: list = None) -> list:

    """
    Convenience wrapper: call all applicable trigger functions and return
    the combined list of MemorySample objects.

    Pass only the outputs that are available; None inputs are skipped.
    """

    samples: list = []

    # extend is used here to avoid the list becoming a nests of list
    # instead it adds all the results from the previous functions and extends into this new list
    # to create a flat list of sample results

    if allocs:

        samples.extend(sample_virtual_allocs(pid, allocs))

    if threads:

        samples.extend(sample_threads(pid, threads))

    if remote_threads:

        samples.extend(sample_remote_threads(pid, remote_threads))

    if mapped_modules:

        samples.extend(sample_mapped_modules(pid, mapped_modules))

    if write_events:

        samples.extend(sample_write_events(pid, write_events))

    return samples

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# conversion function
# memory sample hex conversion to base64 string
# base64 = from raw bytes to printable ASCII

def sample_to_base64(sample: "MemorySample") -> str:

    """Convert a MemorySample's hex data to a base64 string."""

    # if sample failed reach, exit without crash

    if not sample.data_hex or not sample.read_ok:

        return ""

    # 3 steps
    # 1. convert hex string to raw bytes
    # 2. encode these bytes as base64
    # 3. convert to readable string

    raw_bytes = bytes.fromhex(sample.data_hex)
    base64_bytes = base64.b64encode(raw_bytes)
    ascii_string = base64_bytes.decode("ascii")

    # base 64 is choosen due to its flexibility, ascii strings can be stored in csv, passed to llm, ml etc

    return ascii_string

# produces hex dump
# takes each raw address, splits into 16 bytes, then produces HEX and ASCII as result

def _hex_dump_lines(data: bytes, base_addr: int) -> list:

    """
    Classic hex dump: 16 bytes per row, address | hex | ASCII.
    Returns a list of formatted strings (no newlines).
    """

    lines = []

    # processes 16 bytes of data at a time

    for off in range(0, len(data), 16):

        chunk = data[off:off + 16]

        # calculate address by adding base + offset

        addr_str = f"{base_addr + off:016x}"

        hex_parts = []

        # chunk is the whole 16 bytes of raw data from current offset

        # this part loops over each chunk of data and adds it to the list
        # it takes each chunk and loops over 1 single byte
        # each byte is then formatted to a hex and added to the list

        for b in chunk:

            hex_parts.append(f"{b:02x}") # 02x means format to hex

        hex_part = " ".join(hex_parts)

        hex_part = f"{hex_part:<47}" # padding 

        ascii_parts = []

        # same applies as above
        # loops through each byte of data from chunk
        
        # 0x20 / 0x7f = space / delete
        
        # everything between these is a printable ascii character
        # everything else can be a letter that is not printable so its replaced with a .

        for b in chunk:

            if 0x20 <= b < 0x7f:

                ascii_parts.append(chr(b))

            else:

                ascii_parts.append(".")

        # runs the result in a readable string
        # for eaxmple MZ.....HI.....

        ascii_part = "".join(ascii_parts)

        lines.append(f"  {addr_str}  {hex_part}  {ascii_part}")

    return lines

# ---------------------------------------------------------------------------
# print_memory_samples
# ---------------------------------------------------------------------------

# in this function both hex and bytes are needed
# the orignal dataclass instance already stores the hex as a string in the objects in MemorySample
# both hex and raw bytes are needed in the program as they are used for different things

# for example below hex is converted to raw bytes to find malware signatures

def print_memory_samples(samples: list, show_hex_dump: bool = True, hex_dump_limit: int = 256):

    """
    Print a summary table then, optionally, a classic hex dump for each
    successfully read MemorySample.

    Parameters
    ----------
    samples        : list of MemorySample
    show_hex_dump  : if True, print the hex dump under each entry
    hex_dump_limit : max bytes to hex-dump per sample (capped at 256 by
                     default to keep console output readable; set to 4096
                     to see the full dump)
    """

    # same applies

    print(f"\nMemory samples  ({len(samples)} captured)")

    if not samples:

        print("  No samples collected (no triggering regions found).")
        return

    # count for successful / failed

    ok = [s for s in samples if s.read_ok]
    failed = [s for s in samples if not s.read_ok]

    print(f"  Successful reads : {len(ok)}")
    print(f"  Failed reads     : {len(failed)}")

    if failed:

        print()
        print("  Failed reads:")

        # print which ones failed and their address

        for s in failed:

            print(f"    {hex(s.address):<18} err=0x{s.error_code:08X}  [{s.trigger}]")

    if not ok:

        return

    print()
    print(f"  {'Address':<18} {'Bytes':>5}  {'B64 (first 32 chars)':<34}  Trigger")
    print("  " + "-" * 90)

    # call to the converter function
    # returns base 64 string

    for s in ok:

        b64 = sample_to_base64(s)
        
        # print out the results
        # successful sample, address, bytes read, first 32 characters of base64 and the trigger
        # keeps the home console clean

        if len(b64) > 32:
             b64_preview = b64[:32] + ".."
        else:
            b64_preview = b64

        print(f"  {hex(s.address):<18} {s.size_read:>5}  {b64_preview:<34}  {s.trigger}")

        # if empty exit here

    if not show_hex_dump:

        return

    # convert hex string back to raw bytes
    # limit to 256 bytes for readable output

    dump_limit = min(hex_dump_limit, _REGION_SAMPLE_BYTES)

    for s in ok:

        if not s.data_hex:

            continue

        raw_bytes = bytes.fromhex(s.data_hex) # converts here
        to_show = raw_bytes[:dump_limit] # displays here with the dump limit

        print()
        print(f"  -- {s.trigger} --")
        print(f"  address={hex(s.address)}  read={s.size_read}B"
              f"  showing first {len(to_show)}B")

        # detects sample against known signatures by reading first bytes
        # first bytes show details in memory coding and may reveal info like mz headers, jump instructions etc

        # detect MZ header

        if len(to_show) >= 2 and to_show[0] == 0x4D and to_show[1] == 0x5A:

            print("  [MZ] DOS header detected - likely a PE image")

        # detect common shellcode starters

        if len(to_show) >= 2:

            # x64 push rbp / mov rbp, rsp prologue

            if to_show[0] == 0x55 and to_show[1] == 0x48:

                print("  [ASM] Possible x64 function prologue (push rbp)")

            # relative jmp / call

            elif to_show[0] in (0xE8, 0xE9):

                print("  [ASM] Starts with CALL/JMP rel32")

            # mov eax, N (syscall stub)

            elif to_show[0] == 0xB8:

                print("  [ASM] Starts with MOV EAX (possible syscall stub)")

        # dump the actual hex here

        for line in _hex_dump_lines(to_show, s.address):

            print(line)

        print(f"  base64: {sample_to_base64(s)[:80]}"
              + ("..." if len(sample_to_base64(s)) > 80 else ""))

# ---------------------------------------------------------------------------
# Performance & system metrics  (I.)
# ---------------------------------------------------------------------------

# standard parser as before
# same applies

def parse_perf_snapshot(raw: dict) -> "PerfSnapshot":

    return PerfSnapshot(
        pid = raw.get("pid",              0),
        cpu_percent = float(raw.get("cpu_percent", 0.0)),
        working_set_kb = int(raw.get("working_set_kb",   0)),
        private_bytes_kb = int(raw.get("private_bytes_kb", 0)),
        peak_ws_kb = int(raw.get("peak_ws_kb",       0)),
        page_faults = int(raw.get("page_faults",      0)),
        io_read_bytes = int(raw.get("io_read_bytes",    0)),
        io_write_bytes = int(raw.get("io_write_bytes",   0)),
        io_read_ops = int(raw.get("io_read_ops",      0)),
        io_write_ops = int(raw.get("io_write_ops",     0)),
        io_other_bytes = int(raw.get("io_other_bytes",   0)),
        io_other_ops = int(raw.get("io_other_ops",     0)),
        handle_count = int(raw.get("handle_count",     0)),
        thread_count = int(raw.get("thread_count",     0)),
        sample_ok = bool(raw.get("sample_ok",       False)),
        scan_ts_us = int(raw.get("scan_ts_us",       0)),
        trace_id = str(raw.get("trace_id",         "")),
    )

# below are standard wrappers to fill in the parser and create dataclass object
# same applies

def get_perf_snapshot(pid: int, delay_ms: int = 1000) -> "PerfSnapshot":

    """
    Measure CPU%, memory, and I/O metrics for a single process over delay_ms ms.
    The window should match the other timed scans so metrics are comparable.
    """

    raw = memory_scanner.get_perf_snapshot(pid, delay_ms)

    return parse_perf_snapshot(raw)

def get_perf_samples(pids: list, delay_ms: int = 1000) -> list:

    """
    Batch version: snapshot all PIDs with one shared sleep.
    Returns a list of PerfSnapshot in the same order as pids.
    Efficient for populating the process table.
    """

    raw_list = memory_scanner.get_perf_samples(pids, delay_ms)

    results = []

    for r in raw_list:

        snapshot = parse_perf_snapshot(r)
        results.append(snapshot)

    return results

# turns a byte count into a readable string

def _fmt_bytes(n: int) -> str:

    """Format a byte count as a human-readable string (B / KB / MB / GB)."""

    if n < 1024:

        return f"{n} B" # less than 1kb show byte

    if n < 1024 ** 2:

        return f"{n / 1024:.1f} KB" # less than 1mb, show as kb

    if n < 1024 ** 3:

        return f"{n / 1024**2:.1f} MB" # less than 1gb, show as mb

    return f"{n / 1024**3:.2f} GB" # if bigger show as gb

# printer function
# returns peformance back to the console

def print_perf_snapshot(pid: int, name: str, delay_ms: int = 1000):

    """
    Run a performance snapshot and print results for a process.
    """

    snap = get_perf_snapshot(pid, delay_ms)

    print(f"\nPerformance metrics for {name} (PID {pid})")
    print(f"  Observation window : {delay_ms} ms")

    if snap.scan_ts_us:

        print(f"  Scan time          : {ts_us_to_iso(snap.scan_ts_us)}")
        print(f"  Trace ID           : {snap.trace_id}")

    if not snap.sample_ok:

        print("  Could not sample process (access denied or process exited).")
        return

    # CPU bar (40 chars wide, each char = 2.5%)
    # for example: CPU%  :  50.00%  [####################--------------------]

    bar_width = 40

    pct_capped = min(snap.cpu_percent, 100.0)
    filled = int(pct_capped / 100.0 * bar_width)
    bar = "#" * filled + "-" * (bar_width - filled)

    print(f"\n  CPU%          : {snap.cpu_percent:6.2f}%  [{bar}]")

    # Memory

    ws_mb  = snap.working_set_kb / 1024
    prv_mb = snap.private_bytes_kb / 1024
    pk_mb  = snap.peak_ws_kb / 1024

    print(f"\n  Working set   : {ws_mb:8.1f} MB")
    print(f"  Private bytes : {prv_mb:8.1f} MB")
    print(f"  Peak WS       : {pk_mb:8.1f} MB")
    print(f"  Page faults   : {snap.page_faults:,}")

    # I/O

    print(f"\n  I/O reads     : {_fmt_bytes(snap.io_read_bytes)}"
          f"  ({snap.io_read_ops:,} ops)")

    print(f"  I/O writes    : {_fmt_bytes(snap.io_write_bytes)}"
          f"  ({snap.io_write_ops:,} ops)")

    if snap.io_other_bytes:

        print(f"  I/O other     : {_fmt_bytes(snap.io_other_bytes)}"
              f"  ({snap.io_other_ops:,} ops)")

    # Misc

    print(f"\n  Handles       : {snap.handle_count}")
    print(f"  Threads       : {snap.thread_count}")