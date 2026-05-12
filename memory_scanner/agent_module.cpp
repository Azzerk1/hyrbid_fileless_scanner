#include <pybind11/pybind11.h> // python module, allows communication
#include <Windows.h> // windows API
#include <TlHelp32.h> // process snapshots
#include <Psapi.h> // process modules
#include <stdio.h>

// most of the below are dataclasses like in python
// vector list, unordered_map is a dictonary

#include <vector>
#include <unordered_map> // protectChangeScan snapshot
#include <set> // findWriterPids dedup
#include <array>
#include <cmath>
#include <algorithm>
#include <string>

namespace py = pybind11;

// ---------------------------------------------------------------------------
// Shannon entropy
// ---------------------------------------------------------------------------
// measures randomness in the byte sequence
// high randomess means encrpytion or compression

double shannon_entropy(const unsigned char* data, size_t len)

{
    if (len == 0) return 0.0; // check if size is emtpy

    // there are 256 possible bytes
    // this creates an arry of the 256 counters then loops through the byte sequence
    // and increments the counter for that byte value

    std::array<size_t, 256> counts{};

    for (size_t i = 0; i < len; i++) {
        counts[data[i]]++;
    }

    // execute only if a byte appeared more than once
    // p becomes probability of a byte

    // for example, in the total sequnce of bytes, if A appears twice in a 4 byte sequence, probability becomes 0.5
    // to work out probability, multiplication is used because it is faster than dividing in terms of CPU execution
    // this avoids multiplying each time

    double entropy = 0.0;
    const double inv_len = 1.0 / static_cast<double>(len); // computes length from total

    for (size_t c : counts) {

        if (c == 0) continue;

        double p = static_cast<double>(c) * inv_len; // probability computed here

        // probability is then applied with log2 for each byte and their probability
        // this result gets stored in entropy, which is the sum of all bytes probability

        // log2 is used beacuse it provides entropy in bits
        // using any other log would still work but the scales would be different

        entropy -= p * std::log2(p);
    }

    return entropy;
}

// ---------------------------------------------------------------------------
// Extract filename from full path
// ---------------------------------------------------------------------------
// small function for utility
// takes a full path and returns just the program at the end
// for example notepad.exe

std::string file_name(const std::wstring& full_path)
{
    DWORD position = full_path.find_last_of(L"\\/"); // search for last \/ etc

    // if \ found, exeute next

    if (position != std::wstring::npos)

    {
        // take everything from the last slash
        // conver to regular string

        std::wstring name = full_path.substr(position + 1);
        return std::string(name.begin(), name.end());
    }

    // if no slash found, then file is already filename

    return std::string(full_path.begin(), full_path.end());
}

// ---------------------------------------------------------------------------
// Integrity level from token
// ---------------------------------------------------------------------------
// read the integrity level and return human readable string

std::string integirty_level(HANDLE h_token)

{
    // two step pattern
    // sends a request to windows which fails to find the required size

    DWORD size = 0;
    GetTokenInformation(h_token, TokenIntegrityLevel, nullptr, 0, &size); // gets token information

    if (size == 0) return "unknown";

    // second call
    // creates the call with the required buffer from first call
    // retrives the integirty level from a handle process

    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(h_token, TokenIntegrityLevel, buffer.data(), size, &size))
        return "unknown";

    // extracts the RID from the integrity level function
    // RID can be converted to a known integirty level

    auto* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data()); // treat the bytes as a token mandatory label structures

    DWORD rid = *GetSidSubAuthority( // then extract the RID bytes from that structure
        label->Label.Sid, // last secrutiy indentifier isnide the structure, which is the rid
        *GetSidSubAuthorityCount(label->Label.Sid) - 1
    );

    // converts the RID number to an integrity level

    if (rid < SECURITY_MANDATORY_MEDIUM_RID) return "low";
    if (rid < SECURITY_MANDATORY_HIGH_RID) return "medium";
    if (rid < SECURITY_MANDATORY_SYSTEM_RID) return "high";

    return "system";
}

// ---------------------------------------------------------------------------
// Elevation check from token
// ---------------------------------------------------------------------------
// same as above but simpler
// check if process is running admin
// no two call pattern beacuse token elevation is a fixed structure
// the buffer size is known upfront

bool elevated_level(HANDLE h_token)
{
    TOKEN_ELEVATION elevation;

    DWORD size = sizeof(elevation);

    if (!GetTokenInformation(h_token, TokenElevation, &elevation, size, &size))
        return false;

    return elevation.TokenIsElevated != 0; // non zero is elevated, zero means not elevated, this is converted to a boolean here
}

// ---------------------------------------------------------------------------
// Token privilege enumeration
// ---------------------------------------------------------------------------
// returns what privileges a process token has and whether enabled
// uses the same two call pattern

py::list token_enumeration(HANDLE h_token)
{
    py::list out;
    DWORD size = 0;

    // send call, fail, find size, step 1

    GetTokenInformation(h_token, TokenPrivileges, nullptr, 0, &size);
    if (size == 0) return out;

    // send call, collect the information, step 2

    std::vector<BYTE> buffer(size);

    if (!GetTokenInformation(h_token, TokenPrivileges, buffer.data(), size, &size))
        return out;

    // cast data to token data structure
    // the data structure holds how many entires follow, array of PRIVILEGES

    // the array holds an ID for the privilege and attributes which says if enabled or disabled

    auto* tp = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.data());

    for (DWORD i = 0; i < tp->PrivilegeCount; i++)

    {

        // for each privilage, loop through and collectoe the LUID (luid holds the ID and attribute)

        LUID luid = tp->Privileges[i].Luid;
        DWORD attrs = tp->Privileges[i].Attributes;
        WCHAR name[256];
        DWORD name_len = 256;

        // convert the LUID to human readable

        if (LookupPrivilegeNameW(nullptr, &luid, name, &name_len))

        {

            // each privilege becomes a small dict
            // this later returns the data as what privilages are used and what is enabled etc

            py::dict priv;
            priv["name"] = std::string(name, name + name_len);
            priv["enabled"] = (attrs & SE_PRIVILEGE_ENABLED) != 0;
            out.append(priv);
        }
    }

    return out;

}

// ---------------------------------------------------------------------------
// PE header detection
// ---------------------------------------------------------------------------
// check if memory is a Windows .exe or .dll file
// using PE MZ
// stores whether the headers are present or not

struct pe_header_info {

    bool has_mz = false;
    bool has_pe = false;

};
// takes in data which is memory from a process in bytes
// size carries the size of that byte block
pe_header_info detect_pe_header(const unsigned char* data, size_t len)

{
    pe_header_info info{};

    if (len < 64) return info; // if size is less than 64, return headers are false

    // checks the first two bytes to see if MZ is present

    if (data[0] == 'M' && data[1] == 'Z') {

        info.has_mz = true; // turns MZ header to true
        uint32_t e_lfanew = *reinterpret_cast<const uint32_t*>(data + 0x3C); // uses a data structure to locate the PE header at a location where it would be present

        if (e_lfanew + 4 <= len) { // must be in the memory sample, not outside

            // looks for bytes that spell out PE 00, which is the real signature

            if (data[e_lfanew] == 'P' &&
                data[e_lfanew + 1] == 'E' &&
                data[e_lfanew + 2] == 0 &&
                data[e_lfanew + 3] == 0)
            {
                info.has_pe = true;
            }
        }
    }

    return info;
}

// ---------------------------------------------------------------------------
// Protection flags -> readable string
// ---------------------------------------------------------------------------
// fix implemented: added missing PAGE_WRITECOPY / PAGE_EXECUTE_WRITECOPY cases
// each memory has a permission such as read / write etc
// the function takes a protection value and converts to human readable

std::string convert_protect(DWORD protect)

{
    switch (protect & 0xff)

    {

    case PAGE_READONLY: return "R";
    case PAGE_READWRITE: return "RW";
    case PAGE_WRITECOPY: return "WC";
    case PAGE_EXECUTE: return "X";
    case PAGE_EXECUTE_READ: return "RX";
    case PAGE_EXECUTE_READWRITE: return "RWX";
    case PAGE_EXECUTE_WRITECOPY: return "RWC";
    case PAGE_NOACCESS: return "N/A";

    default: return "Unknown";

    }
}

// ---------------------------------------------------------------------------
// state -> readable string
// ---------------------------------------------------------------------------
// each memory has a constraint
// this constrait is converted for readability

std::string convert_state(DWORD state)

{
    if (state == MEM_COMMIT) return "Commit";
    if (state == MEM_RESERVE) return "Reserve";
    if (state == MEM_FREE) return "Free";

    return "Unknown";
}

// ---------------------------------------------------------------------------
// memory type -> readable string
// ---------------------------------------------------------------------------
// each memory has a type
// this type is converted to human readable for readability 

std::string convert_type(DWORD type)

{
    if (type == MEM_IMAGE) 
        return "Image";
    if (type == MEM_MAPPED)
        return "Mapped";
    if (type == MEM_PRIVATE) 
        return "Private";

    return "Unknown";
}

// ---------------------------------------------------------------------------
// can a page be read without faulting?
// ---------------------------------------------------------------------------
// checks whether a memory type is safe for scanner to read
// takes memory protection value for a region
// if no protection cannot be read

bool can_read_protect(DWORD protect)

{
    if (protect == 0)
        return false;

    if (protect & PAGE_GUARD)
        return false;

    DWORD p = protect & 0xff; // keeps the main protect and remove extra flags

    switch (p) {

    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:

        return true;

    default:

        return false;

    }
}

// ---------------------------------------------------------------------------
// module enumeration for one process handle
// ---------------------------------------------------------------------------
// lists loaded modules inside one process
// a module is usually an exe or dll file

py::list module_enumeration(HANDLE h_process) // pybind module, returns a python list to python
{
    py::list modules;

    // space for up to 1024 handels
    // and storage for how many bytes required

    HMODULE h_mods[1024];
    DWORD cb_needed = 0;

    // requests all modules loaded in a process from handle

    if (!EnumProcessModulesEx(h_process, h_mods, sizeof(h_mods), &cb_needed, LIST_MODULES_ALL))
        return modules;

    // converts to a number of loaded modules
    // for example, if each hmodule is 8bytes, and windows needed 80 bytes
    // it would calculate 10 modules

    DWORD count = cb_needed / sizeof(HMODULE);

    // loop through each module

    for (DWORD i = 0; i < count; i++) {

        // create storage for each module information
        // and store data like base address, module size etc

        MODULEINFO mi{};
        WCHAR module_path[MAX_PATH] = L"";
        WCHAR mapped_path[MAX_PATH] = L"";

        // request information for current module, skip if failed

        if (!GetModuleInformation(h_process, h_mods[i], &mi, sizeof(mi)))
            continue;
        GetModuleFileNameExW(h_process, h_mods[i], module_path, MAX_PATH); // get module path

        bool file_backed = GetMappedFileNameW(h_process, mi.lpBaseOfDll, mapped_path, MAX_PATH) != 0; // check for backing by file

        // creates a python dict for each module
        // dump the collected data into the dict

        py::dict mod;

        mod["base"] = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
        mod["size"] = static_cast<uint64_t>(mi.SizeOfImage);
        mod["path"] = std::string(module_path, module_path + wcslen(module_path));
        mod["file_backed"] = file_backed;
        modules.append(mod);
    }

    return modules;
}

// ---------------------------------------------------------------------------
// memory region enumeration + entropy + PE detection
// ---------------------------------------------------------------------------
// scan target process memory layout and return a list of memory regions

py::list memory_regions(HANDLE h_process)

{
    py::list regions;

    // store information about 1 region (mbi), start at address 0 which is start of address space, and max read is 4096 bytes from each region

    MEMORY_BASIC_INFORMATION mbi{};

    uintptr_t address = 0;

    constexpr SIZE_T sample_max = 4096;
    // walk through the process memory region by region
    while (VirtualQueryEx(

        h_process,
        reinterpret_cast<LPCVOID>(address),
        &mbi,
        sizeof(mbi)) == sizeof(mbi))
    {

        // each loop provides information about the region

        py::dict region;

        region["base"] = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        region["size"] = static_cast<uint64_t>(mbi.RegionSize);
        region["state"] = convert_state(mbi.State);
        region["protect"] = convert_protect(mbi.Protect);
        region["type"] = convert_type(mbi.Type);
        WCHAR mapped_path[MAX_PATH] = L"";

        // checks whether the current region is linked to a file on disk

        if (GetMappedFileNameW(h_process, mbi.BaseAddress, mapped_path, MAX_PATH))
            region["mapped_file"] = std::string(mapped_path, mapped_path + wcslen(mapped_path));

        else

            region["mapped_file"] = "";

        // these set the default values before reading memory incase anything fails or the region is missing any specific data

        double entropy = -1.0;
        uint64_t sample_size = 0;
        bool read_ok = false;
        bool has_mz = false;
        bool has_pe = false;

        // check for region reading
        // only read if memory is commited and protection allows reading

        if (mbi.State == MEM_COMMIT && can_read_protect(mbi.Protect)) {

            // decides how many bytes to read, reading the smaller value betrween region size and 4096 bytes

            SIZE_T to_read = std::min<SIZE_T>(mbi.RegionSize, sample_max);

            std::vector<unsigned char> sample(to_read);

            SIZE_T bytes_read = 0;

            // read bytes from the target process using the buffer

            if (ReadProcessMemory(h_process, mbi.BaseAddress, sample.data(), to_read, &bytes_read) && bytes_read > 0) // if successful, process the bytes

                // record the reading work

            {
                read_ok = true;
                sample_size = static_cast<uint64_t>(bytes_read);
                entropy = shannon_entropy(sample.data(), bytes_read);
                pe_header_info pe_info = detect_pe_header(sample.data(), bytes_read);
                has_mz = pe_info.has_mz;
                has_pe = pe_info.has_pe;
            }
        }

        // calculate entropy using the previous functions
        // calculate the header results

        region["entropy"] = entropy;
        region["entropy_sample_size"] = sample_size;
        region["entropy_read"] = read_ok;
        region["has_mz"] = has_mz;
        region["has_pe"] = has_pe;

        // add result to the region dict

        regions.append(region);

        // next memory region

        address += mbi.RegionSize;

        if (address == 0) 
            break; // overflow guard
    }

    return regions;
}

// ---------------------------------------------------------------------------
// helper: open a pid and fill a dictionary with token / path / time info
// does not enumerate modules or memory (fast path for listing)
// returns an empty dict on total failure
// ---------------------------------------------------------------------------
// build a python dict for a process
// used by listProcesses() and scanProcess()

py::dict build_process_dict(DWORD pid, bool include_modules_and_memory) // bool decides for a simple scan or advanced with regions

{
    py::dict d;

    // vars for process path and name
    std::wstring path_wide;
    std::string  path_utf8;
    std::string  name_utf8;
    // fix: zero initialise so values are never garbage if GetProcessTimes fails

    FILETIME ft_creation{}, ft_exit{}, ft_kernel{}, ft_user{};

    // open the windows target process
    // use permissions only for reading and not writing

    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    // if successful, h process is valid

    if (h_process)
    {
        WCHAR buffer[MAX_PATH];
        DWORD size = MAX_PATH;

        if (QueryFullProcessImageNameW(h_process, 0, buffer, &size)) // full executable path C:\Windows\System32\notepad.exe

        {
            // filename extraction
            // from C:\Windows\System32\notepad.exe to notepad.exe

            path_wide.assign(buffer, size);
            path_utf8 = std::string(path_wide.begin(), path_wide.end());
            name_utf8 = file_name(path_wide);
        }

        else

        {
            path_utf8 = "<access denied>";
            name_utf8 = "<access denied>"; // fix: was left empty before
        }

        GetProcessTimes(h_process, &ft_creation, &ft_exit, &ft_kernel, &ft_user);

        // if it fails the zero initialised values are safe defaults
        d["pid"] = (int)pid;
        d["path"] = path_utf8;
        d["name"] = name_utf8;
        d["creation"] = (uint64_t(ft_creation.dwHighDateTime) << 32) | ft_creation.dwLowDateTime;
        d["kernel"] = (uint64_t(ft_kernel.dwHighDateTime) << 32) | ft_kernel.dwLowDateTime;
        d["user"] = (uint64_t(ft_user.dwHighDateTime) << 32) | ft_user.dwLowDateTime;

        HANDLE h_token = nullptr;

        // open process token which contains integrity level, admin and privelages

        if (OpenProcessToken(h_process, TOKEN_QUERY, &h_token))

        {
            d["integrity"] = integirty_level(h_token);
            d["elevated"] = elevated_level(h_token);
            d["privileges"] = token_enumeration(h_token);
            CloseHandle(h_token);
        }

        else

        { // fallback
            d["integrity"] = "unknown";
            d["elevated"] = false;
            d["privileges"] = py::list();
        }
        if (include_modules_and_memory) // if true, add loaded modules and memory regions

        {
            d["modules"] = module_enumeration(h_process);
            d["memory_regions"] = memory_regions(h_process);
        }

        else

        { // otherwise empty list
            d["modules"] = py::list();
            d["memory_regions"] = py::list();
        }
        CloseHandle(h_process);
    }

    else

    {
        // minimal fallback when we cant open the process at all

        d["pid"] = (int)pid;
        d["path"] = "<access denied>";
        d["name"] = "<access denied>";
        d["creation"] = (uint64_t)0;
        d["kernel"] = (uint64_t)0;
        d["user"] = (uint64_t)0;
        d["integrity"] = "unknown";
        d["elevated"] = false;
        d["privileges"] = py::list();
        d["modules"] = py::list();
        d["memory_regions"] = py::list();
    }

    return d;
}

// ---------------------------------------------------------------------------
// list_processes()
// fast enumeration of all running processes, no module memory scanning.
// used to populate the process table in the GUI.
// ---------------------------------------------------------------------------
// used for GUI enumeration, its quick

py::list list_processes()
{
    py::list out;
    DWORD pids[4096]; // store process PIDs here
    DWORD bytes = 0;

    if (!EnumProcesses(pids, sizeof(pids), &bytes)) // ask Windows for all running process Pids
        return out;

    DWORD count = bytes / sizeof(DWORD); // convert number of bytes into process IDs
    // loop through each ID and get the process ID

    for (DWORD i = 0; i < count; i++)

    {
        DWORD pid = pids[i];
        if (pid == 0) continue; // skip System idle Process
        py::dict d = build_process_dict(pid, false); // lightweight no memory scan, build dict
        out.append(d);

    }

    return out;
}

// ---------------------------------------------------------------------------
// scan_process(pid)
// full deep scan of a single process: modules + memory regions + entropy.
// called when the user selects a process in the GUI and clicks Scan.
// ---------------------------------------------------------------------------
// full scan, it includes everything

py::dict scan_process(int pid)
{
    return build_process_dict(static_cast<DWORD>(pid), true); // feeds the earlier function with true booleans for a deep scan
}

// ---------------------------------------------------------------------------
// virtualAllocScan(hProcess)
//
// identifies regions that are characteristic of VirtualAllocEx allocations:
//   - MEM_PRIVATE (not file-backed, not a mapped section)
//   - MEM_COMMIT (pages are actually allocated, not just reserved)
//   - No mapped file backing
//
// these are the exact conditions produced by VirtualAllocEx / VirtualAlloc.
//
// ror each region it also reads up to 4 KB so we can report entropy, MZ/PE
// presence.
// ---------------------------------------------------------------------------
// this entire block of code looks for memory regions that were created with VirtualAlloc / VirtualAllocEx
// it finds private memory areas inside a process, which are executeable or contain suspiocus bytes
// fileless malware often is in private commited memory
// protection turned to human-readable for the alloc table (same logic, kept local)

static std::string alloc_protect_str(DWORD protect)
{
    std::string base = convert_protect(protect); // protections become R, RX, RW etc
    // catch guard / no-cache modifiers, and add extra labels if needed

    if (protect & PAGE_GUARD) base += "+G";
    if (protect & PAGE_NOCACHE) base += "+NC";
    if (protect & PAGE_WRITECOMBINE) base += "+WC";
    return base;
}

// is this protection executable in any form?
// return true for any of the conditions below

static bool is_executable(DWORD protect)
{
    DWORD p = protect & 0xff;

    return (p == PAGE_EXECUTE ||

        p == PAGE_EXECUTE_READ ||
        p == PAGE_EXECUTE_READWRITE ||
        p == PAGE_EXECUTE_WRITECOPY);
}

// this is the main scan that returns a python dict of suspicous and private allocation regions

py::list virtual_alloc_scan(HANDLE h_process)
{
    py::list allocs;

    // same applies

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t address = 0;
    constexpr SIZE_T sample_max = 4096;

    // loops through target memory
    // each call asks windows what region exists at this address

    while (VirtualQueryEx(

        h_process,
        reinterpret_cast<LPCVOID>(address),
        &mbi,
        sizeof(mbi)) == sizeof(mbi))
    {

        // only care about private committed pages with no file backing
        // filters the scan

        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
        {
            // confirm there is no mapped file (stack/heap has none, but checking keeps results clean)

            WCHAR mapped_path[MAX_PATH] = L"";

            // if no file backing, its more interesting for detection 

            bool has_backing = GetMappedFileNameW(h_process, mbi.BaseAddress, mapped_path, MAX_PATH) != 0;
            if (!has_backing)

            {
                double entropy = -1.0;
                uint64_t sample_size = 0;
                bool read_ok = false;
                bool has_mz = false;
                bool has_pe = false;

                // only read memory if safe to read

                if (can_read_protect(mbi.Protect)) {

                    // read whichever is smaller like before, same applies

                    SIZE_T to_read = std::min<SIZE_T>(mbi.RegionSize, sample_max);
                    std::vector<unsigned char> sample(to_read);
                    SIZE_T bytes_read = 0;
                    // is executed successfully, it records same size, entropy, peheaderinfo etc

                    if (ReadProcessMemory(h_process, mbi.BaseAddress,sample.data(), to_read, &bytes_read) && bytes_read > 0)

                    {
                        read_ok = true;
                        sample_size = static_cast<uint64_t>(bytes_read);
                        entropy = shannon_entropy(sample.data(), bytes_read);
                        pe_header_info pe_info = detect_pe_header(sample.data(), bytes_read);
                        has_mz = pe_info.has_mz;
                        has_pe = pe_info.has_pe;
                    }
                }

                // build the python result
                // each suspicous and private allocation becomes a python dict

                py::dict alloc;
                alloc["base"] = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                alloc["size"] = static_cast<uint64_t>(mbi.RegionSize);
                alloc["protect"] = alloc_protect_str(mbi.Protect);
                alloc["protect_raw"] = static_cast<uint32_t>(mbi.Protect);
                alloc["entropy"] = entropy;
                alloc["entropy_sample_size"] = sample_size;
                alloc["entropy_read"] = read_ok;
                alloc["has_mz"] = has_mz;
                alloc["has_pe"] = has_pe;
                allocs.append(alloc);
            }
        }

        // next memory region
        address += mbi.RegionSize;
        if (address == 0) break; // overflow guard
    }

    return allocs;
}

// ---------------------------------------------------------------------------
// Timestamp and correlation ID helpers
//
// nowUs()
//   returns microseconds since the Unix epoch (1970-01-01 00:00:00 UTC).
//   Uses GetSystemTimeAsFileTime which has ~100ns resolution on modern
//   Windows. 
//	 convert the 100ns FILETIME ticks to microseconds.
//   the Unix epoch offset from the Windows FILETIME epoch
//   (1601-01-01) is 11644473600 seconds = 116444736000000000 ticks.
//
// makeTraceId(pid, ts_us)
//   produces a deterministic string {pid}-{ts_us} that 
//   identifies one invocation of a scan function.  all event dicts
//   emitted by the same call share this ID so the Python rule engine
//   can group them without any additional bookkeeping.
// ---------------------------------------------------------------------------
// this block creares timesstamps and trace IDs, and exposes virutalAllocScan as a python function
// returns current time in microseconds

static uint64_t now_us()
{
    FILETIME ft; // get windows time
    GetSystemTimeAsFileTime(&ft);
    uint64_t ticks = (uint64_t(ft.dwHighDateTime) << 32) | ft.dwLowDateTime; // windows time starts at 1601, unix is from 1970, the number is the difference between the starting points
    const uint64_t epoch_diff_ticks = 116444736000000000ULL;

    return (ticks - epoch_diff_ticks) / 10;  // /10: 100ns ticks -> microseconds
}

// make a unique id for a scan

static std::string make_trace_id(int pid, uint64_t ts_us)
{
    // "{pid}-{ts_us}", e.g. "1234-1711234567890123"

    return std::to_string(pid) + "-" + std::to_string(ts_us); // combines the process id scan and the time
    // later it can allows the rule engine to group events by time
}

// ---------------------------------------------------------------------------
// get_virtual_allocs(pid)
// public entry point - opens the process and runs virtualAllocScan.
// ---------------------------------------------------------------------------
// function which python can call
// it creates scan_ts and trade_id

py::list get_virtual_allocs(int pid)
{
    py::list empty;
    uint64_t scan_ts = now_us();
    std::string trace_id = make_trace_id(pid, scan_ts);

    // open target process and read process memory

    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));

    if (!h_process) // saftey for if the process cannot be open
        return empty;

    py::list result = virtual_alloc_scan(h_process); // runs the virtualAllocScan from the previous block

    CloseHandle(h_process); // close when finished

    // stamp every event with scan timestamp and trace id
    Py_ssize_t n = PyList_Size(result.ptr()); // get number of result items

    // for every result, add the extra fields to the result, which is when the csan started, what event was observed, and the ID for this scan

    for (Py_ssize_t i = 0; i < n; i++)

    {
        PyObject* item = PyList_GetItem(result.ptr(), i);
        PyDict_SetItemString(item, "scan_ts_us", PyLong_FromUnsignedLongLong(scan_ts));
        PyDict_SetItemString(item, "event_ts_us", PyLong_FromUnsignedLongLong(scan_ts));
        PyDict_SetItemString(item, "trace_id", PyUnicode_FromString(trace_id.c_str()));
    }

    // return final list to python

    return result;
}

// ---------------------------------------------------------------------------
// protectChangeScan(hProcess, delayMs)
//
// Detects VirtualProtect / mprotect activity by taking two memory snapshots
// separated by a short sleep and diffing the protection flags
//
// a protection change means something called VirtualProtect on that region
// between the two samples. The most dangerous transition for fileless malware
// detection is RW -> RX / RWX 
//
// Each result contains:
//   base - region start address
//   size - region size in bytes
//   protect_old - protection string from snapshot 1
//   protect_new - protection string from snapshot 2
//   protect_raw_old / protect_raw_new - raw DWORD values
//   gained_exec - true if new flags are executable but old ones were not
//   lost_write - true if write permission was removed (RW -> RX pattern)
//   gained_exec - true when protection gained execute permission
// ---------------------------------------------------------------------------
// these functions detect process memory change permsisions during the observation time
// snapshot: map from base address to raw protection DWORD
// example: 0x10000000 -> PAGE_READWRITE

using protect_map = std::unordered_map<uintptr_t, DWORD>;

// this function takes a snapshot of the process memory permissions

static protect_map snapshot_protections(HANDLE h_process)
{
    protect_map snap;
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t address = 0;

    // it loops memory and records each committed region
    while (VirtualQueryEx(

        h_process,
        reinterpret_cast<LPCVOID>(address),
        &mbi,
        sizeof(mbi)) == sizeof(mbi))

    {
        // only track committed pages - free/reserved have no meaningful protect
        if (mbi.State == MEM_COMMIT)
            snap[reinterpret_cast<uintptr_t>(mbi.BaseAddress)] = mbi.Protect;
        address += mbi.RegionSize;

        if (address == 0) 
            break;

    }

    return snap;
}

// this function is the detector
// returns a python list of memory regions where protection has changed

py::list protect_change_scan(HANDLE h_process, int delay_ms)
{
    py::list changes;

    // --- snapshot 1 ---

    protect_map before = snapshot_protections(h_process);

    // --- wait ---

    Sleep(static_cast<DWORD>(delay_ms));

    // --- snapshot 2 ---

    protect_map after = snapshot_protections(h_process);

    // --- difference: find addresses present in both where protection changed ---

    // this fucntion loops through the first snapshot
    // it checks for the same base address and whether it still exsits in the second snapshot

    for (protect_map::iterator pit = before.begin(); pit != before.end(); ++pit)

    {
        uintptr_t base = pit->first;
        DWORD old_protect = pit->second;
        auto it = after.find(base);

        if (it == after.end()) continue;// region unmapped between samples

        DWORD new_protect = it->second;

        if (old_protect == new_protect) continue; // no change
        // a check for whether a region was executeable before and after
		
        bool was_exec = is_executable(old_protect);
        bool now_exec = is_executable(new_protect);
		
        // was write allowed before?
        DWORD op = old_protect & 0xff;

        bool had_write = (op == PAGE_READWRITE ||op == PAGE_WRITECOPY || op == PAGE_EXECUTE_READWRITE || op == PAGE_EXECUTE_WRITECOPY); 
        DWORD np = new_protect & 0xff;

        bool has_write = (np == PAGE_READWRITE || np == PAGE_WRITECOPY || np == PAGE_EXECUTE_READWRITE || np == PAGE_EXECUTE_WRITECOPY);

        bool gained_exec = (!was_exec && now_exec);
        bool lost_write = (had_write && !has_write);

        py::dict change; // build the result dict for python

        change["base"] = static_cast<uint64_t>(base);
        change["protect_old"] = alloc_protect_str(old_protect);
        change["protect_new"] = alloc_protect_str(new_protect);
        change["protect_raw_old"] = static_cast<uint32_t>(old_protect);
        change["protect_raw_new"] = static_cast<uint32_t>(new_protect);
        change["gained_exec"] = gained_exec;
        change["lost_write"] = lost_write;
        changes.append(change);
    }
	
    return changes;
}

// ---------------------------------------------------------------------------
// get_protect_changes(pid, delay_ms)
// public entry point: opens the process and runs protectChangeScan.
// delay_ms controls the window between snapshots (default 500ms).
// ---------------------------------------------------------------------------
// this is the function that python can execute
// it creates a timestamp and id, open target process, run protectchangescan(), add timesamp fields to each result, return list to python

py::list get_protect_changes(int pid, int delay_ms)

{
    // create a fallback list, record when scan started and create unique trace ID

    py::list empty;
    uint64_t scan_ts = now_us();
    std::string trace_id = make_trace_id(pid, scan_ts);

    // open target process with permission to ready memory

    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));

    if (!h_process)
        return empty;

    // execute the snapshot protection change scan and close handle

    py::list result = protect_change_scan(h_process, delay_ms);

    CloseHandle(h_process);

    // event_ts_us is the time AFTER the sleep (when the change was observed)

    uint64_t event_ts = now_us();

    // add the data to every result

    Py_ssize_t n = PyList_Size(result.ptr());

    for (Py_ssize_t i = 0; i < n; i++)

    {
        PyObject* item = PyList_GetItem(result.ptr(), i);
        PyDict_SetItemString(item, "scan_ts_us", PyLong_FromUnsignedLongLong(scan_ts));
        PyDict_SetItemString(item, "event_ts_us", PyLong_FromUnsignedLongLong(event_ts));
        PyDict_SetItemString(item, "trace_id", PyUnicode_FromString(trace_id.c_str()));
    }

    return result; // return back
}

// ---------------------------------------------------------------------------
// WriteProcessMemory detection
//
// Detects cross-process memory writes by:
//   1. Sampling the first WRITE_SAMPLE bytes of every private committed region
//   2. Sleeping for delayMs
//   3. Re sampling the same regions
//   4. Reporting any region whose content changed
//
// writer PID identification uses NtQuerySystemInformation(SystemHandleInformation)
// to enumerate all open handles on the system, finds handles held by other processes
// that point to the target PID and carry PROCESS_VM_WRITE access.
// These are the writers. 
//
// each result dict contains:
//   base - region base address
//   size - region size in bytes
//   protect - protection string 
//   protect_raw - raw protection DWORD
//   sample_before - hex of first WRITE_SAMPLE bytes before sleep
//   sample_after - hex of first WRITE_SAMPLE bytes after sleep
//   writer_pids - list of PIDs holding PROCESS_VM_WRITE handles to target
// ---------------------------------------------------------------------------
// only 64 bytes read

#define write_sample 64 // bytes sampled per region for content comparison

// NtQuerySystemInformation typedefs (not always in SDK headers)

#define system_handle_information_class 16
#define status_info_length_mismatch 0xC0000004L

// windows status return type

typedef LONG ntstatus_t;

// defines shape of NtQuerySystemInformation
// tells windows what the fucntion looks like

typedef ntstatus_t(NTAPI* pfn_nt_query_sys_info)(
    ULONG system_information_class,
    PVOID system_information,
    ULONG system_information_length,
    PULONG return_length
    );

// handle table entry returned by NtQuerySystemInformation class 16
// this matters because it will show if another process has write access to the target

#pragma pack(push, 1)
typedef struct {

    ULONG owner_pid;
    BYTE object_type;
    BYTE handle_flags;
    USHORT handle_value;
    PVOID object_pointer;
    ULONG access_mask;

} sys_handle_entry;
#pragma pack(pop)
// shows the full hanldelist returned by windows
typedef struct {

    ULONG handle_count;
    sys_handle_entry handles[1];

} sys_handle_info;

// content snapshot: base address{region_size, protect, sample_bytes}
// stores snaopshot of one mmeory region keeping the above

struct region_sample {
    SIZE_T region_size;
    DWORD  protect;
    std::vector<BYTE> sample;
};

using content_map = std::unordered_map<uintptr_t, region_sample>; // creates a map (dict) for base address and region size

// byte buffer to lowercase hex string

static std::string to_hex(const std::vector<BYTE>& v)

{
    static const char* digits = "0123456789abcdef";

    std::string out;
    out.reserve(v.size() * 2);

    for (BYTE b : v) {
        out += digits[b >> 4];
        out += digits[b & 0xf];
    }

    return out;
}

// take a lightweight content snapshot of all private committed regions
// samples the first 64 byres for each matching region
// used for catching the before and after states
// returns a dict of the base and the bytes
// this information is later used to compare the before and after

static content_map snapshot_content(HANDLE h_process)

{
    // empty snapshot dict, windows structure that stores information about a region, and pointer to start from the start of address space

    content_map snap;
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t address = 0;
    // open process and retrive the required information
    while (VirtualQueryEx(h_process,reinterpret_cast<LPCVOID>(address),&mbi,sizeof(mbi)) == sizeof(mbi))
    {

        // main memory permission is extracted her
        // each loop is about a single region PAGE_EXECUTE_READ for example

        DWORD base_protect = mbi.Protect & 0xff;
        // sample region for all of these that are true
        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE &&
            base_protect != PAGE_NOACCESS && // in no access avoid
            !(mbi.Protect & PAGE_GUARD)) // guard pages for secrutiy etc avoid
        {

            // every region that was true,
            // create a sample of this region
            // region size, memory protection, byres read from region etc

            region_sample rs;
            rs.region_size = mbi.RegionSize;
            rs.protect = mbi.Protect;
            rs.sample.resize(write_sample, 0);
            SIZE_T to_read = min((SIZE_T)write_sample, mbi.RegionSize);
            SIZE_T bytes_read = 0;

            if (!ReadProcessMemory(
                h_process, mbi.BaseAddress,
                rs.sample.data(), to_read, &bytes_read))
                bytes_read = 0;

            rs.sample.resize(bytes_read);
            // store the region in the snapshot map
            // the key is the memory region base address 
            snap[reinterpret_cast<uintptr_t>(mbi.BaseAddress)] = std::move(rs);
        }
        address += mbi.RegionSize; // move next
        if (address == 0) 
            break;
    }

    return snap; // return completed snapshot
}
// enumerate PIDs of all processes that hold a PROCESS_VM_WRITE handle to the given target PID.  Returns an empty list on any failure
// this function returns a list of PIDs that have write handles to the target
// uses ntdll to enumerate every system handle and filter by access mask
static std::vector<DWORD> find_writer_pids(DWORD target_pid)
{
    std::vector<DWORD> writers;

    // load ntdll dynamically to access NtQuerySystemInformation
    // not always exposed in SDK headers so we resolve it at runtime

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) 
        return writers;

    auto nt_qsi = reinterpret_cast<pfn_nt_query_sys_info>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!nt_qsi) 
        return writers;

    // Grow the buffer until the call succeeds
    // keep doubling the buffer until the system returns success
    // 0xC0000004 means buffer was too small

    ULONG buf_size = 0x20000;
    std::vector<BYTE> buf;
    ntstatus_t status;

    do {
        buf_size *= 2;
        buf.resize(buf_size);
        status = nt_qsi(
            system_handle_information_class,
            buf.data(), buf_size, nullptr);
    } 

    while (status == (ntstatus_t)status_info_length_mismatch);

    if (status != 0) return writers;

    // cast the raw buffer to a system handle info structure
    // this gives access to handle count and the handle array

    auto* info = reinterpret_cast<sys_handle_info*>(buf.data());
    HANDLE our_process = GetCurrentProcess();
    DWORD  our_pid = GetCurrentProcessId();
    std::set<DWORD> seen; // dedup writers so the same PID isnt added twice

    // loop through every handle in the system

    for (ULONG i = 0; i < info->handle_count; i++)
    {
        sys_handle_entry& entry = info->handles[i];

        // the target opening itself isnt interesting, and our scanner shouldnt flag itself

        if (entry.owner_pid == target_pid) 
            continue;
        if (entry.owner_pid == our_pid) 
            continue;

        // must carry write permission
        // only PROCESS_VM_WRITE handles can do WriteProcessMemory

        if (!(entry.access_mask & PROCESS_VM_WRITE))
            continue;

        // already reported this owner

        if (seen.count(entry.owner_pid)) 
            continue;

        // open the owning process so it can duplicate its handle
        // PROCESS_DUP_HANDLE is the minimum right needed to copy a handle

        HANDLE h_owner = OpenProcess(
            PROCESS_DUP_HANDLE, FALSE, entry.owner_pid);
        if (!h_owner) 
            continue;

        // duplicate into process with minimal rights so we can call GetProcessId
        // duplicating the handle lets us inspect what process it actually points to

        HANDLE h_dup = nullptr;

        BOOL ok = DuplicateHandle(

            h_owner,
            reinterpret_cast<HANDLE>(static_cast<uintptr_t>(entry.handle_value)),
            our_process,
            &h_dup,
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            0);

        CloseHandle(h_owner);
        if (!ok || !h_dup) 
            continue;

        // extract the PID this handle actually points to
        // if it matches the target, the owner is a confirmed writer

        DWORD pid = GetProcessId(h_dup);
        CloseHandle(h_dup);

        if (pid == target_pid)

        {
            seen.insert(entry.owner_pid);
            writers.push_back(entry.owner_pid);
        }
    }

    return writers;
}

//  write detection: diff two content snapshots, then identify writer PIDs
// this is the main scan that detects WriteProcessMemory activity
// same snapshot pattern as before, snapshot 1 sleep snapshot 2 diff

static py::list write_detect_scan(HANDLE h_process, DWORD target_pid, int delay_ms)
{
    py::list results;

    // snapshot 1
    // capture first 64 bytes of every private committed region

    content_map before = snapshot_content(h_process);

    // wait
    // give time for any write activity to happen

    Sleep(static_cast<DWORD>(delay_ms));

    // snapshot 2
    // take the same snapshot again to compare

    content_map after = snapshot_content(h_process);

    // find writer PIDs once in whole process
    // the writer info is the same for every region detected, so only collect it once

    std::vector<DWORD> writer_pids = find_writer_pids(target_pid);

    // build pybind list of writer pids for the dict
    // convert c++ vector to python list so it can be attached to each result

    py::list py_writers;

    for (DWORD wp : writer_pids)
        py_writers.append(static_cast<int>(wp));

    // Diff
    // compare each region from snapshot 1 against snapshot 2
    // any region whose bytes changed is a write event

    for (content_map::iterator cit = before.begin(); cit != before.end(); ++cit)

    {
        uintptr_t base = cit->first;
        region_sample& brs = cit->second;
        auto it = after.find(base);

        if (it == after.end()) continue; // region disappeared

        region_sample& ars = it->second;

        // skip if sample length changed (region was remapped) or content identical
        // only emit when the actual byte content is different

        if (brs.sample == ars.sample) continue;

        // build the result dict for python
        // each detected write becomes one entry in the output list

        py::dict ev;
        ev["base"] = static_cast<uint64_t>(base);
        ev["size"] = static_cast<uint64_t>(brs.region_size);
        ev["protect"] = alloc_protect_str(brs.protect);
        ev["protect_raw"] = static_cast<uint32_t>(brs.protect);
        ev["sample_before"] = to_hex(brs.sample);
        ev["sample_after"] = to_hex(ars.sample);
        ev["writer_pids"] = py_writers;
        results.append(ev);
    }

    return results;
}

// ---------------------------------------------------------------------------
// get_write_detect(pid, delay_ms)
// public entry point - opens process and runs write detection scan.
// ---------------------------------------------------------------------------
// python entry point
// same applies, open process, run scan, stamp timestamps, return

py::list get_write_detect(int pid, int delay_ms)

{
    py::list empty;
    uint64_t scan_ts = now_us();
    std::string trace_id = make_trace_id(pid, scan_ts);

    // open target with read access for the snapshot function

    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));

    if (!h_process)
        return empty;

    // run the detection scan and close handle

    py::list result = write_detect_scan(h_process, static_cast<DWORD>(pid), delay_ms);
    CloseHandle(h_process);

    // event_ts_us is the time after the sleep, when the write was observed

    uint64_t event_ts = now_us();

    // add timestamps and trace id to every result entry

    Py_ssize_t n = PyList_Size(result.ptr());

    for (Py_ssize_t i = 0; i < n; i++)
    {
        PyObject* item = PyList_GetItem(result.ptr(), i);
        PyDict_SetItemString(item, "scan_ts_us", PyLong_FromUnsignedLongLong(scan_ts));
        PyDict_SetItemString(item, "event_ts_us", PyLong_FromUnsignedLongLong(event_ts));
        PyDict_SetItemString(item, "trace_id", PyUnicode_FromString(trace_id.c_str()));
    }

    return result;
}

// ---------------------------------------------------------------------------
// NT Syscall detection
//
// Three checks:
// 1. Direct Nt*/Zw* imports in non system modules
// 2. SYSCALL/SYSENTER/INT2Eh stubs in executable private memory
// 3. Inline hook detection on key ntdll exports
// ---------------------------------------------------------------------------
// this block detects suspicious use of NT syscalls
// malware often calls Nt functions directly to bypass user mode hooks
// list of high risk NT functions to watch for
// these are rarely imported by normal code outside system DLLs

static const char* nt_watched[] = {
	
    "NtCreateThreadEx", // remote thread creation rare outside malware
    "NtQueueApcThread", // APC injection rare outside async I/O internals
    "NtWriteVirtualMemory", // cross-process write almost never imported directly
    "NtProtectVirtualMemory", // RW -> RX flip for shellcode staging
    nullptr
};

// converts string to lowercase for comparison

static std::string nt_str_lower(const char* s)
{
    std::string out(s ? s : "");

    for (size_t i = 0; i < out.size(); i++)
        out[i] = static_cast<char>(tolower(static_cast<unsigned char>(out[i])));

    return out;
}

// convert a WCHAR buffer to a lowercase narrow string
// windows uses wide chars, this converts them to regular ascii lowercase

static std::string nt_wide_to_lower(const WCHAR* ws)
{
    char buf[512];
    buf[0] = '\0';
    WideCharToMultiByte(CP_ACP, 0, ws, -1, buf, 511, NULL, NULL);
    return nt_str_lower(buf);
}

// read bytes from target process
// wrapper around ReadProcessMemory that returns bytes read

static size_t nt_read_target(HANDLE h_process, uintptr_t addr, void* buf, size_t len)
{
    SIZE_T got = 0;

    if (!ReadProcessMemory(h_process, reinterpret_cast<LPCVOID>(addr), buf, len, &got))
        return 0;

    return static_cast<size_t>(got);
}

// convert bytes to lowercase hex string
// builds a space separated hex dump for logging context bytes

static std::string nt_bytes_to_hex(const BYTE* p, size_t n)
{
    static const char* d = "0123456789abcdef";

    std::string out;
    out.reserve(n * 3);

    for (size_t i = 0; i < n; i++) {
        if (i) out += ' ';
        out += d[p[i] >> 4];
        out += d[p[i] & 0xf];
    }
    return out;
}

// is this a system DLL to skip?

// system DLLs are expected to import Nt functions, so it skips them
// only non system modules importing Nt functions are weird

static bool nt_is_system_dll(const std::string& lower)
{

    return (lower == "ntdll.dll" ||
        lower == "kernel32.dll" ||
        lower == "kernelbase.dll" ||
        lower == "user32.dll" ||
        lower == "advapi32.dll" ||
        lower == "msvcrt.dll" ||
        lower == "ucrtbase.dll" ||
        lower.find("api-ms-win") != std::string::npos);
}

// is this protect flag executable?
// returns true if any execute bit is set

static bool nt_is_exec(DWORD p)
{
    DWORD b = p & 0xff;

    return (b == PAGE_EXECUTE ||
        b == PAGE_EXECUTE_READ ||
        b == PAGE_EXECUTE_READWRITE ||
        b == PAGE_EXECUTE_WRITECOPY);
}

// ---------------------------------------------------------------------------
// Part 1: direct Nt*/Zw* imports in non system modules
// ---------------------------------------------------------------------------
// this function walks every non system module in the target
// it parses the PE import table and flags any Nt or Zw function imported from ntdll

static py::list nt_scan_imports(HANDLE h_process, DWORD pid)

{
    py::list results;

    // enumerate loaded modules via snapshot
    // CreateToolhelp32Snapshot gives us a module list for the target process

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

    if (snap == INVALID_HANDLE_VALUE) return results;

    // collect non system module bases 
    // loop through every loaded module and keep only non system ones

    MODULEENTRY32W me;
    ZeroMemory(&me, sizeof(me));
    me.dwSize = sizeof(me);

    std::vector<std::pair<std::string, uintptr_t> > mods;

    if (Module32FirstW(snap, &me)) {

        do {
            std::string name = nt_wide_to_lower(me.szModule);

            if (!nt_is_system_dll(name)) {
                uintptr_t base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                mods.push_back(std::make_pair(name, base));
            }

        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);

    // for each non system module, parse its PE headers and walk imports

    for (size_t mi = 0; mi < mods.size(); mi++)

    {
        const std::string& mod_name = mods[mi].first;
        uintptr_t          base = mods[mi].second;

        // read DOS header
        // first part of any PE file, must start with MZ signature

        IMAGE_DOS_HEADER dos;
        ZeroMemory(&dos, sizeof(dos));
		
        if (nt_read_target(h_process, base, &dos, sizeof(dos)) < sizeof(dos)) 
            continue;
		
        if (dos.e_magic != IMAGE_DOS_SIGNATURE) 
            continue;

        // read NT headers
        // e_lfanew points to where the real PE header sits

        BYTE nt_buf[sizeof(IMAGE_NT_HEADERS64)];
        ZeroMemory(nt_buf, sizeof(nt_buf));
        uintptr_t nt_off = base + static_cast<DWORD>(dos.e_lfanew);
		
        if (nt_read_target(h_process, nt_off, nt_buf, sizeof(nt_buf)) < sizeof(nt_buf)) 
            continue;

        // the buffer can be interpreted as 32 or 64 bit headers
        // the magic field tells us which one to use

        IMAGE_NT_HEADERS32* nth32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(nt_buf);
        IMAGE_NT_HEADERS64* nth64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(nt_buf);

        if (nth32->Signature != IMAGE_NT_SIGNATURE) continue;

        bool is64 = (nth32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

        // get the import directory location and size
        // this is where the list of imported DLLs and functions lives

        DWORD import_rva = 0;
        DWORD import_size = 0;

        if (is64) {

            import_rva = nth64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            import_size = nth64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }

        else {

            import_rva = nth32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            import_size = nth32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }

        if (!import_rva || !import_size) 
            continue;

        // read the array of import descriptors
        // each descriptor represents one imported DLL

        size_t num_desc = import_size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        std::vector<IMAGE_IMPORT_DESCRIPTOR> descs(num_desc);
        ZeroMemory(descs.data(), num_desc * sizeof(IMAGE_IMPORT_DESCRIPTOR));

        if (nt_read_target(h_process, base + import_rva, descs.data(), num_desc * sizeof(IMAGE_IMPORT_DESCRIPTOR)) == 0) 
            continue;

        // loop through each import descriptor (each imported DLL)

        for (size_t di = 0; di < num_desc; di++)
        {
            IMAGE_IMPORT_DESCRIPTOR& desc = descs[di];
            if (!desc.Name && !desc.FirstThunk) 
                break;

            // read the name of the DLL being imported from

            char dll_name[128];
            ZeroMemory(dll_name, sizeof(dll_name));
            nt_read_target(h_process, base + desc.Name, dll_name, sizeof(dll_name) - 1);

            // only care about imports from ntdll
            // these are the syscall stubs to flag

            if (nt_str_lower(dll_name) != "ntdll.dll") 
                continue;

            // thunk array contains pointers to function names or ordinals
            // OriginalFirstThunk is preferred because FirstThunk is fallback

            DWORD thunk_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;

            if (!thunk_rva) continue;

            uintptr_t thunk_addr = base + thunk_rva;
            size_t entry_size = is64 ? 8 : 4; // pointer size differs by arch

            // walk the thunk array entry by entry until it hits a null terminator

            for (;;)

            {
                uintptr_t entry = 0;
                if (nt_read_target(h_process, thunk_addr, &entry, entry_size) < entry_size) 
                    break;
                if (!entry) 
                    break;

                // the top bit indicates import by ordinal vs by name

                uintptr_t ord_bit = is64 ? (uintptr_t)IMAGE_ORDINAL_FLAG64
                    : (uintptr_t)IMAGE_ORDINAL_FLAG32;

                if (entry & ord_bit) { thunk_addr += entry_size; 
                continue; }

                // the entry points to a hint and name structure
                // the name starts 2 bytes after the hint

                WORD hint = 0;
                char func_name[128];
                ZeroMemory(func_name, sizeof(func_name));
                uintptr_t ibn_addr = base + (DWORD)(entry & 0x7FFFFFFF);
                nt_read_target(h_process, ibn_addr, &hint, sizeof(hint));
                nt_read_target(h_process, ibn_addr + 2, func_name, sizeof(func_name) - 1);

                // only flag functions starting with Nt or Zw
                // these are direct syscall wrappers, suspicious in non-system code

                if ((func_name[0] == 'N' && func_name[1] == 't') ||
                    (func_name[0] == 'Z' && func_name[1] == 'w'))
                {
                    // check if this function is on the high risk watch list

                    bool watched = false;
                    for (int k = 0; nt_watched[k]; k++) {
                        if (strcmp(func_name, nt_watched[k]) == 0) {
                            watched = true; break;
                        }
                    }

                    // add the hit to the results dict for python

                    py::dict hit;
                    hit["importing_module"] = mod_name;
                    hit["function"] = std::string(func_name);
                    hit["from_dll"] = std::string("ntdll.dll");
                    hit["watched"] = watched;
                    results.append(hit);
                }
                thunk_addr += entry_size;
            }
        }
    }
    return results;
}

// ---------------------------------------------------------------------------
// Part 2: SYSCALL/SYSENTER/INT2Eh stubs in executable private memory
// ---------------------------------------------------------------------------
// scans private executable memory looking for raw syscall opcodes
// fileless malware drops syscall stubs into private RX memory to bypass hooks

static py::list nt_scan_syscall_stubs(HANDLE h_process)
{
    py::list results;

    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));
    uintptr_t address = 0;

    // walk every memory region in the target

    while (VirtualQueryEx(h_process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        // check if region is executable

        DWORD bp = mbi.Protect & 0xff;
        bool exec = (bp == PAGE_EXECUTE ||
            bp == PAGE_EXECUTE_READ ||
            bp == PAGE_EXECUTE_READWRITE ||
            bp == PAGE_EXECUTE_WRITECOPY);

        // only scan private committed executable regions
        // system DLLs are MEM_IMAGE so they get filtered out

        if (mbi.State == MEM_COMMIT &&mbi.Type == MEM_PRIVATE &&exec && !(mbi.Protect & PAGE_GUARD))

        {
            // read region in 64KB chunks to avoid massive allocations

            const SIZE_T chunk = 65536;
            SIZE_T region_left = mbi.RegionSize;
            uintptr_t scan_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);

            while (region_left > 0)

            {
                SIZE_T to_read = (region_left < chunk) ? region_left : chunk;
                std::vector<BYTE> buf(static_cast<size_t>(to_read));
                SIZE_T got = 0;

                if (!ReadProcessMemory(h_process,reinterpret_cast<LPCVOID>(scan_addr),buf.data(), to_read, &got) || got < 2)
                    break;

                // scan the chunk byte by byte for syscall opcodes
                // look for the three patterns that trigger a kernel transition

                for (SIZE_T i = 0; i + 1 < got; i++)

                {
                    const char* op_type = NULL;
                    if (buf[i] == 0x0F && buf[i + 1] == 0x05) op_type = "SYSCALL (0F 05)";
                    else if (buf[i] == 0xCD && buf[i + 1] == 0x2E) op_type = "INT 2Eh (CD 2E)";
                    else if (buf[i] == 0x0F && buf[i + 1] == 0x34) op_type = "SYSENTER (0F 34)";

                    if (op_type)

                    {
                        // capture some context bytes around the match for logging
                        // 4 bytes before and up to 16 total bytes

                        SIZE_T ctx_start = (i >= 4) ? i - 4 : 0;
                        SIZE_T ctx_len = (got - ctx_start < 16) ? got - ctx_start : 16;
                        std::string ctx = nt_bytes_to_hex(
                            buf.data() + static_cast<size_t>(ctx_start),
                            static_cast<size_t>(ctx_len));

                        // build the result dict with the location and the bytes

                        py::dict hit;

                        hit["base"] = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(mbi.BaseAddress));
                        hit["offset"] = static_cast<uint64_t>(scan_addr + i - reinterpret_cast<uintptr_t>(mbi.BaseAddress));
                        hit["address"] = static_cast<uint64_t>(scan_addr + i);
                        hit["opcode"] = std::string(op_type);
                        hit["context"] = ctx;
                        hit["protect"] = alloc_protect_str(mbi.Protect);
                        results.append(hit);
                        i++; // skip the second byte of the opcode pair
                    }
                }

                // advance to next chunk

                scan_addr += got;
                region_left = (got <= region_left) ? (region_left - got) : 0;
            }
        }

        // next memory region

        address += mbi.RegionSize;
        if (address == 0) break;
    }

    return results;
}

// ---------------------------------------------------------------------------
// Part 3: check ntdll export stubs in target for inline hooks
// ---------------------------------------------------------------------------
// classify the first few bytes of an ntdll function
// a clean stub follows a known pattern, anything else is a hook

static std::string nt_classify_hook(const BYTE* b, size_t len)
{
    if (len < 2) return "unknown";

    // clean x64: 4C 8B D1 = mov r10, rcx
    // this is the standard ntdll prologue on 64 bit windows

    if (len >= 3 && b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1) return "clean";

    // clean x86: B8 xx xx xx xx = mov eax, N
    // standard 32 bit ntdll prologue, loads syscall number into eax

    if (b[0] == 0xB8) return "clean";

    // anything below is a hook of some kind
    // the byte informs what kind of jump was used

    if (b[0] == 0xE9) 
        return "JMP rel32";
	
    if (b[0] == 0xEB) 
        return "JMP rel8";
	
    if (b[0] == 0xE8) 
        return "CALL rel32";
	
    if (len >= 2 && b[0] == 0xFF && b[1] == 0x25) 
        return "JMP [rip+off]";
	
    if (len >= 2 && b[0] == 0xFF && b[1] == 0x15) 
        return "CALL [rip+off]";
	
    if (b[0] == 0x68) 
        return "PUSH imm";
	
    if (b[0] == 0x90) 
        return "NOP sled";
	
    if (b[0] == 0xCC) 
        return "INT3";
	
    if (b[0] == 0xC3) 
        return "RET (neutered)";
	

    return "modified";
}

// reads the first few bytes of high risk ntdll exports
// compares them against the known clean pattern to detect hooks

static py::list nt_check_hooks(HANDLE h_process, DWORD pid)

{
    py::list results;

    // find ntdll's base address in the target by walking its module list

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

    if (snap == INVALID_HANDLE_VALUE) 
        return results;

    uintptr_t ntdll_base = 0;
    MODULEENTRY32W me2;
    ZeroMemory(&me2, sizeof(me2));
    me2.dwSize = sizeof(me2);

    if (Module32FirstW(snap, &me2)) {
        do {
            if (nt_wide_to_lower(me2.szModule) == "ntdll.dll") {
                ntdll_base = reinterpret_cast<uintptr_t>(me2.modBaseAddr);
                break;
            }
        } while (Module32NextW(snap, &me2));
    }
    CloseHandle(snap);

    if (!ntdll_base) return results;

    // parse ntdll PE headers, same pattern as Part 1
    // need to find the export directory to locate function names and addresses

    IMAGE_DOS_HEADER dos;

    ZeroMemory(&dos, sizeof(dos));

    if (nt_read_target(h_process, ntdll_base, &dos, sizeof(dos)) < sizeof(dos)) 
        return results;

    if (dos.e_magic != IMAGE_DOS_SIGNATURE) 
        return results;

    BYTE nt_buf[sizeof(IMAGE_NT_HEADERS64)];
    ZeroMemory(nt_buf, sizeof(nt_buf));

    if (nt_read_target(h_process, ntdll_base + dos.e_lfanew, nt_buf, sizeof(nt_buf)) < sizeof(nt_buf)) 
        return results;

    IMAGE_NT_HEADERS32* nth32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(nt_buf);
    IMAGE_NT_HEADERS64* nth64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(nt_buf);

    if (nth32->Signature != IMAGE_NT_SIGNATURE) 
        return results;

    bool is64 = (nth32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    // locate the export directory inside ntdll

    DWORD exp_rva = is64
        ? nth64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        : nth32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (!exp_rva) return results;

    IMAGE_EXPORT_DIRECTORY exp_dir;

    ZeroMemory(&exp_dir, sizeof(exp_dir));

    if (nt_read_target(h_process, ntdll_base + exp_rva, &exp_dir, sizeof(exp_dir)) < sizeof(exp_dir)) 
        return results;

    // the export directory has three parallel arrays
    // function RVAs, name RVAs, and name ordinals that link the two

    std::vector<DWORD> func_rvas(exp_dir.NumberOfFunctions, 0);
    std::vector<DWORD> name_rvas(exp_dir.NumberOfNames, 0);
    std::vector<WORD> name_ords(exp_dir.NumberOfNames, 0);

    nt_read_target(h_process, ntdll_base + exp_dir.AddressOfFunctions, func_rvas.data(), func_rvas.size() * sizeof(DWORD));
    nt_read_target(h_process, ntdll_base + exp_dir.AddressOfNames, name_rvas.data(), name_rvas.size() * sizeof(DWORD));
    nt_read_target(h_process, ntdll_base + exp_dir.AddressOfNameOrdinals, name_ords.data(), name_ords.size() * sizeof(WORD));

    // for each watched function, find its address and check the prologue

    for (int fi = 0; nt_watched[fi]; fi++)

    {
        const char* target = nt_watched[fi];
        uintptr_t func_addr = 0;

        // walk the name array looking for our target function

        for (DWORD ni = 0; ni < exp_dir.NumberOfNames; ni++)

        {
            char ename[128];
            ZeroMemory(ename, sizeof(ename));
            nt_read_target(h_process, ntdll_base + name_rvas[ni], ename, sizeof(ename) - 1);

            if (strcmp(ename, target) == 0) {
                WORD ord = name_ords[ni];

            if (ord < exp_dir.NumberOfFunctions)
                    func_addr = ntdll_base + func_rvas[ord];
                break;
            }
        }
        if (!func_addr) 

            continue;

        // read the first 16 bytes of the function
        // the classifier only needs the first few, but more helps for context

        BYTE stub[16];
        ZeroMemory(stub, sizeof(stub));
        size_t got = nt_read_target(h_process, func_addr, stub, sizeof(stub));
        if (got < 4) 
            continue;

        size_t use_len = got < 8 ? got : 8;
        std::string hook_type = nt_classify_hook(stub, got);
        bool hooked = (hook_type != "clean");

        // build the result entry for this function

        py::dict entry;
        entry["function"] = std::string(target);
        entry["address"] = static_cast<uint64_t>(func_addr);
        entry["hook_type"] = hook_type;
        entry["bytes"] = nt_bytes_to_hex(stub, use_len);
        entry["hooked"] = hooked;
        results.append(entry);
    }

    return results;

}

// ---------------------------------------------------------------------------
// getNtSyscallInfo(pid) - public entry point
// ---------------------------------------------------------------------------
// public entry that runs all three NT syscall checks and combines results
// returns a dict with three sub-lists for imports, stubs, and hooks

py::dict get_nt_syscall_info(int pid)

{
    py::dict result;
    uint64_t scan_ts = now_us();
    std::string trace_id = make_trace_id(pid, scan_ts);

    // open target with read access

    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));

    // if open fails, return empty result with the metadata still attached

    if (!h_process)
    {
        result["direct_nt_imports"] = py::list();
        result["syscall_stubs"] = py::list();
        result["hooked_functions"] = py::list();
        result["scan_ts_us"] = scan_ts;
        result["trace_id"] = trace_id;
        return result;
    }

    // run all three scan passes

    py::list nt_imports = nt_scan_imports(h_process, static_cast<DWORD>(pid));
    py::list stubs = nt_scan_syscall_stubs(h_process);
    py::list hooks = nt_check_hooks(h_process, static_cast<DWORD>(pid));
    CloseHandle(h_process);

    // stamp each sub list item
    // lambda to add scan timestamps and trace id to every item in a lis

    auto stamp_list = [&](py::list& lst) {
        Py_ssize_t n = PyList_Size(lst.ptr());
        for (Py_ssize_t i = 0; i < n; i++)

        {
            PyObject* item = PyList_GetItem(lst.ptr(), i);
            PyDict_SetItemString(item, "scan_ts_us", PyLong_FromUnsignedLongLong(scan_ts));
            PyDict_SetItemString(item, "event_ts_us", PyLong_FromUnsignedLongLong(scan_ts));
            PyDict_SetItemString(item, "trace_id", PyUnicode_FromString(trace_id.c_str()));
        }
        };

    stamp_list(nt_imports);
    stamp_list(stubs);
    stamp_list(hooks);

    // assemble final dict for python

    result["direct_nt_imports"] = nt_imports;
    result["syscall_stubs"] = stubs;
    result["hooked_functions"] = hooks;
    result["scan_ts_us"] = scan_ts;
    result["trace_id"] = trace_id;
    return result;
}

// ---------------------------------------------------------------------------
// thread detection
//
// Two checks:
//
// 1. THREAD START ADDRESS AUDIT  (getThreadInfo)
//
//    enumerate every thread belonging to a PID using CreateToolhelp32Snapshot
//    (TH32CS_SNAPTHREAD). For each thread we call NtQueryInformationThread
//    with class 9 (ThreadQuerySetWin32StartAddress) to recover the Win32 start
//    address that was passed to CreateThread / CreateRemoteThread.
//
//    then walk the target's module list and the VirtualQuery map to classify
//    the start address:
//      - address falls inside a loaded MEM_IMAGE region -> legitimate
//      - address falls in a MEM_PRIVATE executable region -> in_private_exec=True
//        (shellcode, reflectively loaded PE, injected stub)
//      - address cannot be resolved -> unknown
//
//    Each result includes tid, start_address, start_module (basename or ""),
//    in_private_exec (bool).
//
// 2. REMOTE THREAD DETECTOR  (getRemoteThreads)
//
//    takes two snapshots of threads owned by the target PID separated by
//    delay_ms.  any TID present in snapshot 2 but not in snapshot 1 is a
//    NEW thread created during the window.
//
//    for each new thread we then enumerate all system handles looking for
//    processes that hold a handle with THREAD_ALL_ACCESS or that includes
//    THREAD_SET_CONTEXT / SYNCHRONIZE 
//    then duplicate the handle into process, call
//    GetThreadId() on it, and confirm it matches the new TID.  The owning
//    process PID becomes the suspected creator.
//
//    a creator_pid of 0 means no external handle was found (the thread was
//    created by the target process itself). A non-zero creator_pid that
//    differs from the target PID is a remote thread injection event.
// ---------------------------------------------------------------------------
// NtQueryInformationThread typedef (class 9 = ThreadQuerySetWin32StartAddress)
// function signature, resolved at runtime from ntdll

typedef LONG(NTAPI* pfn_nt_query_info_thread)(

    HANDLE thread_handle,
    ULONG  thread_information_class,
    PVOID  thread_information,
    ULONG  thread_information_length,
    PULONG return_length);

// class number for querying win32 start address of a thread

static const ULONG thread_query_set_win32_start_address = 9;

// access mask used by CreateRemoteThread on the new thread
// these are the rights the creator gets back from the API

static const DWORD remote_thread_access =
THREAD_SET_CONTEXT | THREAD_GET_CONTEXT |
THREAD_SUSPEND_RESUME | SYNCHRONIZE;

// ---------------------------------------------------------------------------
// helper: get start address for a thread via NtQueryInformationThread
// returns 0 on failure.
// ---------------------------------------------------------------------------
// retrieves the original entry point a thread was created with
// for a legitimate thread this lives in an image, for injection it lives in private memory

static uintptr_t get_thread_start_address(HANDLE h_thread)

{
    // cache the function pointer on first call to avoid repeated lookups

    static pfn_nt_query_info_thread pfn = NULL;

    if (!pfn)

    {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");

        if (ntdll)
            pfn = reinterpret_cast<pfn_nt_query_info_thread>(GetProcAddress(ntdll, "NtQueryInformationThread"));
    }

    if (!pfn) return 0;

    // ask for the win32 start address using class 9

    uintptr_t start_addr = 0;
    ULONG returned = 0;
    pfn(h_thread, thread_query_set_win32_start_address, &start_addr, sizeof(start_addr), &returned);

    return start_addr;
}

// ---------------------------------------------------------------------------
// helper: build a map of base_address -> {size, type, protect} for target
// used to classify a start address as image / private-exec / other
// ---------------------------------------------------------------------------
// holds the info we need about a memory region to classify it

struct region_info {
	
    SIZE_T size;
    DWORD  type;
    DWORD  protect;
	
};

typedef std::unordered_map<uintptr_t, region_info> region_map;

// walks the target memory and builds a base address -> region info map
// used later to figure out what kind of memory a thread starts in

static region_map build_region_map(HANDLE h_process)

{
    region_map rm;
    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));
    uintptr_t addr = 0;

    // same applies, walk every region with VirtualQueryEx

    while (VirtualQueryEx(h_process,reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi))

    {
        // only keep committed regions, free/reserved have no meaningful data

        if (mbi.State == MEM_COMMIT)

        {
            region_info ri;
            ri.size = mbi.RegionSize;
            ri.type = mbi.Type;
            ri.protect = mbi.Protect;
            rm[reinterpret_cast<uintptr_t>(mbi.BaseAddress)] = ri;
        }

        addr += mbi.RegionSize;
        if (addr == 0) break;
    }

    return rm;
}
// classify a start address: find its enclosing region
// given an address, find the region it falls inside and determine its type

static bool classify_address(const region_map& rm,uintptr_t addr,bool& in_private_exec, bool& in_image)

{
    in_private_exec = false;
    in_image = false;

    // linear search through the region map looking for the containing region

    for (region_map::const_iterator it = rm.begin(); it != rm.end(); ++it)
    {
        uintptr_t base = it->first;
        if (addr >= base && addr < base + it->second.size)

        {
            // region is an image (loaded dll/exe) means thread starts in legit code

            in_image = (it->second.type == MEM_IMAGE);

            // check if region is executable

            DWORD bp = it->second.protect & 0xff;
            bool exec = (bp == PAGE_EXECUTE ||
                bp == PAGE_EXECUTE_READ ||
                bp == PAGE_EXECUTE_READWRITE ||
                bp == PAGE_EXECUTE_WRITECOPY);

            // private exec means not image and executable, strongly suspicious

            in_private_exec = (!in_image && exec);
            return true;
        }
    }

    return false;
}

// ---------------------------------------------------------------------------
// helper: given a set of TIDs, find which external PID created them
// uses system handle enumeration
// ---------------------------------------------------------------------------
// figures out which external process holds a handle to each new thread
// same handle enumeration trick as findWriterPids but for thread handles

static std::unordered_map<DWORD, DWORD> find_thread_creators(const std::set<DWORD>& new_tids, DWORD target_pid)

{
    // tid -> suspected creator pid
    // initialise every new tid with creator 0 (unknown)

    std::unordered_map<DWORD, DWORD> result;

    for (std::set<DWORD>::const_iterator it = new_tids.begin();
        it != new_tids.end(); ++it)
        result[*it] = 0;

    if (new_tids.empty()) return result;

    // load NtQuerySystemInformation dynamically

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    if (!ntdll) return result;

    pfn_nt_query_sys_info pfn_qsi = reinterpret_cast<pfn_nt_query_sys_info>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!pfn_qsi) return result;

    // SystemHandleInformation = 16
    // grow buffer until call succeeds, same applies

    std::vector<BYTE> buf(1 << 20);
    ULONG needed = 0;
    ntstatus_t status;

    do {
        status = pfn_qsi(16, buf.data(),
            static_cast<ULONG>(buf.size()), &needed);
			
        if (status == (ntstatus_t)status_info_length_mismatch)
            buf.resize(buf.size() * 2);
    } 
    while (status == (ntstatus_t)status_info_length_mismatch);

    if (status != 0) return result;

    DWORD our_pid = GetCurrentProcessId();
    auto* info = reinterpret_cast<sys_handle_info*>(buf.data());

    // loop through every handle in the system

    for (ULONG i = 0; i < info->handle_count; i++)
    {
        sys_handle_entry& entry = info->handles[i];

        // skip handles owned by target or ourselves, same applies

        if (entry.owner_pid == target_pid) continue;
        if (entry.owner_pid == our_pid)    continue;

        // must have thread access 
        // SYNCHRONIZE is common to all thread handles, cheap pre filter

        if (!(entry.access_mask & SYNCHRONIZE)) continue;

        // duplicate the handle into the process so it can call GetThreadId

        HANDLE h_owner = OpenProcess(PROCESS_DUP_HANDLE, FALSE, entry.owner_pid);

        if (!h_owner) continue;

        HANDLE h_dup = NULL;
        BOOL ok = DuplicateHandle(h_owner,
            reinterpret_cast<HANDLE>(static_cast<uintptr_t>(entry.handle_value)),GetCurrentProcess(), &h_dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
			
        CloseHandle(h_owner);
        if (!ok || !h_dup) continue;

        // confirm the handle points to one of the new tids
        // if so, mark the owner as the suspected creator

        DWORD tid = GetThreadId(h_dup);
        CloseHandle(h_dup);

        if (tid && new_tids.count(tid))
            result[tid] = entry.owner_pid;
    }
    return result;
}
// ---------------------------------------------------------------------------
// getThreadInfo(pid) - enumerate threads + classify start addresses
// ---------------------------------------------------------------------------
// returns every thread in the target with its start address classified
// classification tells us if the thread starts in legitimate code or private memory

py::list get_thread_info(int pid)
{
    py::list results;
    uint64_t scan_ts = now_us();
    std::string trace_id = make_trace_id(pid, scan_ts);
    DWORD dpid = static_cast<DWORD>(pid);

    // open target for memory queries
    // needed for building the region map

    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dpid);

    region_map rm;

    if (h_process)
        rm = build_region_map(h_process);

    // build module base ranges from snapshot for name lookup
    // module_base -> {size, name}
    // used to map a start address to a module name when its inside an image

    std::vector<std::pair<uintptr_t, std::pair<SIZE_T, std::string> > > mod_ranges;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dpid);

        if (snap != INVALID_HANDLE_VALUE)
			
        {
            MODULEENTRY32W me;
            ZeroMemory(&me, sizeof(me));
            me.dwSize = sizeof(me);

            if (Module32FirstW(snap, &me)) {
				
                do {
                    char narrow[512];
                    narrow[0] = '\0';
                    WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, narrow, 511, NULL, NULL);
					
                    uintptr_t base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
					
                    SIZE_T sz = static_cast<SIZE_T>(me.modBaseSize);
					
                    std::string nm(narrow);
					
                    mod_ranges.push_back(std::make_pair(base, std::make_pair(sz, nm)));
					
                } while (Module32NextW(snap, &me));

            }
            CloseHandle(snap);
        }
    }

    // walk thread snapshot
    // TH32CS_SNAPTHREAD gives every thread system wide, so filter by owner

    HANDLE tsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	
    if (tsnap == INVALID_HANDLE_VALUE)
    {
        if (h_process) CloseHandle(h_process);
        return results;
    }

    THREADENTRY32 te;
    ZeroMemory(&te, sizeof(te));
    te.dwSize = sizeof(te);

    if (Thread32First(tsnap, &te))

    {
        do {
            // skip threads owned by other processes

            if (te.th32OwnerProcessID != dpid) 
                continue;
            DWORD tid = te.th32ThreadID;

            // open the thread and ask for its start address

            uintptr_t start_addr = 0;
            HANDLE h_thread = OpenThread(
                THREAD_QUERY_INFORMATION, FALSE, tid);

            if (h_thread)
            {
                start_addr = get_thread_start_address(h_thread);
                CloseHandle(h_thread);
            }

            // classify start address
            // first try matching against a module range, then fall back to region map

            bool in_priv_exec = false;
            bool in_image = false;
            bool resolved = false;
            std::string mod_name;

            if (start_addr)
            {
                // check module ranges first
                // if the address is inside a loaded module we get its name

                for (size_t mi = 0; mi < mod_ranges.size(); mi++)

                {
                    uintptr_t mbase = mod_ranges[mi].first;
                    SIZE_T    msz = mod_ranges[mi].second.first;
                    if (start_addr >= mbase && start_addr < mbase + msz)

                    {
                        mod_name = mod_ranges[mi].second.second;
                        in_image = true;
                        resolved = true;
                        break;
                    }
                }

                // fall back to the region map for non-module addresses

                if (!resolved)
                    resolved = classify_address(rm, start_addr,
                        in_priv_exec, in_image);
            }

            // build the per-thread result dict

            py::dict d;
            d["tid"] = static_cast<int>(tid);
            d["start_address"] = static_cast<uint64_t>(start_addr);
            d["start_module"] = mod_name;
            d["in_private_exec"] = in_priv_exec;
            d["in_image"] = in_image;
            d["resolved"] = resolved;
            d["scan_ts_us"] = scan_ts;
            d["event_ts_us"] = scan_ts;
            d["trace_id"] = trace_id;
            results.append(d);

        } while (Thread32Next(tsnap, &te));
    }

    CloseHandle(tsnap);
    if (h_process) CloseHandle(h_process);
    return results;
}

// ---------------------------------------------------------------------------
// getRemoteThreads(pid, delay_ms) - detect threads created between two snapshots
// and identify their creator PID
// ---------------------------------------------------------------------------
// detects threads created during the observation window by diffing two thread lists
// any new tid is checked against system handles to find who created it

py::list get_remote_threads(int pid, int delay_ms)

{
    py::list results;
    uint64_t scan_ts = now_us();
    std::string trace_id = make_trace_id(pid, scan_ts);
    DWORD dpid = static_cast<DWORD>(pid);

    // --- snapshot 1 ---
    // collect every tid currently owned by the target

    std::set<DWORD> before;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) 
            return results;

        THREADENTRY32 te;
        ZeroMemory(&te, sizeof(te));
        te.dwSize = sizeof(te);

        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == dpid)
                    before.insert(te.th32ThreadID);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }

    // wait for the window

    Sleep(static_cast<DWORD>(delay_ms));
    uint64_t event_ts = now_us();  // timestamp AFTER sleep = when thread was observed

    // --- Snapshot 2 ---
    // same applies, capture the tid set again

    std::set<DWORD> after;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		
        if (snap == INVALID_HANDLE_VALUE) 
            return results;

        THREADENTRY32 te;
        ZeroMemory(&te, sizeof(te));
        te.dwSize = sizeof(te);

        if (Thread32First(snap, &te)) {
			
            do {
				
                if (te.th32OwnerProcessID == dpid)
					
                    after.insert(te.th32ThreadID);
					
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }

    // --- diff: find new TIDs ---
    // any tid in after but not in before is a thread that started during the window

    std::set<DWORD> new_tids;

    for (std::set<DWORD>::const_iterator it = after.begin();
        it != after.end(); ++it)
    {
        if (!before.count(*it))
            new_tids.insert(*it);
    }

    if (new_tids.empty()) return results;

    // --- get start addresses and identify creators ---
    // open target to build region map for classifying start addresses

    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dpid);

    region_map rm;

    if (h_process) rm = build_region_map(h_process);

    // run handle enumeration to find who created each new thread

    std::unordered_map<DWORD, DWORD> creator_map =
        find_thread_creators(new_tids, dpid);

    // build a result entry per new thread

    for (std::set<DWORD>::const_iterator it = new_tids.begin();
        it != new_tids.end(); ++it)
    {
        DWORD tid = *it;

        // get start address for the thread

        uintptr_t start_addr = 0;
        HANDLE h_thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);

        if (h_thread)

        {
            start_addr = get_thread_start_address(h_thread);
            CloseHandle(h_thread);
        }

        // classify where the start address points

        bool in_priv_exec = false;
        bool in_image = false;

        if (start_addr)
            classify_address(rm, start_addr, in_priv_exec, in_image);

        // look up the suspected creator pid from the map

        DWORD creator_pid = 0;
        {
            std::unordered_map<DWORD, DWORD>::const_iterator ci =
                creator_map.find(tid);

            if (ci != creator_map.end())
                creator_pid = ci->second;
        }

        // remote flag is true if creator is a different non-zero pid

        bool remote = (creator_pid != 0 && creator_pid != dpid);

        // assemble the result dict

        py::dict d;
        d["tid"] = static_cast<int>(tid);
        d["start_address"] = static_cast<uint64_t>(start_addr);
        d["in_private_exec"] = in_priv_exec;
        d["in_image"] = in_image;
        d["creator_pid"] = static_cast<int>(creator_pid);
        d["remote"] = remote;
        d["scan_ts_us"] = scan_ts;
        d["event_ts_us"] = event_ts;
        d["trace_id"] = trace_id;
        results.append(d);
    }
	
    if (h_process) CloseHandle(h_process);
    return results;
}

// ---------------------------------------------------------------------------
// manually mapped module detection
//
// reflective DLL injection and manual mapping load a PE into the target
// without going through the Windows loader.  The result is executable
// MEM_IMAGE regions that are invisible to
// standard enumeration because they are absent from:
//   (1) EnumProcessModulesEx  (the Win32 / Psapi module list)
//   (2) The PEB loader data table (InLoadOrder / InInitOrder / InMemoryOrder)
//   (3) The file-system backing: GetMappedFileNameW returns nothing
//
// This function runs four independent passes and cross-references them:
//
// PASS 1 - VirtualQuery sweep
//   walk every MEM_IMAGE committed region and call GetMappedFileNameW to
//   get its device path (e.g. \Device\HarddiskVolume3\Windows\...).
//   Build a set: image_base -> {device_path, size}.
//
// PASS 2 - EnumProcessModulesEx set
//   call EnumProcessModulesEx(LIST_MODULES_ALL) and collect the base
//   addresses of every module the Win32 API knows about.
//   any image_base from Pass 1 that is absent here is "not in Win32 list".
//
// PASS 3 - PEB LDR walk (all three doubly-linked lists)
//   Read the target PEB via NtQueryInformationProcess class 0.
//   walk InLoadOrderModuleList, InMemoryOrderModuleList,
//   InInitializationOrderModuleList and collect DllBase values.
//   any image_base absent from all three LDR lists is "hidden from loader".
//
// PASS 4 - No-file-backing check
//   any MEM_IMAGE region for which GetMappedFileNameW returns an empty
//   string has no file backing at all - the strongest indicator.
//
// suspicion flags:
//   not_in_win32_list   - absent from EnumProcessModulesEx
//   not_in_ldr          - absent from all three PEB LDR lists
//   no_file_backing     - GetMappedFileNameW returned nothing
//   has_pe_header       - first two bytes of the region are MZ
// ---------------------------------------------------------------------------
// this block detects manually mapped or reflectively loaded modules
// these dont go through the windows loader so they hide from normal enumeration
// NtQueryInformationProcess typedef (class 0 = ProcessBasicInformation)
// used to find the PEB address of the target process

typedef LONG(NTAPI* pfn_nt_qip)(
    HANDLE process_handle,
    ULONG  process_information_class,
    PVOID  process_information,
    ULONG  process_information_length,
    PULONG return_length);

// minimal PEB / LDR structures
// it read these from the target process with ReadProcessMemory.
// All offsets are for 64 bit 32 bit offsets differ but the function
// minimal subset of the structure, it only needs PebBaseAddress

struct mm_pbi {
	
    PVOID  reserved_1;
    PVOID  peb_base_address;
    PVOID  reserved_2[2];
    ULONG_PTR unique_process_id;
    PVOID  reserved_3;
	
};

// PEB offsets it needs (64 bit)
// PEB layout is undocumented but stable, these offsets work on 64 bit windows

static const size_t peb_off_ldr = 0x18; // PEB.Ldr -> PPEB_LDR_DATA

// PEB_LDR_DATA offsets
// these are the heads of the three doubly linked module lists

static const size_t ldr_off_inload = 0x10; // InLoadOrderModuleList.Flink
static const size_t ldr_off_inmem = 0x20; // InMemoryOrderModuleList.Flink
static const size_t ldr_off_ininit = 0x30; // InInitializationOrderModuleList.Flink

// LDR_DATA_TABLE_ENTRY offsets (64-bit)
// offsets within each entry to find the DllBase field

static const size_t ldr_entry_size = 0x120;
static const size_t ldr_entry_dllbase_load = 0x30; // via InLoadOrder
static const size_t ldr_entry_dllbase_mem = 0x20; // via InMemoryOrder (FLINK is +0x10 from entry start in this list, DllBase is still abs)
static const size_t ldr_entry_dllbase_init = 0x20; // via InInitOrder

// helper: read a pointer sized value from target at addr
// simple wrapper used a lot when walking the PEB

static uintptr_t mm_read_ptr(HANDLE h_process, uintptr_t addr)

{
    uintptr_t val = 0;
    SIZE_T got = 0;
    ReadProcessMemory(h_process, reinterpret_cast<LPCVOID>(addr),
        &val, sizeof(val), &got);
    return val;
}

// walk one doubly linked LDR list and collect DllBase values
// listHead is the address of the LIST_ENTRY Flink field
// dllBaseOffFromLink is how many bytes past the LIST_ENTRY's own address
// the DllBase field lives 
// walks one of the three loader lists and collects every DllBase it finds

static void walk_ldr_list(HANDLE h_process,
    uintptr_t list_head_flink,
    uintptr_t list_head_addr,
    size_t dll_base_off_from_entry_start,
    size_t link_off_from_entry_start,
    std::set<uintptr_t>& out)
{
    uintptr_t cur = mm_read_ptr(h_process, list_head_flink); // first flink
	
    if (!cur) 
        return;

    int guard = 1024; // prevent infinite loop on corrupt list

    // walk forward through the list until we loop back or hit the limit

    while (cur && cur != list_head_addr && --guard > 0)

    {
        // cur is the address of the LIST_ENTRY inside the entry struct.
        // entry_start = cur - linkOffFromEntryStart
        // back up to the start of the entry, then read the DllBase field

        uintptr_t entry_start = cur - link_off_from_entry_start;
        uintptr_t dll_base = mm_read_ptr(h_process, entry_start + dll_base_off_from_entry_start);
			
        if (dll_base)
            out.insert(dll_base);

        // advance: read the Flink of the current LIST_ENTRY
        // move to the next entry in the doubly linked list

        cur = mm_read_ptr(h_process, cur);
    }
}

// collect all DllBase values from all three PEB LDR lists
// any module loaded via the official loader will appear in all three lists
// manually mapped modules wont appear in any of them

static std::set<uintptr_t> collect_ldr_bases(HANDLE h_process)

{
    std::set<uintptr_t> bases;

    // resolve NtQueryInformationProcess once and cache it

    static pfn_nt_qip s_pfn_nt_qip = nullptr;

    if (!s_pfn_nt_qip) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");

        if (ntdll)
            s_pfn_nt_qip = reinterpret_cast<pfn_nt_qip>(
                GetProcAddress(ntdll, "NtQueryInformationProcess"));
    }

    if (!s_pfn_nt_qip) return bases;

    // ask for ProcessBasicInformation to get the PEB address

    mm_pbi pbi;
    ZeroMemory(&pbi, sizeof(pbi));
    ULONG ret_len = 0;

    if (s_pfn_nt_qip(h_process, 0, &pbi, sizeof(pbi), &ret_len) != 0)
        return bases;

    uintptr_t peb_addr = reinterpret_cast<uintptr_t>(pbi.peb_base_address);
    if (!peb_addr) return bases;

    // PEB.Ldr
    // follow PEB.Ldr to find the PEB_LDR_DATA structure

    uintptr_t ldr_addr = mm_read_ptr(h_process, peb_addr + peb_off_ldr);
    if (!ldr_addr) return bases;

    // --- InLoadOrderModuleList ---
    // flink of the list head is at ldrAddr + LDR_OFF_INLOAD
    // each LIST_ENTRY is at offset 0x00 from LDR_DATA_TABLE_ENTRY start
    // DllBase is at offset 0x30 from entry start
    // walk the load order list

    {
        uintptr_t head_addr = ldr_addr + ldr_off_inload;
        uintptr_t head_flink = head_addr; // points to itself initially -> first real entry's InLoadOrderLinks
        walk_ldr_list(h_process, head_flink, head_addr,
            0x30, // DllBase from entry start
            0x00, // InLoadOrderLinks offset from entry start
            bases);
    }

    // --- InMemoryOrderModuleList ---
    // LIST_ENTRY embedded at offset 0x10 from entry start
    // DllBase at 0x30 from entry start
    // walk the memory order list

    {
        uintptr_t head_addr = ldr_addr + ldr_off_inmem;
        uintptr_t head_flink = head_addr;
        walk_ldr_list(h_process, head_flink, head_addr,
            0x30, // DllBase
            0x10, // InMemoryOrderLinks from entry start
            bases);
    }

    // --- InInitializationOrderModuleList ---
    // LIST_ENTRY embedded at offset 0x20 from entry start
    // DllBase at 0x30 from entry start
    // walk the initialisation order list

    {
        uintptr_t head_addr = ldr_addr + ldr_off_ininit;
        uintptr_t head_flink = head_addr;
        walk_ldr_list(h_process, head_flink, head_addr,
            0x30, // DllBase
            0x20, // InInitializationOrderLinks from entry start
            bases);
    }
    return bases;
}

// check if two bytes at a region base are MZ
// check whether a region starts with the PE signature

static bool has_mz_header(HANDLE h_process, uintptr_t base)

{
    BYTE buf[2] = { 0, 0 };
    SIZE_T got = 0;
    ReadProcessMemory(h_process, reinterpret_cast<LPCVOID>(base),
        buf, 2, &got);

    return (got == 2 && buf[0] == 'M' && buf[1] == 'Z');
}

// convert device path to a loggable narrow string
// converts the wide device path returned by GetMappedFileNameW

static std::string mm_device_path_to_narrow(const WCHAR* ws)

{
    char buf[1024];
    buf[0] = '\0';
    WideCharToMultiByte(CP_ACP, 0, ws, -1, buf, 1023, NULL, NULL);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// getMappedModules(pid) - public entry point
// ---------------------------------------------------------------------------
// runs all four passes and cross-references them to find hidden modules
// only emits results that have at least one anomaly flag set

py::list get_mapped_modules(int pid)

{
    py::list results;
    uint64_t scan_ts = now_us();
    std::string trace_id = make_trace_id(pid, scan_ts);
    DWORD dpid = static_cast<DWORD>(pid);

    // open target with read access for all the queries

    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dpid);
    if (!h_process) return results;

    // ------------------------------------------------------------------
    // PASS 1: VirtualQuery sweep - collect all MEM_IMAGE committed regions
    // image_base -> {first_region_base, total_size, device_path}
    // group contiguous MEM_IMAGE pages with the same mapped file into
    // one logical entry keyed by the lowest base in the run.
    // ------------------------------------------------------------------
    // pass 1 walks every region looking for image type memory
    // groups by AllocationBase so multiple sections of one DLL combine

    struct image_entry {
        uintptr_t base;
        SIZE_T size;
        std::string device_path;
        bool has_mz;
    };

    // key by the lowest address seen for a given device path / run

    std::unordered_map<uintptr_t, image_entry> image_map;
    {
        MEMORY_BASIC_INFORMATION mbi;
        ZeroMemory(&mbi, sizeof(mbi));
        uintptr_t addr = 0;

        while (VirtualQueryEx(h_process,
            reinterpret_cast<LPCVOID>(addr),
            &mbi, sizeof(mbi)) == sizeof(mbi))
        {
            // only care about committed image type memory

            if (mbi.State == MEM_COMMIT &&
                mbi.Type == MEM_IMAGE)
            {
                uintptr_t base = reinterpret_cast<uintptr_t>(mbi.AllocationBase);

                if (image_map.find(base) == image_map.end())
                {
                    // first time we see this AllocationBase - get path
                    // query device path and check for MZ header

                    WCHAR mapped[2048];
                    ZeroMemory(mapped, sizeof(mapped));
                    GetMappedFileNameW(h_process, mbi.AllocationBase, mapped, 2047);

                    image_entry ie;
                    ie.base = base;
                    ie.size = mbi.RegionSize;
                    ie.device_path = mm_device_path_to_narrow(mapped);
                    ie.has_mz = has_mz_header(h_process, base);
                    image_map[base] = ie;
                }

                else

                {
                    // same allocation seen before, just add to total size

                    image_map[base].size += mbi.RegionSize;
                }
            }
            addr += mbi.RegionSize;
            if (addr == 0) break;
        }
    }

    // ------------------------------------------------------------------
    // PASS 2: EnumProcessModulesEx - Win32 module list bases
    // ------------------------------------------------------------------
    // pass 2 gets the official win32 module list from Psapi
    // any image base missing from this is not visible to standard tools

    std::set<uintptr_t> win32_bases;
    {
        HMODULE h_mods[4096];
        DWORD cb_needed = 0;

        if (EnumProcessModulesEx(h_process, h_mods, sizeof(h_mods),
            &cb_needed, LIST_MODULES_ALL))
        {
            DWORD count = cb_needed / sizeof(HMODULE);

            for (DWORD i = 0; i < count; i++)
                win32_bases.insert(reinterpret_cast<uintptr_t>(h_mods[i]));
        }
    }

    // ------------------------------------------------------------------
    // PASS 3: PEB LDR walk - loader list bases
    // ------------------------------------------------------------------
    // pass 3 walks the PEB loader lists directly
    // anything missing from here was loaded outside the official loader

    std::set<uintptr_t> ldr_bases = collect_ldr_bases(h_process);

    // ------------------------------------------------------------------
    // cross-reference and emit results
    // ------------------------------------------------------------------
    // compare passes against each other and emit any region with anomalies

    for (std::unordered_map<uintptr_t, image_entry>::const_iterator it = image_map.begin(); it != image_map.end(); ++it)

    {
        uintptr_t        base = it->first;
        const image_entry& ie = it->second;

        // check each anomaly indicator

        bool not_in_win32 = (win32_bases.find(base) == win32_bases.end());
        bool not_in_ldr = (ldr_bases.find(base) == ldr_bases.end());
        bool no_file = ie.device_path.empty();

        // if ldrBases is empty (couldnt read PEB: access denied / 32-bit
        // target on 64 bit host) dont raise false positives on notInLdr

        bool ldr_available = !ldr_bases.empty();

        // only emit entries that have at least one anomaly flag set
        // no point reporting normal modules, only flagged ones

        bool any_anomaly = no_file || not_in_win32 || (ldr_available && not_in_ldr);

        if (!any_anomaly) 
			continue;

        // build the result dict for python

        py::dict d;
        d["base"] = static_cast<uint64_t>(base);
        d["size"] = static_cast<uint64_t>(ie.size);
        d["device_path"] = ie.device_path;
        d["has_mz"] = ie.has_mz;
        d["not_in_win32_list"] = not_in_win32;
        d["not_in_ldr"] = ldr_available ? not_in_ldr : false;
        d["ldr_available"] = ldr_available;
        d["no_file_backing"] = no_file;
        d["scan_ts_us"] = scan_ts;
        d["event_ts_us"] = scan_ts;
        d["trace_id"] = trace_id;
        results.append(d);
    }

    CloseHandle(h_process);
    return results;
}

// ---------------------------------------------------------------------------
// handle / open-access audit  (getHandleAudit)
//
// before any injection technique can succeed the attacker must first open
// a handle to the target process with sufficient rights.  Common minimum
// access masks required:
//
//   PROCESS_VM_WRITE | PROCESS_VM_OPERATION WriteProcessMemory
//   PROCESS_CREATE_THREAD CreateRemoteThread
//   PROCESS_VM_READ ReadProcessMemory (recon)
//   PROCESS_SUSPEND_RESUME SuspendThread / NtSuspend
//   PROCESS_DUP_HANDLE handle duplication attacks
//   PROCESS_ALL_ACCESS (0x1FFFFF) full control
//
// it enumerates every handle in the system via NtQuerySystemInformation
// class 16, filter to handles whose resolved
// target PID matches the target, duplicate each one into own process
// to confirm the target, then decode the access mask.
//
// owner name lookup uses a TH32CS_SNAPPROCESS snapshot taken once before
// the loop so the scan does not repeatedly open/close processes.
//
// result fields per entry:
//   owner_pid PID that holds the handle
//   owner_name process basename (best-effort)
//   handle_value raw handle value in the owner process
//   access_mask raw DWORD access mask
//   access_decoded human-readable list of rights (e.g. "VM_WRITE|CREATE_THREAD")
//   has_vm_write PROCESS_VM_WRITE present
//   has_vm_read PROCESS_VM_READ present
//   has_create_thread PROCESS_CREATE_THREAD present
//   has_suspend PROCESS_SUSPEND_RESUME present
//   has_dup_handle PROCESS_DUP_HANDLE present
//   has_all_access full PROCESS_ALL_ACCESS mask present
// ---------------------------------------------------------------------------
// this block lists every external handle open to the target
// the access mask tells us what an attacker could do with that handle
// Dangerous access mask bits we explicitly decode
// each constant maps to a windows API that requires that right

static const DWORD ha_vm_write = PROCESS_VM_WRITE;
static const DWORD ha_vm_read = PROCESS_VM_READ;
static const DWORD ha_vm_op = PROCESS_VM_OPERATION;
static const DWORD ha_create_thread = PROCESS_CREATE_THREAD;
static const DWORD ha_suspend = PROCESS_SUSPEND_RESUME;
static const DWORD ha_dup_handle = PROCESS_DUP_HANDLE;
static const DWORD ha_query_info = PROCESS_QUERY_INFORMATION;
static const DWORD ha_set_info = PROCESS_SET_INFORMATION;
static const DWORD ha_all = PROCESS_ALL_ACCESS;

// decode access mask to a pipe separated string of right names
// turns a raw access mask into a human readable string like VM_WRITE|CREATE_THREAD

static std::string decode_access_mask(DWORD mask)
{
    std::string out;

    // macro to append a label if bit is set
    // keeps the per bit code compact

#define ha_bit(ha_mask_bit, ha_mask_label) \
    if ((mask & (ha_mask_bit)) == (ha_mask_bit)) { \
        if (!out.empty()) out += '|'; \
        out += (ha_mask_label); \
    }

    // check ALL_ACCESS first as a shortcut
    // if all rights are set, no point listing each one

    if ((mask & ha_all) == ha_all)

    {
        out = "ALL_ACCESS";
        return out;
    }

    // check each interesting bit one by one

    ha_bit(ha_vm_write, "VM_WRITE")
        ha_bit(ha_vm_read, "VM_READ")
        ha_bit(ha_vm_op, "VM_OPERATION")
        ha_bit(ha_create_thread, "CREATE_THREAD")
        ha_bit(ha_suspend, "SUSPEND_RESUME")
        ha_bit(ha_dup_handle, "DUP_HANDLE")
        ha_bit(ha_query_info, "QUERY_INFO")
        ha_bit(ha_set_info, "SET_INFO")
#undef ha_bit

        // catch remaining bits not decoded above
        // anything left over gets logged as raw hex

        DWORD known = ha_vm_write | ha_vm_read | ha_vm_op | ha_create_thread | ha_suspend | ha_dup_handle | ha_query_info | ha_set_info;
    DWORD remaining = mask & ~known & 0x0000FFFF; // strip standard rights

    if (remaining)

    {
        char buf[32];
        if (!out.empty()) out += '|';
        sprintf_s(buf, sizeof(buf), "0x%04X", remaining);
        out += buf;
    }

    if (out.empty()) out = "NONE";
    return out;
}

// build a pid -> name map from a process snapshot called once per audit
// avoids opening every process individually to get its name

static std::unordered_map<DWORD, std::string> build_pid_name_map()
{
    std::unordered_map<DWORD, std::string> m;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snap == INVALID_HANDLE_VALUE) return m;

    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    // walk every process and record its pid and exe name

    if (Process32FirstW(snap, &pe)) {
		
        do {
			
            char narrow[512];
            narrow[0] = '\0';
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, narrow, 511, NULL, NULL);
			
            m[pe.th32ProcessID] = std::string(narrow);
        } 
		while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return m;
}

// ---------------------------------------------------------------------------
// getHandleAudit(pid) - public entry point
// ---------------------------------------------------------------------------
// public entry that lists all external handles open to the target with decoded rights

py::list get_handle_audit(int pid)

{
    py::list results;
    uint64_t scan_ts = now_us();
    std::string trace_id = make_trace_id(pid, scan_ts);
    DWORD target_pid = static_cast<DWORD>(pid);
    DWORD our_pid = GetCurrentProcessId();

    // load NtQuerySystemInformation
    // same applies, resolve from ntdll at runtime

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    if (!ntdll) 
        return results;

    pfn_nt_query_sys_info pfn_qsi = reinterpret_cast<pfn_nt_query_sys_info>(GetProcAddress(ntdll, "NtQuerySystemInformation"));

    if (!pfn_qsi) 
        return results;

    // enumerate all system handles
    // grow buffer until query succeeds, same applies

    std::vector<BYTE> buf(1 << 20);  // 1 MB starting size
    ULONG needed = 0;
    ntstatus_t status;

    do {
        status = pfn_qsi(system_handle_information_class,
            buf.data(),
            static_cast<ULONG>(buf.size()),
            &needed);
        if (status == (ntstatus_t)status_info_length_mismatch)
            buf.resize(buf.size() * 2);
    } while (status == (ntstatus_t)status_info_length_mismatch);

    if (status != 0) return results;

    auto* info = reinterpret_cast<sys_handle_info*>(buf.data());

    // build name map once
    // faster than opening each owner process for its name

    std::unordered_map<DWORD, std::string> pid_names = build_pid_name_map();

    // dedup: owner_pid -> set of already-reported handle values
    // same owner can have multiple handles to the same target
 //	report all

    HANDLE our_process = GetCurrentProcess();

    // loop through every handle in the system

    for (ULONG i = 0; i < info->handle_count; i++)

    {
        sys_handle_entry& entry = info->handles[i];

        // same applies, ignore self and target

        if (entry.owner_pid == target_pid) continue;
        if (entry.owner_pid == our_pid)    continue;

        // mask filter: must carry at least one interesting right
        // (this avoids duplicating thousands of harmless handles)

        DWORD interesting = ha_vm_write | ha_vm_read | ha_vm_op | ha_create_thread | ha_suspend | ha_dup_handle | ha_all;

        if (!(entry.access_mask & interesting)) continue;

        // open owner so it can duplicate
        // PROCESS_DUP_HANDLE is the minimum needed

        HANDLE h_owner = OpenProcess(PROCESS_DUP_HANDLE, FALSE, entry.owner_pid);

        if (!h_owner) continue;

        // duplicate with PROCESS_QUERY_LIMITED_INFORMATION so it can
        // call GetProcessId() to confirm this handle really points at target
        // it needs enough rights to query but not modify the resolved process

        HANDLE h_dup = NULL;

        BOOL ok = DuplicateHandle(

            h_owner,
            reinterpret_cast<HANDLE>(static_cast<uintptr_t>(entry.handle_value)),
            our_process,
            &h_dup,
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            0);

        CloseHandle(h_owner);
        if (!ok || !h_dup) 
			continue;

        // confirm the handle actually points at the target

        DWORD resolved_pid = GetProcessId(h_dup);
        CloseHandle(h_dup);

        if (resolved_pid != target_pid) continue;  // not pointing at the target

        // decode the access mask
        // turn the raw bits into a readable list of rights

        DWORD mask = entry.access_mask;
        std::string decoded = decode_access_mask(mask);

        // boolean shortcuts for the most dangerous bits
        // these are easier to filter on in python

        bool has_vm_write = (mask & ha_vm_write) != 0;
        bool has_vm_read = (mask & ha_vm_read) != 0;
        bool has_create_thread = (mask & ha_create_thread) != 0;
        bool has_suspend = (mask & ha_suspend) != 0;
        bool has_dup_handle = (mask & ha_dup_handle) != 0;
        bool has_all_access = (mask & ha_all) == ha_all;

        // owner name
        // look up the owners exe name from the prebuilt map

        std::string owner_name;

        {
            std::unordered_map<DWORD, std::string>::const_iterator ni =
                pid_names.find(entry.owner_pid);
            if (ni != pid_names.end())
                owner_name = ni->second;
        }

        // build the result entry for python

        py::dict d;
        d["owner_pid"] = static_cast<int>(entry.owner_pid);
        d["owner_name"] = owner_name;
        d["handle_value"] = static_cast<int>(entry.handle_value);
        d["access_mask"] = static_cast<uint32_t>(mask);
        d["access_decoded"] = decoded;
        d["has_vm_write"] = has_vm_write;
        d["has_vm_read"] = has_vm_read;
        d["has_create_thread"] = has_create_thread;
        d["has_suspend"] = has_suspend;
        d["has_dup_handle"] = has_dup_handle;
        d["has_all_access"] = has_all_access;
        d["scan_ts_us"] = scan_ts;
        d["event_ts_us"] = scan_ts;
        d["trace_id"] = trace_id;
        results.append(d);
    }

    return results;
}

// ---------------------------------------------------------------------------
// API activity snapshot  (getApiActivitySnapshot)
//
// because it runs usermode only without a kernel driver it cannot directly
// intercept another processs syscalls.  Instead it takes N lightweight
// sub snapshots of the targets memory and thread state over a timed
// window, diff consecutive pairs, and infer which APIs were called from
// what changed:
//
//   new MEM_PRIVATE committed region appeared -> VirtualAllocEx
//   protection on a committed region changed -> VirtualProtect
//       ...and the new protection is executable -> VirtualProtect (->RX)
//   first bytes of an existing region changed -> WriteProcessMemory
//   a new TID appeared in the process -> CreateRemoteThread
//
// each inferred call is recorded as a timestamped timeline event. after
// all sub samples the ordered sequence of distinct event types is matched
// against known injection fingerprints to produce a pattern match list and
//
// known injection patterns matched:
//   "alloc_write_thread"    alloc -> write -> create_thread
//                           (classic DLL injection / shellcode inject)
//   "alloc_write"           alloc -> write
//                           (allocation + payload write, precursor to exec)
//   "alloc_exec"            alloc -> protect_exec
//                           (allocate then make executable)
//   "write_exec"            write -> protect_exec
//                           (write to existing region then make executable)
//   "write_thread"          write -> create_thread
//                           (write to pre-existing region + spawn thread)
//   "full_chain"            alloc -> write -> protect_exec -> create_thread
//                           (full shellcode: alloc RW, write, flip RX, thread)
//
// suspicion scoring (additive, capped at 100):
//   virtual_alloc count * 5 (max 20)
//   write_memory count * 8 (max 24)
//   virtual_protect * 4 (max 12)
//   create_thread *15 (max 30)
//   protect_exec present +10
//   pattern alloc_write + 5 
//   pattern alloc_write_thread +15
//   pattern write_exec or alloc_exec +10
//   pattern full_chain +20
//
// return dict fields:
//   pid, window_ms, samples_taken
//   counts { virtual_alloc, virtual_protect, protect_exec,
//             write_memory, create_thread, total }
//   timeline [ {ts_ms, event_type, detail} ... ]
//   event_sequence [ ordered distinct event types first seen ]
//   event_sequence [ ordered distinct event types ]
// ---------------------------------------------------------------------------
// this block infers what API calls happened in the target without a kernel driver
// works by taking many small snapshots and inferring activity from the diffs

#define activity_sample 24 // bytes sampled per region for change detection

// ---------- lightweight activity snapshot taken at each sub interval ----------
// each snapshot captures memory regions, protection flags, content samples and thread list

struct act_snap {

    ULONGLONG ts;
    std::unordered_map<uintptr_t, DWORD> private_regions; // base->protect
    std::unordered_map<uintptr_t, DWORD> all_regions; // base->protect
    std::unordered_map<uintptr_t, std::vector<BYTE>> content; // private base -> sample
    std::set<DWORD> threads;
};

// takes one lightweight snapshot of the target state
// kept fast so we can take many in a short window

static act_snap take_act_snap(HANDLE h_process, DWORD pid)
{
    act_snap s;
    s.ts = GetTickCount64();

    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));
    uintptr_t addr = 0;

    // walk memory regions and capture state

    while (VirtualQueryEx(h_process,
        reinterpret_cast<LPCVOID>(addr),
        &mbi, sizeof(mbi)) == sizeof(mbi))

    {
        if (mbi.State == MEM_COMMIT)
        {
            uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            s.all_regions[base] = mbi.Protect;

            // for private regions also capture content sample
            // this is what lets us detect WriteProcessMemory later

            if (mbi.Type == MEM_PRIVATE)

            {
                DWORD bp = mbi.Protect & 0xff;
                if (bp != PAGE_NOACCESS && !(mbi.Protect & PAGE_GUARD))

                {
                    s.private_regions[base] = mbi.Protect;
                    std::vector<BYTE> sample(activity_sample, 0);
                    SIZE_T to_read = mbi.RegionSize < (SIZE_T)activity_sample
                        ? mbi.RegionSize
                        : (SIZE_T)activity_sample;
                    SIZE_T got = 0;
                    ReadProcessMemory(h_process, mbi.BaseAddress, sample.data(), to_read, &got);
                    sample.resize(got);
                    s.content[base] = std::move(sample);
                }
            }
        }
		
        addr += mbi.RegionSize;

        if (addr == 0) break;
    }

    // also snapshot the thread list for new thread detection

    HANDLE tsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (tsnap != INVALID_HANDLE_VALUE)

    {
        THREADENTRY32 te;
        ZeroMemory(&te, sizeof(te));
        te.dwSize = sizeof(te);

        if (Thread32First(tsnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid)
                    s.threads.insert(te.th32ThreadID);
            } while (Thread32Next(tsnap, &te));
        }
        CloseHandle(tsnap);
    }
    return s;
}

// ---------- timeline event ----------
// represents one inferred API call with its time and details

struct act_event {
	
    ULONGLONG ts_rel; // ms since start of observation
	
    std::string type; // "virtual_alloc" | "virtual_protect" | "protect_exec"
    // | "write_memory" | "create_thread"
	
    std::string detail;
};

// ---------- diff two consecutive snapshots, append events to timeline ----------
// compares two snapshots and emits an event for each detected change

static void diff_act_snaps(const act_snap& before,
    const act_snap& after,
    ULONGLONG      start_ts,
    std::vector<act_event>& timeline)
{
    ULONGLONG ts = (after.ts > start_ts) ? (after.ts - start_ts) : 0;

    // --- new private regions (VirtualAllocEx) ---
    // a region appearing in after that wasnt in before = allocation

    for (std::unordered_map<uintptr_t, DWORD>::const_iterator
        it = after.private_regions.begin();
        it != after.private_regions.end(); ++it)
    {
        if (!before.private_regions.count(it->first))
        {
            act_event ev;
            ev.ts_rel = ts;
            ev.type = "virtual_alloc";
            char buf[64];
            sprintf_s(buf, sizeof(buf), "base=0x%llX protect=%s",
                (unsigned long long)it->first,
                alloc_protect_str(it->second).c_str());
            ev.detail = std::string(buf);
            timeline.push_back(ev);
        }
    }

    // --- protection changes (VirtualProtect) ---
    // any region whose protect flags changed = a VirtualProtect call
    // if the change gives execute permission its even more suspicious

    for (std::unordered_map<uintptr_t, DWORD>::const_iterator
        it = before.all_regions.begin();
        it != before.all_regions.end(); ++it)
    {
        std::unordered_map<uintptr_t, DWORD>::const_iterator ai =
            after.all_regions.find(it->first);

        if (ai == after.all_regions.end()) 
            continue;
        if (it->second == ai->second) 
            continue;

        bool was_exec = is_executable(it->second);
        bool now_exec = is_executable(ai->second);
        bool gained_exec = (!was_exec && now_exec);

        // emit generic protect change
        // label as protect_exec when execute was added

        {
            act_event ev;
            ev.ts_rel = ts;
            ev.type = gained_exec ? "protect_exec" : "virtual_protect";
            char buf[128];
            sprintf_s(buf, sizeof(buf),
                "base=0x%llX %s->%s",
                (unsigned long long)it->first,
                alloc_protect_str(it->second).c_str(),
                alloc_protect_str(ai->second).c_str());
            ev.detail = std::string(buf);
            timeline.push_back(ev);
        }
    }

    // --- content changes (WriteProcessMemory) ---
    // region exists in both snapshots but bytes changed = something wrote to it

    for (std::unordered_map<uintptr_t, std::vector<BYTE>>::const_iterator
        it = before.content.begin();
        it != before.content.end(); ++it)
    {
        std::unordered_map<uintptr_t,
            std::vector<BYTE>>::const_iterator ai =
            after.content.find(it->first);

        if (ai == after.content.end())
            continue;
		
        if (it -> second.empty())
            continue;
		
        if (it -> second == ai->second)
            continue;
		

        act_event ev;
        ev.ts_rel = ts;
        ev.type = "write_memory";
        char buf[64];
        sprintf_s(buf, sizeof(buf), "base=0x%llX",
            (unsigned long long)it->first);
        ev.detail = std::string(buf);
        timeline.push_back(ev);
    }

    // --- new threads (CreateRemoteThread) ---
    // new tid in after = a thread was created during this interval

    for (std::set<DWORD>::const_iterator
        it = after.threads.begin();
        it != after.threads.end(); ++it)

    {
        if (!before.threads.count(*it))

        {
            act_event ev;
            ev.ts_rel = ts;
            ev.type = "create_thread";
            char buf[32];
            sprintf_s(buf, sizeof(buf), "tid=%u", (unsigned)*it);
            ev.detail = std::string(buf);
            timeline.push_back(ev);
        }
    }
}

// build ordered list of distinct event types in first-seen order
// gives the python side a clean sequence to pattern match against

static std::vector<std::string> build_ordered_seq(const std::vector<act_event>& timeline)
{
    std::vector<std::string> seq;
    std::set<std::string> seen;

    for (size_t i = 0; i < timeline.size(); i++)

    {
        const std::string& t = timeline[i].type;
        if (!seen.count(t))

        {
            seen.insert(t);
            seq.push_back(t);
        }
    }
    return seq;
}

// ---------------------------------------------------------------------------
// getApiActivitySnapshot(pid, delayMs, numSamples) - public entry point
// ---------------------------------------------------------------------------
// public entry, runs the whole observation pipeline and returns counts plus timeline

py::dict get_api_activity_snapshot(int pid, int delay_ms, int num_samples)
{
    py::dict result;
    uint64_t scan_ts = now_us();
    std::string trace_id = make_trace_id(pid, scan_ts);
    DWORD dpid = static_cast<DWORD>(pid);

    // clamp samples
    // keep numSamples in a sensible range to avoid runaway scans

    if (num_samples < 2)  num_samples = 2;
    if (num_samples > 20) num_samples = 20;

    // compute per sample delay with a minimum floor

    int sub_interval_ms = delay_ms / num_samples;
    if (sub_interval_ms < 50) sub_interval_ms = 50;

    // open target with read access

    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dpid);

    if (!h_process)

    {
        result["error"] = "OpenProcess failed";
        result["pid"] = pid;
        return result;
    }

    std::vector<act_event> timeline;
    ULONGLONG start_ts = GetTickCount64();
    int samples_taken = 0;

    // take initial snapshot
    // baseline state before any observation period

    act_snap prev = take_act_snap(h_process, dpid);
    samples_taken++;

    // take additional snapshots, diff each against the previous one

    for (int s = 1; s < num_samples; s++)

    {
        Sleep(static_cast<DWORD>(sub_interval_ms));
        act_snap curr = take_act_snap(h_process, dpid);
        samples_taken++;
        diff_act_snaps(prev, curr, start_ts, timeline);
        prev = curr;
    }

    CloseHandle(h_process);

    // --- aggregate counts ---
    // total up each event type across the whole timeline

    int c_alloc = 0;
    int c_protect = 0;
    int c_prot_exec = 0;
    int c_write = 0;
    int c_thread = 0;

    for (size_t i = 0; i < timeline.size(); i++)
		
    {
        const std::string& t = timeline[i].type;
        if (t == "virtual_alloc")   c_alloc++;
        else if (t == "virtual_protect") c_protect++;
        else if (t == "protect_exec") { c_protect++; c_prot_exec++; }
        else if (t == "write_memory")    c_write++;
        else if (t == "create_thread")   c_thread++;
    }

    // --- build ordered event sequence ---
    // distinct event types in first seen order, for pattern matching in python

    std::vector<std::string> seq = build_ordered_seq(timeline);

    // --- build counts sub-dict ---
    // numeric summary for quick filtering

    py::dict counts;
    counts["virtual_alloc"] = c_alloc;
    counts["virtual_protect"] = c_protect;
    counts["protect_exec"] = c_prot_exec;
    counts["write_memory"] = c_write;
    counts["create_thread"] = c_thread;
    counts["total"] = c_alloc + c_protect + c_write + c_thread;

    // --- build timeline list ---
    // convert internal events into python dicts with absolute timestamps

    py::list py_timeline;
    for (size_t i = 0; i < timeline.size(); i++)
    {
        // ts_rel is milliseconds since scan start (from GetTickCount64 diff)
        // convert to absolute microseconds by adding to scan_ts
		
        uint64_t event_ts = scan_ts + static_cast<uint64_t>(timeline[i].ts_rel) * 1000;

        py::dict ev;
        ev["ts_ms"] = static_cast<uint64_t>(timeline[i].ts_rel);
        ev["event_ts_us"] = event_ts;
        ev["event_type"] = timeline[i].type;
        ev["detail"] = timeline[i].detail;
        ev["trace_id"] = trace_id;
        py_timeline.append(ev);
    }

    // --- build event sequence list ---
    // flat list of distinct event types for python rule engine

    py::list py_seq;
	
    for (size_t i = 0; i < seq.size(); i++)
        py_seq.append(seq[i]);

    // --- assemble result ---
    // pack all sections into the final dict

    result["pid"] = pid;
    result["window_ms"] = delay_ms;
    result["samples_taken"] = samples_taken;
    result["counts"] = counts;
    result["timeline"] = py_timeline;
    result["event_sequence"] = py_seq;
    result["scan_ts_us"] = scan_ts;
    result["trace_id"] = trace_id;

    return result;
}

// ---------------------------------------------------------------------------
// performance & system metrics  (get_perf_snapshot / get_perf_samples)
//
// CPU% calculation
// ----------------
// windows reports CPU time as accumulated 100-nanosecond intervals in
// FILETIME structs via GetProcessTimes(). to convert to a percentage it
// take two snapshots separated by a clock interval and compute:
//
//   delta_cpu = (kernel2 - kernel1) + (user2 - user1) 100ns units
//   delta_wall = elapsed wall-clock time 100ns units
//   cpu_pct = delta_cpu / (delta_wall * num_cores) * 100.0
//
// multiplying delta_wall by the logical processor count normalises the
// percentage so that 100% means one full core saturated. this matches
// what Task Manager displays.
//
// memory metrics  (PROCESS_MEMORY_COUNTERS_EX via GetProcessMemoryInfo)
// -----------------------------------------------------------------------
//   working_set_kb current physical memory pages mapped for this process
//   private_bytes_kb pages backed by the page file (not shared)
//   page_faults cumulative page fault count since process start
//   peak_ws_kb peak working set
//
// I/O counters  (GetProcessIoCounters)
// -----------------------------------------------------------------------
//   io_read_bytes total bytes read since process start
//   io_write_bytes total bytes written
//   io_read_ops number of read operations
//   io_write_ops number of write operations
//   io_other_bytes control operations (DeviceIoControl etc.)
//   io_other_ops
//
// misc
// -----------------------------------------------------------------------
//   handle_count open handles (GetProcessHandleCount)
//   thread_count threads (from TH32CS_SNAPTHREAD snapshot)
//
// returned dict keys (per process):
//   pid, cpu_percent (double), working_set_kb, private_bytes_kb,
//   peak_ws_kb, page_faults, io_read_bytes, io_write_bytes,
//   io_read_ops, io_write_ops, io_other_bytes, io_other_ops,
//   handle_count, thread_count, sample_ok (bool)
// ---------------------------------------------------------------------------
// this block gathers performance metrics like cpu, memory, and IO
// used by the GUI to display live process metrics
// number of logical processors (cached on first call)
// cached because windows wont change core count between calls

static int num_logical_cores()
{
    static int n = 0;
    if (n == 0)

    {
        SYSTEM_INFO si;
        ZeroMemory(&si, sizeof(si));
        GetSystemInfo(&si);
        n = static_cast<int>(si.dwNumberOfProcessors);
        if (n < 1) n = 1;
    }

    return n;
}

// combine FILETIME hi/lo into a uint64 of 100ns units
// FILETIME is split into high and low dwords, this packs them together

static uint64_t ft_to_u64(const FILETIME& ft)

{
    return (uint64_t(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

// one lightweight snapshot for a single pid with no sleep
// captures cpu time and wall time at one point

struct perf_snap_1 {
    uint64_t cpu_total; // kernel + user in 100ns units
    uint64_t wall_time; // GetSystemTimeAsFileTime at moment of read
};

// takes the cpu time snapshot for a process
// returns false if GetProcessTimes fails

static bool take_perf_snap_1(HANDLE h_process, perf_snap_1& out)

{
    FILETIME ft_creation, ft_exit, ft_kernel, ft_user, ft_wall;
    ZeroMemory(&ft_creation, sizeof(ft_creation));
    ZeroMemory(&ft_exit, sizeof(ft_exit));
    ZeroMemory(&ft_kernel, sizeof(ft_kernel));
    ZeroMemory(&ft_user, sizeof(ft_user));

    if (!GetProcessTimes(h_process, &ft_creation, &ft_exit, &ft_kernel, &ft_user))
        return false;

    // get wall time as close as possible to the cpu time read

    GetSystemTimeAsFileTime(&ft_wall);

    // sum kernel and user time, both contribute to cpu usage

    out.cpu_total = ft_to_u64(ft_kernel) + ft_to_u64(ft_user);
    out.wall_time = ft_to_u64(ft_wall);

    return true;
}
// build the full metrics dict for a pid once two cpu snapshots already taken
// shared by both single and batch perf snapshot functions

static py::dict build_perf_dict(int pid, HANDLE h_process, const perf_snap_1& s1, const perf_snap_1& s2)
{
    py::dict d;

    // default everything to zero in case any individual query fails

    d["pid"] = pid;
    d["sample_ok"] = false;
    d["cpu_percent"] = 0.0;
    d["working_set_kb"] = 0;
    d["private_bytes_kb"] = 0;
    d["peak_ws_kb"] = 0;
    d["page_faults"] = 0;
    d["io_read_bytes"] = (uint64_t)0;
    d["io_write_bytes"] = (uint64_t)0;
    d["io_read_ops"] = (uint64_t)0;
    d["io_write_ops"] = (uint64_t)0;
    d["io_other_bytes"] = (uint64_t)0;
    d["io_other_ops"] = (uint64_t)0;
    d["handle_count"] = 0;
    d["thread_count"] = 0;

    if (!h_process) 
		return d;

    // --- cpu ---
    // (delta_cpu / delta_wall) gives fraction of one core
    // dividing by num cores gives a percent normalised to total system capacity

    uint64_t delta_cpu = (s2.cpu_total > s1.cpu_total) ? (s2.cpu_total - s1.cpu_total) : 0;
    uint64_t delta_wall = (s2.wall_time > s1.wall_time) ? (s2.wall_time - s1.wall_time) : 1;
    double cpu_pct = (double)delta_cpu / ((double)delta_wall * num_logical_cores()) * 100.0;

    // clamp to a sensible range

    if (cpu_pct < 0.0)  cpu_pct = 0.0;
    if (cpu_pct > 100.0 * num_logical_cores()) cpu_pct = 100.0 * num_logical_cores();
    d["cpu_percent"] = cpu_pct;

    // --- memory ---
    // working set, private bytes, peak working set, page faults

    PROCESS_MEMORY_COUNTERS_EX pmc;
    ZeroMemory(&pmc, sizeof(pmc));
    pmc.cb = sizeof(pmc);

    if (GetProcessMemoryInfo(h_process,
        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
        sizeof(pmc)))
    {
        d["working_set_kb"] = static_cast<uint64_t>(pmc.WorkingSetSize / 1024);
        d["private_bytes_kb"] = static_cast<uint64_t>(pmc.PrivateUsage / 1024);
        d["peak_ws_kb"] = static_cast<uint64_t>(pmc.PeakWorkingSetSize / 1024);
        d["page_faults"] = static_cast<uint64_t>(pmc.PageFaultCount);
    }

    // --- io ---
    // read write byte counts and op counts since process start

    IO_COUNTERS ioc;
    ZeroMemory(&ioc, sizeof(ioc));

    if (GetProcessIoCounters(h_process, &ioc))

    {
        d["io_read_bytes"] = static_cast<uint64_t>(ioc.ReadTransferCount);
        d["io_write_bytes"] = static_cast<uint64_t>(ioc.WriteTransferCount);
        d["io_read_ops"] = static_cast<uint64_t>(ioc.ReadOperationCount);
        d["io_write_ops"] = static_cast<uint64_t>(ioc.WriteOperationCount);
        d["io_other_bytes"] = static_cast<uint64_t>(ioc.OtherTransferCount);
        d["io_other_ops"] = static_cast<uint64_t>(ioc.OtherOperationCount);
    }

    // --- handle count ---
    // number of open handles in this process

    DWORD handle_count = 0;

    if (GetProcessHandleCount(h_process, &handle_count))
        d["handle_count"] = static_cast<int>(handle_count);

    // --- thread count (snapshot) ---
    // walk thread snapshot and count threads owned by this pid

    {
        HANDLE tsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (tsnap != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 te;
            ZeroMemory(&te, sizeof(te));
            te.dwSize = sizeof(te);
            int tc = 0;
            DWORD dpid = static_cast<DWORD>(pid);

            if (Thread32First(tsnap, &te))
            {
                do {
                    if (te.th32OwnerProcessID == dpid) tc++;
                } while (Thread32Next(tsnap, &te));
            }

            CloseHandle(tsnap);
            d["thread_count"] = tc;
        }
    }

    d["sample_ok"] = true;
    return d;
}

// ---------------------------------------------------------------------------
// get_perf_snapshot(pid, delay_ms)
// single-process performance snapshot over a timed window.
// ---------------------------------------------------------------------------
// public entry, single process metrics over a delay window

py::dict get_perf_snapshot(int pid, int delay_ms)
{
    uint64_t scan_ts = now_us();
    std::string trace_id = make_trace_id(pid, scan_ts);

    // build a fallback dict that we return on any failure
    // all metrics defaulted to zero with sample_ok false

    py::dict fail;
    fail["pid"] = pid;
    fail["sample_ok"] = false;
    fail["cpu_percent"] = 0.0;
    fail["working_set_kb"] = 0;
    fail["private_bytes_kb"] = 0;
    fail["peak_ws_kb"] = 0;
    fail["page_faults"] = 0;
    fail["io_read_bytes"] = (uint64_t)0;
    fail["io_write_bytes"] = (uint64_t)0;
    fail["io_read_ops"] = (uint64_t)0;
    fail["io_write_ops"] = (uint64_t)0;
    fail["io_other_bytes"] = (uint64_t)0;
    fail["io_other_ops"] = (uint64_t)0;
    fail["handle_count"] = 0;
    fail["thread_count"] = 0;
    fail["scan_ts_us"] = scan_ts;
    fail["trace_id"] = trace_id;

    // open target with read access

    DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    HANDLE h_process = OpenProcess(access, FALSE, static_cast<DWORD>(pid));

    if (!h_process) return fail;

    // take first snapshot, sleep, take second

    perf_snap_1 s1, s2;
    if (!take_perf_snap_1(h_process, s1))
    {
        CloseHandle(h_process);
        return fail;
    }

    if (delay_ms > 0)
        Sleep(static_cast<DWORD>(delay_ms));

    if (!take_perf_snap_1(h_process, s2))
    {
        CloseHandle(h_process);
        return fail;
    }

    // build result from the two snapshots

    py::dict result = build_perf_dict(pid, h_process, s1, s2);
    result["scan_ts_us"] = scan_ts;
    result["trace_id"] = trace_id;
    CloseHandle(h_process);

    return result;
}

// ---------------------------------------------------------------------------
// get_perf_samples(pids, delay_ms)
// batch version: snapshot all pids, sleep once, snapshot again
// pids is a Python list of ints
// returns a list of dicts in the same order.
// ---------------------------------------------------------------------------
// batch version, more efficient because only one sleep for all processes

py::list get_perf_samples(py::list pids, int delay_ms)

{
    py::list results;
    Py_ssize_t n = PyList_Size(pids.ptr());
    if (n == 0) return results;

    // open all handles and take first snapshots
    // holds per pid state across the two snapshot passes

    struct entry {
		
        int pid;
        HANDLE h_proc;
        perf_snap_1 s1;
        bool s1ok;
    };

    std::vector<entry> entries(static_cast<size_t>(n));

    // open every process and take the first cpu time snapshot

    for (Py_ssize_t i = 0; i < n; i++)
		
    {
        PyObject* pid_obj = PyList_GetItem(pids.ptr(), i);

        int pid = static_cast<int>(PyLong_AsLong(pid_obj));

        entries[i].pid = pid;

        entries[i].h_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));

        entries[i].s1ok = (entries[i].h_proc != NULL) &&
            take_perf_snap_1(entries[i].h_proc, entries[i].s1);
    }

    // one shared sleep covers the cpu observation window for all pids

    if (delay_ms > 0)
        Sleep(static_cast<DWORD>(delay_ms));

    // second snapshot + build results
    // for each entry take s2 and build the metrics dict

    for (size_t i = 0; i < static_cast<size_t>(n); i++)
    {
        entry& e = entries[i];

        if (!e.s1ok)
        {
            // same applies, return zeroed fallback dict

            py::dict fail;
            fail["pid"] = e.pid;
            fail["sample_ok"] = false;
            fail["cpu_percent"] = 0.0;
            fail["working_set_kb"] = 0;
            fail["private_bytes_kb"] = 0;
            fail["peak_ws_kb"] = 0;
            fail["page_faults"] = 0;
            fail["io_read_bytes"] = (uint64_t)0;
            fail["io_write_bytes"] = (uint64_t)0;
            fail["io_read_ops"] = (uint64_t)0;
            fail["io_write_ops"] = (uint64_t)0;
            fail["io_other_bytes"] = (uint64_t)0;
            fail["io_other_ops"] = (uint64_t)0;
            fail["handle_count"] = 0;
            fail["thread_count"] = 0;
            results.append(fail);
        }

        else

        {
            perf_snap_1 s2;
            take_perf_snap_1(e.h_proc, s2);
            results.append(build_perf_dict(e.pid, e.h_proc, e.s1, s2));
        }

        if (e.h_proc) CloseHandle(e.h_proc);
    }

    return results;
}

// ---------------------------------------------------------------------------
// memory sampling  (get_memory_sample / get_memory_samples)
//
// reads a byte range from a target process and returns it as a
// hex string. The caller rule engine decides which addresses are
// worth capturing, this function just performs the read.
//
// choices:
//   - Max 4096 bytes per call.
//   - Partial reads are accepted: if ReadProcessMemory succeeds for fewer
//     bytes than requested return whatever was read and set size_read accordingly.
//   - address is passed as uint64 so 64 bit VAs round cleanly through
//     python integers without sign extension errors.
//
// returned dict fields:
//   address uint64 virtual address that was sampled
//   size_req int bytes requested
//   size_read int bytes actually read (0 on failure)
//   data_hex str lowercase hex string of bytes read
//   read_ok bool true if ReadProcessMemory returned non-zero
//   error_code int GetLastError() when read_ok is false, else 0
// ---------------------------------------------------------------------------

// helps to read a specific block of memory from a target process

#define memsample_max 4096 // max 4096 bytes of read

static py::dict do_memory_sample(HANDLE h_process, uint64_t address, int size_req)

{ // creates a python dict with default values
	// if successfully read, then defaults are changed
    py::dict d;
    d["address"] = address;
    d["size_req"] = size_req;
    d["size_read"] = 0;
    d["data_hex"] = std::string();
    d["read_ok"] = false;
    d["error_code"] = 0;

	// if python asks for under 0 bytes, reject
    if (size_req <= 0)
		
    {
        d["error_code"] = (int)ERROR_INVALID_PARAMETER;
		
        return d;
    }

	// limit the read size 
    int clamped = (size_req > memsample_max) ? memsample_max : size_req;

	// buffer to store the bytes 
	
    std::vector<BYTE> buf(static_cast<size_t>(clamped), 0);
    SIZE_T got = 0;

	// reads from target process memory, using address, into buffer
	
    BOOL ok = ReadProcessMemory(
	
        h_process,
        reinterpret_cast<LPCVOID>(address),
        buf.data(),
        static_cast<SIZE_T>(clamped),
        &got);

	// if failed, no bytes read, throw error
	
    if (!ok && got == 0)
		
    {
        d["error_code"] = static_cast<int>(GetLastError());
        return d;
    }

    // truncate buffer to what was actually read
	
    buf.resize(got);

    // build hex string
    static const char* hex = "0123456789abcdef";
	
    std::string hex_str;
	
    hex_str.reserve(got * 2);
	
	// loops through the bytes and changes to two hex charactercs
	
    for (size_t i = 0; i < got; i++)
    {
        hex_str += hex[buf[i] >> 4];
        hex_str += hex[buf[i] & 0xf];
    }
	
	// update dictonary with the new results

    d["size_read"] = static_cast<int>(got);
    d["data_hex"] = hex_str;
    d["read_ok"] = true;
    return d;
}

// ---------------------------------------------------------------------------
// get_memory_sample(pid, address, size)
// entry point for a single sample.
// ---------------------------------------------------------------------------

// function for reading a memory sample
// trapped around domemorysample()

py::dict get_memory_sample(int pid, uint64_t address, int size)

{
	// create timestamp and trace id sample
    uint64_t scan_ts = now_us();
    std::string trace_id = make_trace_id(pid, scan_ts);

	// returns a python dictonary for time of sample and trace id

    py::dict fail;
	
	// this is returned if process cannot be opened
	
    fail["address"] = address;
    fail["size_req"] = size;
    fail["size_read"] = 0;
    fail["data_hex"] = std::string();
    fail["read_ok"] = false;
    fail["error_code"] = 0;
    fail["scan_ts_us"] = scan_ts;
    fail["trace_id"] = trace_id;

	// atempt to open the process

    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));

	// checks whether it worked or failed

    if (!h_process)
    {
        fail["error_code"] = static_cast<int>(GetLastError());
        return fail;
    }

	// if successful, add metadata to the result

    py::dict result = do_memory_sample(h_process, address, size);
    result["scan_ts_us"] = scan_ts;
    result["trace_id"] = trace_id;
    CloseHandle(h_process);
	
    return result;
}

// ---------------------------------------------------------------------------
// get_memory_samples(pid, regions)
// Batch version, regions is a Python list of dicts
//
// Returns a list of sample dicts in the same order
// opens the process handle once and reuses it for all reads
// all results from one call share the same trace_id
// ---------------------------------------------------------------------------

// batch version of getmemorysample()

py::list get_memory_samples(int pid, py::list regions)
{
	
	// creates the required timestamp trace id and output list
	
    py::list results;
    uint64_t scan_ts = now_us();
    std::string trace_id = make_trace_id(pid, scan_ts);

	// opens the process once
	// it reuses the same handle

    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));

    Py_ssize_t n = PyList_Size(regions.ptr());
	
	// gets how many regions are requested from the python list 
	// and loops through each memory sample
	
    for (Py_ssize_t i = 0; i < n; i++)
		
    {
		
		// gets each item from the python list
		
        PyObject* item = PyList_GetItem(regions.ptr(), i);  // borrowed ref

        // extract address and size using raw CPython API
        uint64_t addr = 0;
        int sz = 0;

        PyObject* addr_obj = PyDict_GetItemString(item, "address");
        PyObject* size_obj = PyDict_GetItemString(item, "size");

        if (addr_obj) addr = static_cast<uint64_t>(PyLong_AsUnsignedLongLong(addr_obj));
		
        if (size_obj) sz = static_cast<int>(PyLong_AsLong(size_obj));

        uint64_t event_ts = now_us();  // per-read timestamp for each individual read

		// if failed to read, function still creates a failure dictonary per requested region

        if (!h_process)
			
        {
            py::dict fail;
            fail["address"] = addr;
            fail["size_req"] = sz;
            fail["size_read"] = 0;
            fail["data_hex"] = std::string();
            fail["read_ok"] = false;
            fail["error_code"] = static_cast<int>(GetLastError());
            fail["scan_ts_us"] = scan_ts;
            fail["event_ts_us"] = event_ts;
            fail["trace_id"] = trace_id;
            results.append(fail);
        }
		
        else
			// if successful, read memory range, add timestamps and id
        {
            py::dict d = do_memory_sample(h_process, addr, sz);
            d["scan_ts_us"] = scan_ts;
            d["event_ts_us"] = event_ts;
            d["trace_id"] = trace_id;
			
            results.append(d); // append to results
        }
    }

    if (h_process) CloseHandle(h_process);
	
    return results; // return list of memory samples back to python
}

// ---------------------------------------------------------------------------
// pybind11 module registration
// ---------------------------------------------------------------------------

// tells python the modules and that they exist, so they can be called in python

PYBIND11_MODULE(memory_scanner, m)

{
    m.doc() = "Windows memory scanner - pybind11 extension";

    m.def("list_processes", &list_processes,
        "Enumerate all running processes. Returns list of dicts with "
        "pid/name/path/integrity/elevated/privileges. No module or memory "
        "scanning is performed, so this is fast.");

    m.def("scan_process", &scan_process,
        py::arg("pid"),
        "Deep-scan a single process by PID. Returns a dict containing "
        "all fields including modules and memory_regions with entropy data.");

    m.def("get_virtual_allocs", &get_virtual_allocs,
        py::arg("pid"),
        "Scan a process for private committed memory regions (VirtualAllocEx "
        "fingerprint). Returns list of dicts with base, size, protect, "
        "entropy, has_mz, has_pe.");

    m.def("get_protect_changes", &get_protect_changes,
        py::arg("pid"),
        py::arg("delay_ms") = 500,
        "Detect VirtualProtect activity by diffing two memory snapshots "
        "separated by delay_ms milliseconds. Returns list of dicts with "
        "base, protect_old, protect_new, gained_exec, lost_write.");

    m.def("get_write_detect", &get_write_detect,
        py::arg("pid"),
        py::arg("delay_ms") = 500,
        "Detect cross-process WriteProcessMemory activity by diffing content "
        "snapshots of private committed regions. Also identifies writer PIDs "
        "by enumerating PROCESS_VM_WRITE handles. Returns list of dicts with "
        "base, size, protect, sample_before, sample_after, writer_pids.");

    m.def("get_nt_syscall_info", &get_nt_syscall_info,
        py::arg("pid"),
        "NT syscall analysis: (1) scan non-system module import tables for "
        "direct Nt*/Zw* imports; (2) scan executable private regions for "
        "SYSCALL/SYSENTER/INT2E stubs outside ntdll; (3) check ntdll exports "
        "for inline hooks. Returns dict with direct_nt_imports, syscall_stubs, "
        "hooked_functions.");

    m.def("get_thread_info", &get_thread_info,
        py::arg("pid"),
        "Enumerate all threads in a process with their Win32 start addresses. "
        "Classifies each start address as image-backed or private-executable. "
        "Returns list of dicts with tid, start_address, start_module, "
        "in_private_exec, in_image, resolved.");

    m.def("get_remote_threads", &get_remote_threads,
        py::arg("pid"),
        py::arg("delay_ms") = 500,
        "Detect threads created in the target process during the observation "
        "window (delay_ms). For each new thread, attempts to identify the "
        "creator PID via system handle enumeration. Returns list of dicts with "
        "tid, start_address, in_private_exec, in_image, creator_pid, remote.");

    m.def("get_mapped_modules", &get_mapped_modules,
        py::arg("pid"),
        "Detect manually mapped / hidden modules. Cross-references MEM_IMAGE "
        "regions from VirtualQuery against EnumProcessModulesEx (Win32 list) "
        "and the PEB LDR doubly-linked lists (InLoadOrder, InMemoryOrder, "
        "InInitOrder). Returns anomalous entries with base, size, device_path, "
        "has_mz, not_in_win32_list, not_in_ldr, no_file_backing.");

    m.def("get_handle_audit", &get_handle_audit,
        py::arg("pid"),
        "Enumerate all external handles open to a target process. For each "
        "handle held by a foreign process, decodes the access mask. Returns "
        "list of dicts with owner_pid, owner_name, handle_value, access_mask, "
        "access_decoded, has_vm_write, has_vm_read, has_create_thread, "
        "has_suspend, has_dup_handle, has_all_access.");

    m.def("get_api_activity_snapshot", &get_api_activity_snapshot,
        py::arg("pid"),
        py::arg("delay_ms") = 1000,
        py::arg("num_samples") = 5,
        "Infer API call activity by taking num_samples sub-snapshots of "
        "memory and thread state over delay_ms milliseconds and diffing "
        "consecutive pairs. Infers: VirtualAllocEx (new private regions), "
        "VirtualProtect (protection changes), WriteProcessMemory (content "
        "changes), CreateRemoteThread (new TIDs). Returns dict with counts, "
        "timestamped timeline, and ordered event_sequence.");

    m.def("get_memory_sample", &get_memory_sample,
        py::arg("pid"),
        py::arg("address"),
        py::arg("size") = 4096,
        "Read up to `size` bytes (max 4096) from `address` in process `pid`. "
        "Returns dict with address, size_req, size_read, data_hex (lowercase "
        "hex string), read_ok, error_code. Used for targeted forensic capture "
        "of regions identified as interesting by other scans.");

    m.def("get_memory_samples", &get_memory_samples,
        py::arg("pid"),
        py::arg("regions"),
        "Batch version of get_memory_sample. Takes a list of "
        "{\"address\": int, \"size\": int} dicts and returns a list of sample "
        "dicts in the same order. Opens the process handle once for all reads.");

    m.def("get_perf_snapshot", &get_perf_snapshot,
        py::arg("pid"),
        py::arg("delay_ms") = 1000,
        "Measure CPU%, memory, and I/O metrics for a single process over a "
        "delay_ms window. CPU% is computed from delta kernel+user time / "
        "delta wall time normalised by logical core count. Returns dict with: "
        "pid, cpu_percent, working_set_kb, private_bytes_kb, peak_ws_kb, "
        "page_faults, io_read_bytes, io_write_bytes, io_read_ops, io_write_ops, "
        "io_other_bytes, io_other_ops, handle_count, thread_count, sample_ok.");

    m.def("get_perf_samples", &get_perf_samples,
        py::arg("pids"),
        py::arg("delay_ms") = 1000,
        "Batch version of get_perf_snapshot. Takes a Python list of PIDs, "
        "snapshots all at once, sleeps delay_ms once, then snapshots again. "
        "Returns a list of perf dicts in the same PID order. More efficient "
        "than calling get_perf_snapshot N times (one shared sleep).");
}
