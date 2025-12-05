import re
# Utility to safely convert values to int
def safe_int(value, default=None):
    if value is None:
        return default
    if isinstance(value, str):
        value = value.strip()
        if value in ("", "N/A", "NA", "-", "--"):
            return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def parse_vol3_table(text: str):
    lines = [l for l in text.splitlines() if l.strip()]

    # Skip banner lines
    while lines and (
        lines[0].startswith("Volatility") or
        lines[0].startswith("Progress")
    ):
        lines.pop(0)

    if not lines:
        return []

    header_line = lines[0].strip()
    headers = re.split(r"\s+", header_line)

    # 🔧 Special case: "File output" (modules, maybe others)
    if len(headers) >= 2 and headers[-2] == "File" and headers[-1] == "output":
        headers = headers[:-2] + ["File output"]

    rows = []

    for line in lines[1:]:
        parts = re.split(r"\s+", line.strip(), maxsplit=len(headers) - 1)

        if len(parts) != len(headers):
            continue

        rows.append(dict(zip(headers, parts)))

    return rows


# ---------------- Plugin-Specific Parsers -----------------

def parse_pslist(rows):
    parsed = []
    for r in rows:
        parsed.append({
            "pid": safe_int(r.get("PID"), 0),
            "ppid": safe_int(r.get("PPID"), 0),
            "image_filename": r.get("ImageFileName"),
            "offset_v": r.get("Offset(V)"),
            "threads": safe_int(r.get("Threads"), 0),
            "handles": safe_int(r.get("Handles"), 0),
            "session_id": safe_int(r.get("SessionId"), 0),
            "wow64": r.get("Wow64"),
            "create_time": r.get("CreateTime"),
            "exit_time": r.get("ExitTime"),
        })
    return parsed




def parse_dlllist(rows):
    parsed = []

    for r in rows:

        # Step 1: extract simple fields safely
        pid = int(r.get("PID", 0))
        process = r.get("Process")
        base = r.get("Base")
        size = r.get("Size")
        name = r.get("Name")
        path = r.get("Path")

        # Step 2: Reconstruct LoadTime from leftover fields
        # Anything not in known columns goes into LoadTime
        known = {"PID", "Process", "Base", "Size", "Name", "Path"}
        rest = []

        for k, v in r.items():
            if k not in known:
                rest.append(str(v))

        loadtime = " ".join(rest).strip()

        parsed.append({
            "pid": pid,
            "process": process,
            "base": base,
            "size": size,
            "name": name,
            "path": path,
            "loadtime": loadtime,
        })

    return parsed


def parse_handles(rows):
    parsed = []

    for r in rows:
        try:
            pid = int(r.get("PID"))
        except:
            pid = None

        parsed.append({
            "pid": pid,
            "offset": r.get("Offset") or r.get("Offset(P)"),
            "handle_value": r.get("HandleValue"),
            "type": r.get("Type"),
            "granted_access": r.get("GrantedAccess"),
            "name": r.get("Name")
        })

    return parsed

def parse_ldrmodules(rows):
    parsed = []

    for r in rows:
        # Known columns
        pid = int(r.get("Pid", 0))
        process = r.get("Process")

        # Base address is incorrectly shifted right now → fix:
        base = r.get("Base")
        if base and not base.startswith("0x"):
            # Base was incorrectly replaced with process name
            base = r.get("InLoad")  # shift left
       
        # Boolean flags
        in_load = str(r.get("InLoad", "")).lower() == "true"
        in_init = str(r.get("InInit", "")).lower() == "true"
        in_mem  = str(r.get("InMem", "")).lower() == "true"

        # MappedPath is corrupted: "False\tpath"
        mp_raw = r.get("MappedPath", "")
        if "\t" in mp_raw:
            _, mapped_path = mp_raw.split("\t", 1)
        else:
            mapped_path = mp_raw

        parsed.append({
            "pid": pid,
            "process": process,
            "base": base,
            "in_load": in_load,
            "in_init": in_init,
            "in_mem": in_mem,
            "mapped_path": mapped_path.strip(),
        })

    return parsed


def parse_malfind(rows):
    """
    Clean up malfind output:
    - keep only real VAD rows
    - drop hexdump/disasm garbage rows
    """
    parsed = []

    for r in rows:
        pid_raw = r.get("PID")
        start = str(r.get("Start", ""))
        end = str(r.get("End", ""))
        prot = str(r.get("Protection", ""))
        tag = str(r.get("Tag", ""))

        # 1) PID must be an integer
        try:
            pid = int(pid_raw)
        except (TypeError, ValueError):
            continue

        # 2) Start/End must be addresses
        if not (start.startswith("0x") and end.startswith("0x")):
            continue

        # 3) Protection should look like PAGE_...
        if not prot.startswith("PAGE_"):
            continue

        # Now it's a real malfind hit
        commit = r.get("CommitCharge", "0")
        try:
            commit = int(commit)
        except ValueError:
            commit = 0

        parsed.append({
            "pid": pid,
            "process": r.get("Process"),
            "start": start,
            "end": end,
            "tag": tag,
            "protection": prot,
            "commit_charge": commit,
            # you can add PrivateMemory / File / Notes if you want
        })

    return parsed



def parse_psxview(rows):
    parsed = []
    for r in rows:
        parsed.append({
            "pid": int(r.get("PID", 0)),
            "pslist": r.get("pslist") == "True",
            "eprocess_pool": r.get("eprocess_pool") == "True",
            "ethread_pool": r.get("ethread_pool") == "True",
            "pspcid_list": r.get("pspcid_list") == "True",
            "session": r.get("session") == "True",
            "deskthrd": r.get("deskthrd") == "True",
        })
    return parsed


def parse_svcscan(rows):
    """
    Normalize windows.svcscan output into a clean structure.
    """
    parsed = []

    for r in rows:
        # PID: "1234" or "N/A"
        pid_raw = r.get("PID")
        try:
            pid = int(pid_raw) if pid_raw not in (None, "", "N/A") else None
        except ValueError:
            pid = None

        start_type = r.get("Start")       # e.g. SERVICE_AUTO_START
        state = r.get("State")            # e.g. SERVICE_RUNNING
        type_raw = r.get("Type", "") or ""  # e.g. SERVICE_KERNEL_DRIVER

        name = r.get("Name")
        display = r.get("Display")

        # Registry info
        registry_key = r.get("(Registry)")

        # Binary + Dll:
        binary_raw = r.get("Binary") or ""
        dll_raw = r.get("Dll") or ""

        # Many rows have Dll like: "<path>\t-"
        # or: "-p\t%systemroot%\\system32\\svchost.exe ... \t%systemroot%\\...dll"
        # We'll treat text before first \t as main path/command; rest may be extra.
        dll_main = dll_raw
        extra = ""
        if "\t" in dll_raw:
            dll_main, extra = dll_raw.split("\t", 1)

        dll_main = dll_main.strip()
        extra = extra.strip()

        # Decide how to map:
        # - For kernel drivers, dll_main is likely the driver path
        # - For svchost-based services, dll_main might be an argument chunk
        # We'll keep:
        #   binary_path: combine Binary + first part of Dll if it looks like a path/cmd
        #   service_dll: if extra looks like a .dll path, store that.
        binary_path = binary_raw.strip() or None
        service_dll = None

        # If dll_main looks like a path, use it as binary_path when Binary is useless
        if (not binary_path or binary_path in ("-", "Driver", "-k")) and dll_main:
            binary_path = dll_main

        # If extra looks like a DLL path, store it
        if extra.lower().endswith(".dll"):
            service_dll = extra
        elif dll_main.lower().endswith(".dll"):
            service_dll = dll_main

        # Type interpretation
        is_kernel_driver = "SERVICE_KERNEL_DRIVER" in type_raw
        is_fs_driver = "SERVICE_FILE_SYSTEM_DRIVER" in type_raw
        is_own_process = "SERVICE_WIN32_OWN_PROCESS" in type_raw
        is_shared_process = "SERVICE_WIN32_SHARE_PROCESS" in type_raw

        parsed.append({
            "pid": pid,
            "name": name,
            "display_name": display,
            "start_type": start_type,
            "state": state,
            "type_raw": type_raw,
            "is_kernel_driver": is_kernel_driver,
            "is_fs_driver": is_fs_driver,
            "is_own_process": is_own_process,
            "is_shared_process": is_shared_process,
            "registry_key": registry_key,
            "binary_path": binary_path,
            "service_dll": service_dll,
        })

    return parsed



PLUGIN_PARSERS = {
    "windows.pslist": parse_pslist,
    "windows.dlllist": parse_dlllist,
    "windows.handles": parse_handles,
    "windows.ldrmodules": parse_ldrmodules,
    "windows.malfind": parse_malfind,
    "windows.psxview": parse_psxview,
    "windows.svcscan": parse_svcscan, 
}
