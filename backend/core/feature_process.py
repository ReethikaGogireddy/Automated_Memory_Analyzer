# core/feature_process.py

from collections import defaultdict


def _to_int(val, default=0):
    try:
        if val in (None, "", "N/A"):
            return default
        return int(val)
    except Exception:
        return default


def process_features(all_plugins: dict) -> list[dict]:
    """
    Build per-process features from parsed plugin outputs.

    all_plugins should look like:
      {
        "windows.pslist":     [...],
        "windows.dlllist":    [...],
        "windows.handles":    [...],
        "windows.malfind":    [...],
        "windows.psxview":    [...],
        "windows.ldrmodules": [...],
        "windows.svcscan":    [...],
        ...
      }

    Returns: list of dicts, one dict per PID.
    """

    # Gracefully handle missing keys or non-prefixed plugin names
    ps   = all_plugins.get("windows.pslist")     or all_plugins.get("pslist")     or []
    dll  = all_plugins.get("windows.dlllist")    or all_plugins.get("dlllist")    or []
    hnd  = all_plugins.get("windows.handles")    or all_plugins.get("handles")    or []
    mf   = all_plugins.get("windows.malfind")    or all_plugins.get("malfind")    or []
    pv   = all_plugins.get("windows.psxview")    or all_plugins.get("psxview")    or []
    ldr  = all_plugins.get("windows.ldrmodules") or all_plugins.get("ldrmodules") or []
    svc  = all_plugins.get("windows.svcscan")    or all_plugins.get("svcscan")    or []

    processes: dict[int, dict] = {}

    def get_proc(pid: int) -> dict:
        """
        Get or create the feature dict for a given PID.
        """
        if pid not in processes:
            processes[pid] = {
                "pid": pid,
                "name": None,
                "ppid": None,
                "threads": 0,
                "handles_pslist": 0,
                "session_id": None,

                "dll_count": 0,

                "handle_count": 0,
                "file_handle_count": 0,
                "thread_handle_count": 0,
                "key_handle_count": 0,
                "mutant_handle_count": 0,

                "malfind_regions": 0,
                "malfind_commit_sum": 0,
                "malfind_rwx_regions": 0,

                "psxview_hidden_sources": 0,
                "hidden_in_pslist": 0,
                "hidden_in_eprocess_pool": 0,
                "hidden_in_ethread_pool": 0,
                "hidden_in_pspcid_list": 0,
                "hidden_in_csrss_handles": 0,
                "hidden_in_session": 0,
                "hidden_in_deskthrd": 0,

                "ldr_not_in_load": 0,
                "ldr_not_in_init": 0,
                "ldr_not_in_mem": 0,

                "svc_is_kernel_driver": 0,
                "svc_is_fs_driver": 0,
                "svc_is_own_process": 0,
                "svc_is_shared_process": 0,
                "svc_is_running": 0,
            }
        return processes[pid]

    # ---------------- pslist: basic process info ----------------
    for p in ps:
        # raw: PID / PPID / Name / Thds / Hnds
        # parsed: pid / ppid / name / threads / handles
        pid = _to_int(p.get("pid") if "pid" in p else p.get("PID"), default=None)
        if pid is None:
            continue
        proc = get_proc(pid)

        name = p.get("name") or p.get("Name") or p.get("Process")
        proc["name"] = name or proc["name"]

        ppid = _to_int(p.get("ppid") if "ppid" in p else p.get("PPID"), default=None)
        if ppid is not None:
            proc["ppid"] = ppid

        threads = _to_int(
            p.get("threads")
            or p.get("Thds")
            or p.get("Threads"),
            default=0,
        )
        proc["threads"] = threads

        handles_pslist = _to_int(
            p.get("handles")
            or p.get("Hnds")
            or p.get("Handles"),
            default=0,
        )
        proc["handles_pslist"] = handles_pslist

        session_id = _to_int(
            p.get("session_id")
            or p.get("SessionId")
            or p.get("Sess"),
            default=None,
        )
        proc["session_id"] = session_id

    # ---------------- dlllist: dll_count per process ----------------
    for d in dll:
        pid = _to_int(d.get("pid") if "pid" in d else d.get("PID"), default=None)
        if pid is None:
            continue
        proc = get_proc(pid)
        proc["dll_count"] += 1

    # ---------------- handles: handle type distribution ----------------
    for h in hnd:
        pid = _to_int(h.get("pid") if "pid" in h else h.get("PID"), default=None)
        if pid is None:
            continue
        proc = get_proc(pid)
        proc["handle_count"] += 1

        htype = (h.get("type") or h.get("Type") or "").lower()
        if htype == "file":
            proc["file_handle_count"] += 1
        elif htype == "thread":
            proc["thread_handle_count"] += 1
        elif htype == "key":
            proc["key_handle_count"] += 1
        elif htype == "mutant":
            proc["mutant_handle_count"] += 1

    # ---------------- malfind: per-process injected regions ----------------
    for m in mf:
        pid = _to_int(m.get("pid") if "pid" in m else m.get("PID"), default=None)
        if pid is None:
            continue
        proc = get_proc(pid)
        proc["malfind_regions"] += 1

        commit = _to_int(m.get("commit_charge") or m.get("CommitCharge"), default=0)
        proc["malfind_commit_sum"] += commit

        prot = (m.get("protection") or m.get("Protection") or "").upper()
        if "EXECUTE" in prot and "WRITE" in prot:
            proc["malfind_rwx_regions"] += 1

    # ---------------- psxview: hidden process indicators ----------------
    sources = [
        "pslist",
        "eprocess_pool",
        "ethread_pool",
        "pspcid_list",
        "csrss_handles",
        "session",
        "deskthrd",
    ]

    for p in pv:
        pid = _to_int(p.get("pid") if "pid" in p else p.get("PID"), default=None)
        if pid is None:
            continue
        proc = get_proc(pid)

        hidden_sources = 0
        for src in sources:
            val = p.get(src)
            if val is False:
                hidden_sources += 1
                key = f"hidden_in_{src}"
                if key in proc:
                    proc[key] = 1

        proc["psxview_hidden_sources"] = hidden_sources

    # ---------------- ldrmodules: module invisibility per process ----------------
    for m in ldr:
        pid = _to_int(m.get("pid") if "pid" in m else m.get("Pid") or m.get("PID"), default=None)
        if pid is None:
            continue
        proc = get_proc(pid)

        in_load = m.get("in_load")
        in_init = m.get("in_init")
        in_mem = m.get("in_mem")

        if in_load is False:
            proc["ldr_not_in_load"] += 1
        if in_init is False:
            proc["ldr_not_in_init"] += 1
        if in_mem is False:
            proc["ldr_not_in_mem"] += 1

    # ---------------- svcscan: service type/state per PID ----------------
    for s in svc:
        pid = _to_int(s.get("pid") if "pid" in s else s.get("PID"), default=None)
        if pid is None:
            continue
        proc = get_proc(pid)

        if s.get("is_kernel_driver"):
            proc["svc_is_kernel_driver"] = 1
        if s.get("is_fs_driver"):
            proc["svc_is_fs_driver"] = 1
        if s.get("is_own_process"):
            proc["svc_is_own_process"] = 1
        if s.get("is_shared_process"):
            proc["svc_is_shared_process"] = 1

        state = (s.get("state") or "").upper()
        if state == "SERVICE_RUNNING":
            proc["svc_is_running"] = 1

    # ---------------- done ----------------
    # Return as a list of process feature dicts
    return list(processes.values())
