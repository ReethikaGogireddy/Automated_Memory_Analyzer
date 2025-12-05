# core/feature_image.py

from collections import Counter


def _safe_div(num, denom):
    return float(num) / float(denom) if denom else 0.0


def image_features(all_plugins: dict) -> dict:
    """
    Build a single feature vector (one row) for a memory image
    from all parsed plugin outputs in `all_plugins`.

    `all_plugins` is expected to look like:
      {
        "windows.pslist":     [...],
        "windows.dlllist":    [...],
        "windows.handles":    [...],
        "windows.malfind":    [...],
        "windows.psxview":    [...],
        "windows.ldrmodules": [...],
        "windows.svcscan":    [...],
        "windows.modules":    [...],
        "windows.callbacks":  [...],
      }
    """

    # Gracefully handle missing plugins
    ps   = all_plugins.get("windows.pslist")     or []
    dll  = all_plugins.get("windows.dlllist")    or []
    hnd  = all_plugins.get("windows.handles")    or []
    mf   = all_plugins.get("windows.malfind")    or []
    pv   = all_plugins.get("windows.psxview")    or []
    ldr  = all_plugins.get("windows.ldrmodules") or []
    svc  = all_plugins.get("windows.svcscan")    or []
    mods = all_plugins.get("windows.modules")    or []
    cbs  = all_plugins.get("windows.callbacks")  or []

    feats = {}

    # -------------------------------------------------
    # pslist.*  (process statistics)
    # -------------------------------------------------
    procs_with_pid = [p for p in ps if p.get("pid") is not None]
    nproc = len(procs_with_pid)
    feats["pslist.nproc"] = nproc

    feats["pslist.nppid"] = len(
        {p.get("ppid") for p in ps if p.get("ppid") is not None}
    )

    feats["pslist.avg_threads"] = _safe_div(
        sum(p.get("threads", 0) or 0 for p in ps), nproc
    )

    feats["pslist.avg_handlers"] = _safe_div(
        sum(p.get("handles", 0) or 0 for p in ps), nproc
    )

    # If you later add is_64bit / wow64 info to parse_pslist,
    # update this to count 64-bit procs. For now, default to 0.
    feats["pslist.nprocs64bit"] = 0

    # -------------------------------------------------
    # dlllist.* (loaded DLLs)
    # -------------------------------------------------
    ndlls = len(dll)
    feats["dlllist.ndlls"] = ndlls

    dll_pids = {d.get("pid") for d in dll if d.get("pid") is not None}
    n_dll_procs = len(dll_pids) or nproc
    feats["dlllist.avg_dlls_per_proc"] = _safe_div(ndlls, n_dll_procs)

    # -------------------------------------------------
    # handles.* (handle statistics)
    # -------------------------------------------------
    nhandles = len(hnd)
    feats["handles.nhandles"] = nhandles

    handle_pids = {h.get("pid") for h in hnd if h.get("pid") is not None}
    n_handle_procs = len(handle_pids) or nproc
    feats["handles.avg_handles_per_proc"] = _safe_div(nhandles, n_handle_procs)

    # Count handle types (File, Port, Event, etc.)
    type_counts = Counter((h.get("type") or "").lower() for h in hnd)

    feats["handles.nport"]       = type_counts.get("port", 0)
    feats["handles.nfile"]       = type_counts.get("file", 0)
    feats["handles.nevent"]      = type_counts.get("event", 0)
    feats["handles.ndesktop"]    = type_counts.get("desktop", 0)
    feats["handles.nkey"]        = type_counts.get("key", 0)
    feats["handles.nthread"]     = type_counts.get("thread", 0)
    feats["handles.ndirectory"]  = type_counts.get("directory", 0)
    feats["handles.nsemaphore"]  = type_counts.get("semaphore", 0)
    feats["handles.ntimer"]      = type_counts.get("timer", 0)
    feats["handles.nsection"]    = type_counts.get("section", 0)
    feats["handles.nmutant"]     = type_counts.get("mutant", 0)

    # -------------------------------------------------
    # ldrmodules.* (anomalous module loading)
    # -------------------------------------------------
    not_in_load = sum(1 for m in ldr if m.get("in_load") is False)
    not_in_init = sum(1 for m in ldr if m.get("in_init") is False)
    not_in_mem  = sum(1 for m in ldr if m.get("in_mem")  is False)

    feats["ldrmodules.not_in_load"]      = not_in_load
    feats["ldrmodules.not_in_init"]      = not_in_init
    feats["ldrmodules.not_in_mem"]       = not_in_mem
    feats["ldrmodules.not_in_load_avg"]  = _safe_div(not_in_load, nproc)
    feats["ldrmodules.not_in_init_avg"]  = _safe_div(not_in_init, nproc)
    feats["ldrmodules.not_in_mem_avg"]   = _safe_div(not_in_mem, nproc)

    # -------------------------------------------------
    # malfind.* (injected/suspicious regions)
    # -------------------------------------------------
    ninj = len(mf)
    feats["malfind.ninjections"] = ninj
    feats["malfind.commitCharge"] = sum(
        m.get("commit_charge", 0) or 0 for m in mf
    )

    # Number of regions that are RWX/Executable+Writable
    feats["malfind.rwx_regions"] = sum(
        1
        for m in mf
        if "EXECUTE" in (m.get("protection") or "").upper()
        and "WRITE" in (m.get("protection") or "").upper()
    )

    # Count unique (pid, start) pairs as unique injections
    feats["malfind.uniqueInjections"] = len(
        {(m.get("pid"), m.get("start")) for m in mf}
    )

    # -------------------------------------------------
    # psxview.* (cross-view process hiding)
    # -------------------------------------------------
    def _count_false(key: str) -> int:
        return sum(1 for p in pv if key in p and p[key] is False)

    feats["psxview.not_in_pslist"]        = _count_false("pslist")
    feats["psxview.not_in_eprocess_pool"] = _count_false("eprocess_pool")
    feats["psxview.not_in_ethread_pool"]  = _count_false("ethread_pool")
    feats["psxview.not_in_pspcid_list"]   = _count_false("pspcid_list")
    feats["psxview.not_in_csrss_handles"] = _count_false("csrss_handles")
    feats["psxview.not_in_session"]       = _count_false("session")
    feats["psxview.not_in_deskthrd"]      = _count_false("deskthrd")

    feats["psxview.not_in_pslist_false_avg"]        = _safe_div(feats["psxview.not_in_pslist"], nproc)
    feats["psxview.not_in_eprocess_pool_false_avg"] = _safe_div(feats["psxview.not_in_eprocess_pool"], nproc)
    feats["psxview.not_in_ethread_pool_false_avg"]  = _safe_div(feats["psxview.not_in_ethread_pool"], nproc)
    feats["psxview.not_in_pspcid_list_false_avg"]   = _safe_div(feats["psxview.not_in_pspcid_list"], nproc)
    feats["psxview.not_in_csrss_handles_false_avg"] = _safe_div(feats["psxview.not_in_csrss_handles"], nproc)
    feats["psxview.not_in_session_false_avg"]       = _safe_div(feats["psxview.not_in_session"], nproc)
    feats["psxview.not_in_deskthrd_false_avg"]      = _safe_div(feats["psxview.not_in_deskthrd"], nproc)

    # -------------------------------------------------
    # modules.* (kernel module count)
    # -------------------------------------------------
    feats["modules.nmodules"] = len(mods)

    # -------------------------------------------------
    # svcscan.* (services & drivers)
    # -------------------------------------------------
    nsvc = len(svc)
    feats["svcscan.nservices"] = nsvc

    feats["svcscan.kernel_drivers"] = sum(
        1 for s in svc if s.get("is_kernel_driver")
    )
    feats["svcscan.fs_drivers"] = sum(
        1 for s in svc if s.get("is_fs_driver")
    )
    feats["svcscan.process_services"] = sum(
        1 for s in svc if s.get("is_own_process")
    )
    feats["svcscan.shared_process_services"] = sum(
        1 for s in svc if s.get("is_shared_process")
    )
    # You can refine this if you define "interactive" explicitly
    feats["svcscan.interactive_process_services"] = 0

    feats["svcscan.nactive"] = sum(
        1 for s in svc if (s.get("state") or "").upper() == "SERVICE_RUNNING"
    )

    # -------------------------------------------------
    # callbacks.* (kernel callbacks)
    # -------------------------------------------------
    feats["callbacks.ncallbacks"] = len(cbs)
    feats["callbacks.nanonymous"] = sum(
        1 for c in cbs if c.get("symbol") is None
    )
    feats["callbacks.ngeneric"] = sum(
        1
        for c in cbs
        if (c.get("module") or "").lower() in {"generic", "unknown"}
    )

    return feats
