#!/usr/bin/env python3
"""
Simple Volatility 3 runner + timeline builder.

Usage:
  python backend\volatility_runner\extractor.py -i PATH_TO_IMAGE -o timeline.csv

By default the script will try to run the plugins: pslist, pstree, netscan
against the image using the repository's `volatility3/vol.py` (it resolves
the path relative to this file). It requests JSON output (-r json), parses
the result, extracts timestamps where possible, and writes a combined CSV.

Columns:
 - timestamp (ISO 8601 UTC or empty)
 - plugin
 - pid (if present)
 - name/process (if present)
 - extra (JSON dump of the whole row)

Notes:
 - The script uses only Python standard library.
 - It attempts multiple timestamp formats; some plugin rows may not contain timestamps.
 - If a plugin invocation fails, the script logs and continues.
"""

import argparse
import csv
import json
import subprocess
import sys
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# plugins to run (short names). Volatility will attempt the correct plugin for the image.
PLUGINS = ["pslist", "pstree", "netscan"]

# candidate keys that likely contain timestamps
TIMESTAMP_KEY_CANDIDATES = [
    "time",
    "timestamp",
    "create",
    "createtime",
    "create_time",
    "start",
    "starttime",
    "start_time",
    "exit_time",
    "exit",
    "recv_time",
    "last_time",
    "lastseen",
]


def find_vol_py() -> Path:
    """
    Resolve the vol.py in the repo: project-root/volatility3/vol.py
    (project root = two parents up from this file: backend/volatility_runner)
    """
    this = Path(__file__).resolve()
    repo_root = this.parents[2]
    vol_py = repo_root / "volatility3" / "vol.py"
    if not vol_py.exists():
        raise FileNotFoundError(f"vol.py not found at expected path: {vol_py}")
    return vol_py


def run_plugin(vol_py: Path, image: str, plugin: str, timeout: Optional[int] = 300) -> Optional[List[Dict[str, Any]]]:
    """
    Run volatility plugin with JSON renderer and return parsed JSON (list/dict).
    Returns None on failure.
    """
    cmd = [sys.executable, str(vol_py), "-f", str(image), plugin, "-r", "json"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout running {plugin}")
        return None

    stdout = proc.stdout.decode(errors="replace").strip()
    stderr = proc.stderr.decode(errors="replace").strip()

    if proc.returncode != 0:
        # Some plugin errors might still produce JSON; if stdout has JSON try to parse it.
        if not stdout:
            print(f"[!] Plugin {plugin} failed (return code {proc.returncode}). Stderr:\n{stderr}")
            return None

    if not stdout:
        print(f"[!] No output from plugin {plugin}. Stderr:\n{stderr}")
        return None

    try:
        parsed = json.loads(stdout)
    except Exception as e:
        # If JSON parsing fails, include helpful debug
        print(f"[!] Failed to parse JSON output for {plugin}: {e}")
        # show a snippet for debugging
        snippet = stdout[:1000].replace("\n", " ")
        print(f"[debug] stdout snippet: {snippet}")
        return None

    return parsed


def isoformat_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def try_parse_timestamp(value: Any) -> Optional[datetime]:
    """
    Try to convert a value into a datetime.
    - If value is int/float and looks like epoch seconds, use that.
    - If value is a string: try multiple common formats.
    - Return timezone-aware UTC datetime on success, otherwise None.
    """
    if value is None:
        return None

    # integers / floats -> epoch seconds
    if isinstance(value, (int, float)):
        try:
            # heuristic: timestamps > 1e9 are epoch seconds
            if value > 1e9:
                return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None

    if isinstance(value, str):
        s = value.strip()
        # Try ISO-like quick detection
        try:
            # Clean up "UTC" or trailing text
            s_clean = re.sub(r"\s+UTC$", "+00:00", s, flags=re.IGNORECASE)
            s_clean = s_clean.replace("Z", "+00:00") if s_clean.endswith("Z") else s_clean
            # Try fromisoformat (may fail for many formats)
            try:
                dt = datetime.fromisoformat(s_clean)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                pass

            # Try common strptime formats
            for fmt in (
                "%Y-%m-%d %H:%M:%S.%f %z",
                "%Y-%m-%d %H:%M:%S %z",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
            ):
                try:
                    dt = datetime.strptime(s_clean, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.astimezone(timezone.utc)
                except Exception:
                    continue

            # Try to extract epoch-like digits inside the string
            m = re.search(r"([12]\d{9,})", s)  # epoch seconds (10+ digits)
            if m:
                try:
                    sec = int(m.group(1))
                    return datetime.fromtimestamp(sec, tz=timezone.utc)
                except Exception:
                    pass

            # Try RFC 2822-ish
            try:
                from email.utils import parsedate_to_datetime
                dt = parsedate_to_datetime(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                pass

        except Exception:
            return None

    return None


def extract_timestamp_from_row(row: Dict[str, Any]) -> Optional[datetime]:
    """
    Search a JSON row for keys that may contain timestamps and attempt to parse them.
    Returns the first successfully parsed datetime or None.
    """
    # Flatten top-level simple keys first
    for key in row.keys():
        lower = key.lower()
        for candidate in TIMESTAMP_KEY_CANDIDATES:
            if candidate in lower:
                val = row.get(key)
                dt = try_parse_timestamp(val)
                if dt:
                    return dt

    # If not found, inspect nested dicts and lists shallowly
    for key, val in row.items():
        if isinstance(val, str) or isinstance(val, (int, float)):
            dt = try_parse_timestamp(val)
            if dt:
                return dt
        elif isinstance(val, dict):
            for subkey, subval in val.items():
                dt = try_parse_timestamp(subval)
                if dt:
                    return dt
        elif isinstance(val, list) and val:
            # check first element if primitive/dict
            first = val[0]
            if isinstance(first, (str, int, float)):
                dt = try_parse_timestamp(first)
                if dt:
                    return dt
            elif isinstance(first, dict):
                for subval in first.values():
                    dt = try_parse_timestamp(subval)
                    if dt:
                        return dt
    return None


def row_to_csv_records(plugin: str, entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert an entry to a CSV row dict with canonical columns.
    """
    # Common fields
    pid = entry.get("PID") or entry.get("pid") or entry.get("ProcessId") or entry.get("process_pid") or ""
    name = entry.get("Name") or entry.get("Process") or entry.get("ImageFileName") or entry.get("name") or ""
    ts_dt = extract_timestamp_from_row(entry)
    ts_iso = isoformat_utc(ts_dt) if ts_dt else ""
    extra = entry.copy()
    # Remove some big commonly-represented fields to keep "extra" readable?
    # Keep entire entry for now.
    return {
        "timestamp": ts_iso,
        "plugin": plugin,
        "pid": pid,
        "name": name,
        "extra": json.dumps(extra, ensure_ascii=False),
    }


def main():
    ap = argparse.ArgumentParser(description="Run volatility3 plugins and combine into a timeline CSV.")
    ap.add_argument("-i", "--image", required=True, help="Path to memory image")
    ap.add_argument("-o", "--output", default="timeline.csv", help="CSV output path")
    ap.add_argument("-p", "--plugins", nargs="+", help="Plugins to run (default: pslist pstree netscan)")
    ap.add_argument("--volpy", help="Path to vol.py (optional). If omitted, script uses repo's volatility3/vol.py")
    ap.add_argument("--timeout", type=int, default=300, help="Timeout seconds per plugin")
    args = ap.parse_args()

    image = args.image
    out_csv = args.output
    plugins = args.plugins or PLUGINS

    try:
        vol_py = Path(args.volpy) if args.volpy else find_vol_py()
    except Exception as e:
        print(f"[!] Could not locate vol.py: {e}")
        sys.exit(2)

    all_rows = []
    for plugin in plugins:
        print(f"[+] Running plugin: {plugin}")
        parsed = run_plugin(vol_py, image, plugin, timeout=args.timeout)
        if parsed is None:
            print(f"[!] Skipping plugin {plugin} due to failure or empty output.")
            continue

        # parsed may be a list, or a dict (some renderers), try to normalize to iterable rows
        rows = []
        if isinstance(parsed, list):
            rows = parsed
        elif isinstance(parsed, dict):
            # Some outputs contain {"rows": [...]} or similar
            if "rows" in parsed and isinstance(parsed["rows"], list):
                rows = parsed["rows"]
            else:
                # treat dict as single row
                rows = [parsed]
        else:
            print(f"[!] Unexpected JSON type for plugin {plugin}: {type(parsed)}")
            continue

        for entry in rows:
            if not isinstance(entry, dict):
                # If rows are lists/tuples, try to convert to dict by index (skip)
                continue
            rec = row_to_csv_records(plugin, entry)
            all_rows.append(rec)

    # sort by timestamp where present; empty timestamps go after real ones
    def sort_key(r):
        return (r["timestamp"] == "", r["timestamp"])

    all_rows.sort(key=sort_key)

    fieldnames = ["timestamp", "plugin", "pid", "name", "extra"]
    print(f"[+] Writing {len(all_rows)} rows to {out_csv}")
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in all_rows:
            writer.writerow(r)

    print("[+] Done.")


if __name__ == "__main__":
    main()