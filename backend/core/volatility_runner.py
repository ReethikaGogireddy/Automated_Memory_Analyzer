import subprocess
import json
from pathlib import Path
from .parsers import parse_vol3_table, PLUGIN_PARSERS


def run_plugin(vol_path, dump_path, plugin, output_file):
    result = subprocess.run(
        [vol_path, "-f", str(dump_path), plugin],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if result.returncode != 0:
        print(f"[ERROR] Plugin failed: {plugin}")
        print(result.stderr)
        return

    raw = result.stdout

    # Save raw text
    raw_file = output_file.with_suffix(".raw.txt")
    raw_file.write_text(raw, encoding="utf-8")

    # Parse table
    rows = parse_vol3_table(raw)

    # Plugin-specific parser
    parser = PLUGIN_PARSERS.get(plugin)
    if parser:
        parsed = parser(rows)
    else:
        parsed = rows

    # Save JSON
    with open(output_file, "w") as f:
        json.dump(parsed, f, indent=2)

    print(f"[OK] {plugin} → {output_file.name}")
    return parsed
