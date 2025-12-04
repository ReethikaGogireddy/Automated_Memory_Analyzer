import subprocess
import json
import re

def parse_vol3_table(text: str):
    """Convert Volatility 3 table output to JSON."""
    lines = [l for l in text.splitlines() if l.strip()]

    # Skip banner lines
    while lines and (
        lines[0].startswith("Volatility")
        or lines[0].startswith("Progress")
    ):
        lines.pop(0)

    if not lines:
        return []

    headers = re.split(r"\s+", lines[0].strip())
    rows = []

    for line in lines[1:]:
        parts = re.split(r"\s+", line.strip(), maxsplit=len(headers) - 1)
        if len(parts) == len(headers):
            rows.append(dict(zip(headers, parts)))

    return rows


def run_plugin(vol_path, dump_path, plugin, output_file):
    result = subprocess.run(
        [vol_path, "-f", str(dump_path), plugin],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if result.returncode != 0:
        print(f"[ERROR] Failed running plugin: {plugin}")
        print(result.stderr)
        return

    raw_output = result.stdout

    # ---------- SAVE RAW OUTPUT ----------
    raw_output_file = str(output_file).replace(".json", "_raw.txt")
    with open(raw_output_file, "w", encoding="utf-8") as f:
        f.write(raw_output)

    print(f"[+] Raw output saved to {raw_output_file}")

    # ---------- PARSE INTO JSON ----------
    json_data = parse_vol3_table(raw_output)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)

    print(f"[+] Parsed JSON saved to {output_file}")
