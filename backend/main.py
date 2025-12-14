# main.py
from pathlib import Path
import yaml

from core.volatility_runner import run_plugin
from core.feature_image import image_features
from core.feature_process import process_features


def main():
    # 1) Load settings
    settings = yaml.safe_load(open("config/settings.yaml"))
    vol_path = settings["volatility_path"]
    dump_dir = Path("data/dumps/")
    dump_files = list(dump_dir.glob("*.mem"))

    if not dump_files:
        raise FileNotFoundError("No .mem files found in data/dumps/")

    dump_path = max(dump_files, key=lambda f: f.stat().st_mtime)
    print("Using newest file:", dump_path)  # your memory dump
    output_dir = Path(settings["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    plugins = settings["plugins"]

    all_parsed = {}

    print("=== STAGE 1: Running Volatility plugins ===")
    for plugin in plugins:
        print(f"[+] Running {plugin}...")
        out_json = output_dir / f"{plugin.split('.')[-1]}.json"
        parsed = run_plugin(vol_path, dump_path, plugin, out_json)
        all_parsed[plugin] = parsed

    print("=== STAGE 1 done: plugins run and parsed ===")

    # 2) STAGE 2: build image-level features
    print("\n=== STAGE 2: Building IMAGE-LEVEL features ===")
    img_feats = image_features(all_parsed)
    print("Image features:")
    for k, v in img_feats.items():
        print(f"  {k}: {v}")

    # optional: save to file
    (output_dir / "features_image.json").write_text(
        __import__("json").dumps(img_feats, indent=2),
        encoding="utf-8",
    )
    print(f"[+] Saved image-level features to {output_dir / 'features_image.json'}")

    # 3) STAGE 3: build PROCESS-LEVEL features
    print("\n=== STAGE 3: Building PROCESS-LEVEL features ===")
    proc_feats = process_features(all_parsed)
    print(f"Found {len(proc_feats)} processes")
    for row in proc_feats[:5]:  # just first 5 to not spam
        print(row)

    # optional: save to CSV
    try:
        import pandas as pd
        df = pd.DataFrame(proc_feats)
        df.to_csv(output_dir / "features_process.csv", index=False)
        print(f"[+] Saved process-level features to {output_dir / 'features_process.csv'}")
    except ImportError:
        print("[!] pandas not installed, skipping CSV export")


if __name__ == "__main__":
    main()
