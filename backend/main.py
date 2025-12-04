from core.volatility_runner import run_plugin
from pathlib import Path
import yaml

def main():
    # Load config file
    settings = yaml.safe_load(open("config/settings.yaml"))

    vol_path = settings["volatility_path"]
    dump_path = Path("data/dumps/memorydump.mem")  # <--- THIS IS WHERE YOU PASS THE IMAGE
    output_dir = Path(settings["output_dir"])

    plugins = settings["plugins"]

    # Run each plugin
    for plugin in plugins:
        print(f"Running {plugin}...")
        output_file = output_dir / f"{plugin}.json"
        run_plugin(vol_path, dump_path, plugin, output_file)

if __name__ == "__main__":
    main()
