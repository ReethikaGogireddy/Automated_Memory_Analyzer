
import json
from pathlib import Path

import ollama
import pandas as pd  # make sure: pip install pandas

MODEL_NAME = "llama3"  # or the model you pulled

FEATURE_IMAGE = Path("/Users/reethika/Projects/Automated_Memory_Analyzer/backend/data/raw_outputs/features_image.json")
FEATURE_PROCESS_CSV = Path("/Users/reethika/Projects/Automated_Memory_Analyzer/backend/data/raw_outputs/features_process.csv")
EXPLANATION_FILE = Path("data/output/explanation_image.json")  # optional


def load_context():
    """Load image-level and process-level features from disk."""
    image_feats = {}
    if FEATURE_IMAGE.exists():
        text = FEATURE_IMAGE.read_text().strip()
        if text:
            image_feats = json.loads(text)

    process_feats = []
    if FEATURE_PROCESS_CSV.exists():
        df = pd.read_csv(FEATURE_PROCESS_CSV)
        process_feats = df.to_dict(orient="records")

    return image_feats, process_feats


def build_system_message(image, processes):
    """Build a system prompt that forces Ollama to talk about THIS dump."""
    # Limit number of processes to keep context manageable
    proc_sample = processes[:15]

    return {
        "role": "system",
        "content": f"""
You are a digital forensics (DFIR) assistant analyzing ONE SPECIFIC Windows memory dump.

You are given structured output already extracted from this dump:

1) IMAGE-LEVEL FEATURES (aggregated statistics for the entire dump):
{json.dumps(image, indent=2)}

2) PROCESS-LEVEL FEATURES (sample, one row per process, first {len(proc_sample)}):
{json.dumps(proc_sample, indent=2)}

These features include things like:
- counts of processes, DLLs, handles
- psxview anomalies (hidden/stealth processes)
- malfind results (injected memory regions)
- service and module statistics

IMPORTANT INSTRUCTIONS:
- ALWAYS answer about THIS memory dump only, using the data above.
- Do NOT give generic advice about "what a memory dump is".
- If the user asks "is the dump suspicious?", use these features to argue for or against malware.
- If the data is not enough to be certain, say so and suggest what a human analyst should check next.
- Use clear, simple forensic language.
"""
    }


def chat():
    image, processes = load_context()

    if not image and not processes:
        print("❌ No features found. Make sure your pipeline ran and wrote the feature files.")
        return

    system_msg = build_system_message(image, processes)

    history = [system_msg]
    print("🧠 Forensic Chat on Current Memory Dump")
    print("Type 'exit' to quit.\n")

    while True:
        user_msg = input("You: ").strip()
        if user_msg.lower() in ("exit", "quit"):
            break

        history.append({"role": "user", "content": user_msg})

        response = ollama.chat(
            model=MODEL_NAME,
            messages=history,
        )
        answer = response["message"]["content"].strip()
        print(f"\nAI: {answer}\n")

        history.append({"role": "assistant", "content": answer})


if __name__ == "__main__":
    chat()