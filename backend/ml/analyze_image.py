# ml/analyze_image.py

import json
import pandas as pd
from pathlib import Path
import joblib
import shap

# Paths
MODEL_PATH = Path("/Users/reethika/Projects/Automated_Memory_Analyzer/backend/ml/image_model.joblib")
CSV_PATH = Path("/Users/reethika/Projects/Automated_Memory_Analyzer/backend/ml/Obfuscated-MalMem2022.csv")
FEATURE_JSON_PATH = Path("/Users/reethika/Projects/Automated_Memory_Analyzer/backend/data/raw_outputs/features_image.json")

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


def load_model():
    bundle = joblib.load(MODEL_PATH)
    return bundle["model"], bundle["features"]


def load_background(feature_names, n=300):
    df = pd.read_csv(CSV_PATH)
    X = df.drop(columns=["Class", "Category"], errors="ignore")
    X = X[feature_names]

    if len(X) > n:
        X = X.sample(n, random_state=42)

    return X


def analyze():
    # Load features for this dump
    data = json.loads(FEATURE_JSON_PATH.read_text())

    # Load model
    model, feature_names = load_model()

    # Build ML input row
    row = [data.get(f, 0.0) for f in feature_names]
    X = pd.DataFrame([row], columns=feature_names)

    # Prediction
    proba = model.predict_proba(X)[0, 1]
    label_idx = model.predict(X)[0]
    label = "Malware" if label_idx == 1 else "Benign"

    print(f"\nPrediction: {label} (P(malware)={proba:.4f})")

    # SHAP explanation
    background = load_background(feature_names)
    explainer = shap.Explainer(model, background)
    shap_values = explainer(X)

    shap_vec = shap_values.values[0]
    shap_vec = shap_vec.flatten()

    contributions = sorted(
        zip(feature_names, shap_vec),
        key=lambda x: abs(x[1]),
        reverse=True
    )[:15]

    print("\nTop SHAP features:")
    for name, val in contributions:
        direction = "→ Malware" if val > 0 else "→ Benign"
        print(f"{name:35s} SHAP={val:+.4f} {direction}")

    # Optional: Offline LLM explanation using Ollama
    if OLLAMA_AVAILABLE:
        try:
            explanation_dict = {
                "label": label,
                "probability_malware": float(proba),
                "top_features": contributions,
            }

            prompt = f"""
            You are a DFIR (Digital Forensics & Incident Response) analyst.

            You are given a machine-learning prediction and SHAP explanation for a Windows memory dump.

            Your task:
            1. Clearly explain why the dump was classified as {explanation_dict['label']}.
            2. Break down the TOP contributing features in simple terms.
            3. For each feature, explain:
            - what the feature measures
            - why its value is normal or suspicious
            - how it influenced the model's decision
            4. Provide an overall assessment in 2–3 sentences.
            5. KEEP THE LANGUAGE SIMPLE. Avoid jargon unless absolutely needed.
            6. DO NOT talk about "SHAP values" or "the model". Explain what the system behavior means in real-world terms.

            Here is the data:

            Prediction label: {explanation_dict['label']}
            Malware probability: {explanation_dict['probability_malware']}

            Top factors:
            {json.dumps(explanation_dict['top_features'], indent=2)}

            Now write a clear, beginner-friendly forensic explanation.
            """


            resp = ollama.chat(
                model="llama3",
                messages=[{"role": "user", "content": prompt}]
            )
            print("\nLLM Explanation:")
            print(resp["message"]["content"])

        except Exception as e:
            print("\nOllama explanation unavailable:", e)

    else:
        print("\n(Ollama not installed — skipping LLM explanation.)")


if __name__ == "__main__":
    analyze()
