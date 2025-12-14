

import json
import pandas as pd
from pathlib import Path
import joblib
import shap
import subprocess

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


def run_analysis():
    """
    Run prediction + SHAP and return a dict that the API can JSONify.
    Assumes FEATURES_JSON_PATH was created for the latest uploaded dump.
    """
    # Load features for this dump
    data = json.loads(FEATURE_JSON_PATH.read_text())

    # Load model
    model, feature_names = load_model()

    # Build ML input row
    row = [data.get(f, 0.0) for f in feature_names]
    X = pd.DataFrame([row], columns=feature_names)

    # Prediction
    proba = float(model.predict_proba(X)[0, 1])
    label_idx = int(model.predict(X)[0])
    label = "Malware" if label_idx == 1 else "Benign"

    # SHAP explanation
    background = load_background(feature_names)
    explainer = shap.Explainer(model, background)
    shap_values = explainer(X)

    shap_vec = shap_values.values[0].flatten()

    contributions = sorted(
        zip(feature_names, shap_vec),
        key=lambda x: abs(x[1]),
        reverse=True
    )[:15]

    # Convert to JSON-friendly structures
    shap_list = [
        {"feature": name, "value": float(val)}
        for name, val in contributions
    ]

    result = {
        "label": label,
        "probability_malware": proba,
        "shap": shap_list,
        "raw_contributions": contributions,  # for LLM prompt
    }
    return result


def build_ollama_explanation(result: dict) -> str:
    """
    Use Ollama to produce a natural-language explanation from the result dict.
    Returns a string (or a fallback message).
    """
    if not OLLAMA_AVAILABLE:
        return "(Ollama not installed — skipping LLM explanation.)"

    try:
        explanation_dict = {
            "label": result["label"],
            "probability_malware": result["probability_malware"],
            "top_features": result["raw_contributions"],
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
           - how it influenced the system's behavior
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
        return resp["message"]["content"]

    except Exception as e:
        return f"(Ollama explanation unavailable: {e})"