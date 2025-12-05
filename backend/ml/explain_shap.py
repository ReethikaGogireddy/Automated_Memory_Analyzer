from pathlib import Path
import json

import joblib
import pandas as pd
import shap


MODEL_PATH = Path("/Users/reethika/Projects/Automated_Memory_Analyzer/backend/ml/image_model.joblib")
CSV_PATH = Path("/Users/reethika/Projects/Automated_Memory_Analyzer/backend/ml/Obfuscated-MalMem2022.csv")
FEATURE_JSON_PATH = Path("/Users/reethika/Projects/Automated_Memory_Analyzer/backend/data/raw_outputs/features_image.json")


def load_model():
    bundle = joblib.load(MODEL_PATH)
    return bundle["model"], bundle["features"]


def load_background(feature_names, n_background=500):
    df = pd.read_csv(CSV_PATH)
    X = df.drop(columns=["Class", "Category"], errors="ignore")
    X = X[feature_names]

    if len(X) > n_background:
        X = X.sample(n_background, random_state=42)
    return X


def load_sample(feature_names):
    with open(FEATURE_JSON_PATH) as f:
        feat_dict = json.load(f)

    row = [feat_dict.get(name, 0.0) for name in feature_names]
    X = pd.DataFrame([row], columns=feature_names)
    return X, feat_dict


def main():
    model, feature_names = load_model()
    background_X = load_background(feature_names)
    X_sample, _ = load_sample(feature_names)

    # Use unified API
    explainer = shap.Explainer(model, background_X)
    shap_values = explainer(X_sample)

    # Extract SHAP values for the one sample
    malware_shap = shap_values.values[0]

    # SHAP sometimes returns shape (n_features, 1)
    # We flatten it to (n_features,)
    if hasattr(malware_shap, "shape") and len(malware_shap.shape) > 1:
        malware_shap = malware_shap.flatten()

    # Pair each feature name with its SHAP value
    contributions = list(zip(feature_names, malware_shap))

    # Sort by magnitude
    contributions_sorted = sorted(
        contributions,
        key=lambda x: abs(x[1]),
        reverse=True
    )

    print("\nTop SHAP contributions for this dump:")
    for name, val in contributions_sorted[:15]:
        print(f"{name:40s} SHAP = {val:+.4f}")



if __name__ == "__main__":
    main()