# ml/predict_image.py

import joblib
import pandas as pd
from pathlib import Path

def load_model(model_path="/Users/reethika/Projects/Automated_Memory_Analyzer/backend/ml/image_model.joblib"):
    bundle = joblib.load(model_path)
    return bundle["model"], bundle["features"]

def predict_from_features(feature_dict, model, feature_names):
    """
    feature_dict: your big dict (one memory image)
    feature_names: list of columns the model was trained on
    """
    row = [feature_dict.get(name, 0.0) for name in feature_names]
    X = pd.DataFrame([row], columns=feature_names)

    # If the model supports predict_proba (RandomForest does)
    proba = model.predict_proba(X)[0, 1]
    label_idx = model.predict(X)[0]
    label = "Malware" if label_idx == 1 else "Benign"
    return label, float(proba)

if __name__ == "__main__":
    # Example: use your JSON file from the pipeline
    import json

    # This is where you saved image-level features in main.py
    feat_path = Path("/Users/reethika/Projects/Automated_Memory_Analyzer/backend/data/raw_outputs/features_image.json")
    with open(feat_path) as f:
        feature_dict = json.load(f)

    model, feature_names = load_model()
    label, proba = predict_from_features(feature_dict, model, feature_names)

    print(f"Prediction: {label} (P(malware) = {proba:.4f})")
