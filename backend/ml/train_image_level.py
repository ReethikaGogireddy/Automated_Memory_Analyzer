# ml/train_image_level.py

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
from pathlib import Path

def main():
    # 1. Load your dataset
    csv_path = Path("/Users/reethika/Projects/Automated_Memory_Analyzer/backend/ml/Obfuscated-MalMem2022.csv")  # adjust path if needed
    df = pd.read_csv(csv_path)

    # 2. Separate features and labels
    # Assume columns: Category, Class, and all the feature columns
    y = df["Class"].map({"Benign": 0, "Malware": 1})
    X = df.drop(columns=["Class", "Category"], errors="ignore")

    feature_names = X.columns.tolist()
    print(f"Using {len(feature_names)} features")

    # 3. Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 4. Train a simple model (RandomForest as a good baseline)
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X_train, y_train)

    # 5. Evaluate
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))

    # 6. Save the model + feature order
    out_path = Path("ml/image_model.joblib")
    joblib.dump({"model": clf, "features": feature_names}, out_path)
    print(f"[+] Saved model to {out_path}")

if __name__ == "__main__":
    main()
