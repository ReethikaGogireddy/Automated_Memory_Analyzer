
# Automated Memory Analyzer

This project automates **Windows memory forensics** using Volatility 3, extracts structured features, classifies memory dumps as **Malware or Benign** using machine learning, and adds an offline **LLM assistant (Ollama)** for explaining results and identifying suspicious processes.


## 🚀 Features

* Runs key **Volatility 3** plugins automatically
* Cleans and normalizes plugin outputs into JSON
* Extracts **image-level** and **process-level** forensic features
* Uses a trained ML model to classify dumps as *Benign/Malware*
* Provides **SHAP explanations** for transparency
* Uses **Ollama (offline LLM)** for:

  * Natural-language explanations
  * Suspicious process identification
  * Simple forensic Q&A


## 📌 How It Works

1. **Place memory dump**
   Put `.mem` or `.raw` file in:

   ```
   data/dumps/
   ```

2. **Run analysis pipeline**

   ```bash
   python main.py
   ```

   Produces:

   * Cleaned JSON output
   * `features_image.json`
   * `features_process.json`

3. **Train ML model** (one time)

   ```bash
   python ml/train_image_level.py
   ```

4. **Predict malware vs benign**

   ```bash
   python ml/predict_image.py
   ```

5. **Explain the prediction (SHAP)**

   ```bash
   python ml/explain_shap.py
   ```

6. **LLM explanations (offline Ollama)**

   ```bash
   python ml/analyze_image.py
   ```

7. **LLM suspicious-process triage**

   ```bash
   python llm/triage_processes_ollama.py
   ```


## 📁 Project Structure

```
core/               → volatility + parsers + feature extraction
ml/                 → training, prediction, SHAP, LLM explainability
llm/                → Ollama integration and forensic chat
data/dumps/         → memory dumps
data/output/        → all generated outputs
config/settings.yaml
main.py
```


## ⚙ Requirements

* Python 3.9+
* Volatility 3
* Local Ollama installation
* Python packages:

  ```
  pip install pandas scikit-learn shap ollama joblib matplotlib
  ```


## 📝 License

MIT License.

