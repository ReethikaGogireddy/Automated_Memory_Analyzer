# 🧠 MemSight - Automated Memory Artifact Analyzer 

An end-to-end forensic analysis system that automates **RAM/memory dump investigation** using **Volatility**, **Machine Learning**, and **LLM-assisted reasoning**.
The platform helps forensic analysts quickly identify **malicious memory artifacts**, understand **why** a dump is flagged, and interactively investigate suspicious processes.

## 🚀 Features

* 🔍 **Automated Memory Forensics**

  * Executes Volatility plugins on RAM dumps
  * Extracts process, DLL, handle, and memory artifacts
  * Normalizes outputs into structured JSON

* 🤖 **Machine Learning–Based Detection**

  * Random Forest classifier trained on memory artifact features
  * Detects anomalous / malicious memory dumps
  * High accuracy on benchmark datasets

* 📊 **Explainable AI (XAI)**

  * SHAP-based explanations
  * Visualizes which memory features influenced predictions

* 🧠 **LLM-Assisted Analysis**

  * Uses **Ollama** (local LLM)
  * Performs structured forensic reasoning
  * Enables interactive questioning of suspicious processes

* 🌐 **Web Application**

  * Flask backend REST API
  * React frontend for uploads, visualization, and chat-based analysis

## 🛠 Tech Stack

### Backend

* **Flask** (Python REST API)
* **Volatility** (Memory forensics framework)
* **scikit-learn** (Machine Learning)
* **SHAP** (Explainable AI)
* **Ollama** (Local LLM inference)

### Frontend

* **React**
* JavaScript / HTML / CSS

### ML & Data

* Feature extraction from memory artifacts
* Random Forest classifier
* CIC-MalMem-2022 dataset (training & evaluation)

## ⚙️ Installation & Setup

### 1️⃣ Backend Setup (Flask + ML + Volatility)

```bash
git clone https://github.com/your-username/automated-memory-analyzer.git
cd automated-memory-analyzer/backend

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Set environment variables:

```bash
export FLASK_APP=app.py
export FLASK_ENV=development
export OLLAMA_HOST=http://localhost:11434
```

Run backend:

```bash
flask run
```

### 2️⃣ Frontend Setup (React)

```bash
cd frontend
npm install
npm start
```

Access UI at:

```
http://localhost:3000
```

### 3️⃣ Ollama Setup (LLM)

1. Install Ollama from official website
2. Pull a model (example):

```bash
ollama pull llama3
```

3. Ensure Ollama is running:

```bash
ollama serve
```

## 🔄 Workflow

1. Upload a memory dump via the web interface
2. Volatility extracts forensic artifacts
3. ML model classifies dump as benign or malicious
4. SHAP explains the prediction
5. Ollama performs LLM-driven forensic reasoning
6. Analyst interacts with results through the chatbot that uses SHAP and Ollama

## 📊 Machine Learning Details

* **Model:** Random Forest Classifier
* **Features:**

  * Process metadata
  * DLLs loaded
  * Handles and memory structures
* **Explainability:** SHAP values per dump and per process
* **Performance:** ~85% accuracy on benchmark dataset


## ⚠️ Limitations

* Volatility output varies across OS profiles
* Model performance depends on dataset distribution
* Large memory dumps may require significant processing time
* LLM outputs are assistive, not authoritative


## 🔮 Future Enhancements

* Support for additional Volatility plugins
* Streaming and parallel memory analysis
* Ensemble ML models
* Advanced visualization dashboards
* Cloud-based deployment

## 📄 License

This project is licensed under the **MIT License**.
See the `LICENSE` file for details.


## ⭐ Acknowledgements

* Volatility Foundation
* CIC-MalMem-2022 Dataset
* SHAP (Lundberg & Lee)
* Ollama LLM framework
