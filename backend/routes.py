# backend/routes.py
import os
import sys
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename

from ml.analyze_image import (
    run_analysis,
    build_ollama_explanation,
    FEATURE_JSON_PATH,
)
from llm.chat_memory_dump import answer_question 

# all endpoints in this file will be under /api/...
bp = Blueprint("api", __name__, url_prefix="/api")

BASE_DIR = Path(__file__).resolve().parent          # backend/
UPLOAD_FOLDER = BASE_DIR / "data" / "dumps"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# simple in-memory cache for latest analysis
LATEST_RESULT = None
LATEST_EXPLANATION = None

# for now we test with an existing features_image.json
TEST_MODE = False


@bp.route("/upload", methods=["POST"])
def upload_file():
    global LATEST_RESULT, LATEST_EXPLANATION

    try:
        if "file" not in request.files:
            return jsonify({"message": "No file part in the request."}), 400

        file = request.files["file"]

        if file.filename == "":
            return jsonify({"message": "No file selected."}), 400

        filename = secure_filename(file.filename)
        save_path = UPLOAD_FOLDER / filename
        print(f"[UPLOAD] Saving to: {save_path}")
        file.save(str(save_path))

        # -----------------------------
        # TEST MODE: use existing features_image.json
        # -----------------------------
        if TEST_MODE:
            print(f"[TEST_MODE] Using existing features file: {FEATURE_JSON_PATH}")
            if not FEATURE_JSON_PATH.exists():
                return jsonify({
                    "message": (
                        "Uploaded file OK, but features_image.json not found. "
                        "Cannot run test analysis."
                    ),
                }), 500

            try:
                LATEST_RESULT = run_analysis()
                LATEST_EXPLANATION = None  # reset; explanation recomputed on demand
                print("[TEST_MODE] Analysis result:", LATEST_RESULT)
            except Exception as e:
                import traceback
                traceback.print_exc()
                return jsonify({
                    "message": f"Analysis failed using existing features_image.json: {e}"
                }), 500

            return jsonify({
                "message": "UPLOAD OK — used existing features_image.json for testing",
                "filename": filename,
                "saved_to": f"data/dumps/{filename}",
            }), 200

        # -----------------------------
        # REAL MODE (when TEST_MODE = False)
        # -----------------------------
        # 1) Run main.py *right after* upload, using the newly saved file
        try:
            print(f"[REAL_MODE] Running main.py with dump: {save_path}")
            completed = subprocess.run(
                [sys.executable, "main.py", str(save_path)],
                capture_output=True,
                text=True,
                check=True,
            )
            print("[REAL_MODE] main.py stdout:\n", completed.stdout)
            if completed.stderr:
                print("[REAL_MODE] main.py stderr:\n", completed.stderr)
        except subprocess.CalledProcessError as e:
            print("[REAL_MODE] main.py failed:")
            print("STDOUT:", e.stdout)
            print("STDERR:", e.stderr)
            return jsonify({
                "message": "File uploaded, but main.py failed.",
                "error": e.stderr,
            }), 500

        # 2) (Optional) After main.py finishes, run your analysis
        if not FEATURE_JSON_PATH.exists():
            return jsonify({
                "message": (
                    "main.py finished, but features_image.json not found. "
                    "Cannot run analysis."
                )
            }), 500

        try:
            LATEST_RESULT = run_analysis()
            LATEST_EXPLANATION = None
            print("[REAL_MODE] Analysis result:", LATEST_RESULT)
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({
                "message": f"Analysis failed after running main.py: {e}"
            }), 500

        return jsonify({
            "message": "File uploaded and processed successfully.",
            "filename": filename,
            "saved_to": f"data/dumps/{filename}",
            "analysis_result": LATEST_RESULT,
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"message": f"Upload failed on server: {str(e)}"}), 500

def ensure_analysis():
    """
    Helper: if LATEST_RESULT is missing but features_image.json exists,
    run analysis once so /classification and /shap always have data.
    """
    global LATEST_RESULT, LATEST_EXPLANATION

    if LATEST_RESULT is not None:
        return

    if not FEATURE_JSON_PATH.exists():
        print("[ensure_analysis] features_image.json missing; cannot analyze.")
        return

    try:
        print("[ensure_analysis] Running analysis from features_image.json...")
        LATEST_RESULT = run_analysis()
        LATEST_EXPLANATION = None
        print("[ensure_analysis] Analysis result:", LATEST_RESULT)
    except Exception as e:
        import traceback
        traceback.print_exc()
        # leave LATEST_RESULT as None so routes return empty arrays
        print(f"[ensure_analysis] Analysis failed: {e}")


@bp.route("/classification", methods=["GET"])
def get_classification():
    ensure_analysis()

    if not LATEST_RESULT:
        # no analysis available
        return jsonify({"results": []}), 200

    return jsonify({
        "results": [
            {
                "label": LATEST_RESULT["label"],
                "score": LATEST_RESULT["probability_malware"],
            }
        ]
    })


@bp.route("/shap", methods=["GET"])
def get_shap():
    ensure_analysis()

    if not LATEST_RESULT:
        return jsonify({"values": []}), 200

    return jsonify({
        "values": LATEST_RESULT["shap"]  # list of {feature, value}
    })


@bp.route("/shap-explanation", methods=["GET"])
def get_shap_explanation():
    global LATEST_EXPLANATION

    ensure_analysis()

    if not LATEST_RESULT:
        return jsonify({
            "explanation": "No analysis available yet. Upload a dump first."
        }), 400

    if LATEST_EXPLANATION is None:
        LATEST_EXPLANATION = build_ollama_explanation(LATEST_RESULT)

    return jsonify({"explanation": LATEST_EXPLANATION})

@bp.route("/chat", methods=["POST"])
def chat_with_dump():
    """
    Simple chat endpoint used by the React ChatPage.
    Expects JSON: { "message": "<user text>" }
    Returns: { "reply": "<assistant text>" }
    """
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()

    if not message:
        return jsonify({"reply": "Please send a non-empty message."}), 400

    reply = answer_question(message)
    return jsonify({"reply": reply}), 200

