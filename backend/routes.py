# backend/routes.py
import os
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename

bp = Blueprint("api", __name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "data", "dumps")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@bp.route("/api/upload", methods=["POST"])
def upload_file():
    try:
        # Check file field
        if "file" not in request.files:
            return jsonify({"message": "No file part in the request."}), 400

        file = request.files["file"]

        if file.filename == "":
            return jsonify({"message": "No file selected."}), 400

        filename = secure_filename(file.filename)

        save_path = os.path.join(UPLOAD_FOLDER, filename)
        print(f"[UPLOAD] Saving to: {save_path}")  # <--- log

        file.save(save_path)

        return jsonify({
            "message": "File uploaded successfully.",
            "filename": filename,
            "saved_to": f"data/dumps/{filename}",
        }), 200

    except Exception as e:
        # Log the full error in your server console
        import traceback
        traceback.print_exc()
        return jsonify({"message": f"Upload failed on server: {str(e)}"}), 500
