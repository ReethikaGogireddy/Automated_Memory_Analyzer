# backend/app.py
from flask import Flask
from routes import bp as api_bp
from flask_cors import CORS

app = Flask(__name__)

# For dev: allow all origins
CORS(app)  # or CORS(app, origins=["http://localhost:5173"])

app.register_blueprint(api_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
