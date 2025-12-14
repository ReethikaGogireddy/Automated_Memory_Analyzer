# backend/app.py
from flask import Flask
from flask_cors import CORS
from routes import bp as api_bp   # your blueprint

app = Flask(__name__)

# EASIEST for dev: allow everything
CORS(app)  

# Or if you want to be stricter:
# CORS(app, resources={r"/api/*": {"origins": [
#     "http://localhost:5173",
#     "http://localhost:5174",
# ]}})

app.register_blueprint(api_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)