import os
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/hop", methods=["POST"])
def hop():
    zt = os.getenv("ZT_ENABLED", "false").lower() == "true"
    return jsonify({
        "status": "SUCCESS",
        "architecture": "Zero-Trust" if zt else "Legacy",
        "message": "Request accepted. (mTLS enforced at NGINX transport layer when ZT_ENABLED=true)"
    }), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "OK"}), 200
