import os
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

SERVICE_ID = os.getenv("SERVICE_ID", "unknown-service")

INFECTED = False
HOP_COUNT = 0
INFECT_COUNT = 0

@app.route("/hop", methods=["POST"])
def hop():
    global HOP_COUNT
    HOP_COUNT += 1

    caller_cn = request.headers.get("X-Client-CN", "unauthenticated")
    caller_dn = request.headers.get("X-Client-DN", "")

    return jsonify({
        "service": SERVICE_ID,
        "status": "OK",
        "infected": INFECTED,
        "hop_count": HOP_COUNT,
        "caller_cn": caller_cn,
        "caller_dn": caller_dn,
        "ts": time.time()
    }), 200


@app.route("/infect", methods=["POST"])
def infect():
    global INFECTED, INFECT_COUNT
    INFECTED = True
    INFECT_COUNT += 1

    caller_cn = request.headers.get("X-Client-CN", "unauthenticated")
    return jsonify({
        "service": SERVICE_ID,
        "status": "INFECTED",
        "infect_count": INFECT_COUNT,
        "caller_cn": caller_cn,
        "ts": time.time()
    }), 200


@app.route("/metrics", methods=["GET"])
def metrics():
    return jsonify({
        "service": SERVICE_ID,
        "infected": INFECTED,
        "hop_count": HOP_COUNT,
        "infect_count": INFECT_COUNT
    }), 200


@app.route("/reset", methods=["POST"])
def reset():
    global INFECTED, HOP_COUNT, INFECT_COUNT
    INFECTED = False
    HOP_COUNT = 0
    INFECT_COUNT = 0
    return jsonify({"service": SERVICE_ID, "status": "RESET"}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"service": SERVICE_ID, "status": "HEALTHY"}), 200
