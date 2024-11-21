#!/usr/bin/env python3
"""Flask app"""
from flask import Flask, jsonify, Response

app = Flask(__name__)

@app.route("/")
def homr() -> Response:
    """Rout to home page"""
    message = {"message": "Bienvenue"}
    return jsonify(message)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
