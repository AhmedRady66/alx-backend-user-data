#!/usr/bin/env python3
"""Flask app"""
from flask import Flask, jsonify, Response, request
from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route("/")
def homr() -> Response:
    """Rout to home page"""
    message = {"message": "Bienvenue"}
    return jsonify(message)


@app.route("/users", methods=["POST"])
def users() -> Response:
    """Register user"""
    if request.method == "POST":
        pure_email = request.form.get("email")
        email = pure_email.strip()
        pure_pass = request.form.get("password")
        password = pure_pass.strip()
        try:
            AUTH.register_user(email, password)
            message = jsonify({"email": email, "message": "user created"})
            return message
        except Exception:
            return jsonify({"message": "email already registered"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
