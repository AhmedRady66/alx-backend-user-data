#!/usr/bin/env python3
"""Flask app"""
from flask import (Flask, jsonify, Response, request,
                   abort, make_response, redirect)
from auth import Auth
from typing import Optional, Tuple


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


@app.route("/sessions", methods=["POST"])
def login() -> Optional[Tuple]:
    """User Login"""
    try:
        if request.method == "POST":
            pure_email = request.form.get("email")
            email = pure_email.strip()
            pure_pass = request.form.get("password")
            password = pure_pass.strip()
            try:
                if not AUTH.valid_login(email, password):
                    abort(401)
                session_id = AUTH.create_session(email)
                message = {"email": email, "message": "logged in"}
                response = make_response(jsonify(message), 200)
                response.set_cookie("session_id", session_id)
                return response
            except ValueError:
                abort(401)
    except Exception:
        abort(401)


@app.route("/sessions", methods=["DELETE"])
def logout() -> Response:
    """Log out user"""
    if request.method == "DELETE":
        session_id = request.cookies.get("session_id", None)
        if session_id is None:
            abort(403)
        try:
            user = AUTH.get_user_from_session_id(session_id)
            if user:
                AUTH.destroy_session(user.id)
                return redirect("/")
        except Exception:
            abort(403)


@app.route("/profile")
def profile() -> Response:
    """User profile"""
    if request.method == "GET":
        try:
            session_id = request.cookies.get("session_id", None)
            if session_id is None:
                abort(403)
            try:
                user = AUTH.get_user_from_session_id(session_id)
                if user:
                    message = {"email": user.email}
                    response = jsonify(message)
                    return response
                else:
                    abort(403)
            except Exception:
                abort(403)
        except Exception:
            abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
