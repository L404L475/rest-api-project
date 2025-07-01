from flask import Flask, request, jsonify
from functools import wraps
import json
import os
import re
import base64

app = Flask(__name__)
DB_FILE = "users.json"

# --- JSONファイル操作 ---
def load_users():
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w") as f:
            json.dump({}, f)
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(DB_FILE, "w") as f:
        json.dump(users, f, ensure_ascii=False)

# --- バリデーション ---
def valid_user_id(user_id):
    return re.fullmatch(r"[A-Za-z0-9]{6,20}", user_id)

def valid_password(password):
    return re.fullmatch(r"[!-~]{8,20}", password)

# --- Basic認証デコレータ ---
def require_auth(f):
    @wraps(f)
    def decorated(user_id=None, *args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return jsonify({"message": "Authentication failed"}), 401

        try:
            encoded = auth[6:]
            decoded = base64.b64decode(encoded).decode()
            uid, pw = decoded.split(":", 1)
        except:
            return jsonify({"message": "Authentication failed"}), 401

        users = load_users()
        if uid not in users or users[uid]["password"] != pw:
            return jsonify({"message": "No permission for update"}), 403

        if user_id and uid != user_id:
            return jsonify({"message": "No permission for update"}), 403

        request.user_data = users[uid]
        return f(user_id, *args, **kwargs)
    return decorated

# --- POST /signup ---
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    user_id = data.get("user_id", "")
    password = data.get("password", "")

    if not valid_user_id(user_id) or not valid_password(password):
        return jsonify({"message": "Account creation failed"}), 400

    users = load_users()
    if user_id in users:
        return jsonify({"message": "Account creation failed"}), 409

    users[user_id] = {"password": password, "nickname": user_id}
    save_users(users)

    return jsonify({
        "message": "Account successfully created",
        "user": {
            "user_id": user_id,
            "nickname": user_id
        }
    }), 200

# --- GET /users/{user_id} ---
@app.route("/users/<user_id>", methods=["GET"])
@require_auth
def get_user(user_id):
    data = request.user_data
    user = {
        "user_id": user_id,
        "nickname": data.get("nickname", user_id)
    }
    if "comment" in data:
        user["comment"] = data["comment"]

    return jsonify({"message": "User details by", "user": user}), 200

# --- PATCH /users/{user_id} ---
@app.route("/users/<user_id>", methods=["PATCH"])
@require_auth
def patch_user(user_id):
    data = request.get_json()
    users = load_users()

    user = users[user_id]
    updated = {}

    if "nickname" in data:
        user["nickname"] = data["nickname"] or user_id
        updated["nickname"] = user["nickname"]

    if "comment" in data:
        if data["comment"] == "":
            user.pop("comment", None)
        else:
            user["comment"] = data["comment"]
        updated["comment"] = user.get("comment", "")

    save_users(users)
    return jsonify({"message": "User successfully updated", "user": [updated]}), 200

# --- POST /close ---
@app.route("/close", methods=["POST"])
@require_auth
def close_account(user_id):
    users = load_users()
    if user_id in users:
        del users[user_id]
        save_users(users)
        return jsonify({"message": "Account successfully deleted"}), 200
    return jsonify({"message": "Account deletion failed"}), 400

if __name__ == "__main__":
    app.run()
