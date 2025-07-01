from flask import Flask, request, jsonify
from functools import wraps
import json, os, re, base64

app = Flask(__name__)
DB_FILE = "users.json"

# JSONファイル初期化
if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump({}, f)

# ユーザーデータ読み書き関数
def load_users():
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(DB_FILE, "w") as f:
        json.dump(users, f, ensure_ascii=False)

# バリデーション
def valid_user_id(uid):
    return re.fullmatch(r'[A-Za-z0-9]{6,20}', uid)

def valid_password(pw):
    return re.fullmatch(r'[!-~]{8,20}', pw)  # ASCII可視文字のみ

# Basic認証デコレータ
def require_auth(f):
    @wraps(f)
    def decorated(user_id, *args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return jsonify({"error": "Unauthorized"}), 401
        try:
            encoded = auth[6:]
            decoded = base64.b64decode(encoded).decode()
            uid, pw = decoded.split(":", 1)
        except:
            return jsonify({"error": "Invalid auth"}), 401

        users = load_users()
        if uid != user_id or uid not in users or users[uid]["password"] != pw:
            return jsonify({"error": "Invalid credentials"}), 403

        request.user_data = users[uid]
        request.auth_user = uid
        return f(user_id, *args, **kwargs)
    return decorated

# POST /signup
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    uid = data.get("user_id", "")
    pw = data.get("password", "")

    if not valid_user_id(uid):
        return jsonify({"error": "Invalid user_id"}), 400
    if not valid_password(pw):
        return jsonify({"error": "Invalid password"}), 400

    users = load_users()
    if uid in users:
        return jsonify({"error": "User exists"}), 409

    users[uid] = {"password": pw, "nickname": uid}
    save_users(users)

    return jsonify({
        "message": "Account success",
        "user": {"user_id": uid, "nickname": uid}
    }), 200

# GET /users/{user_id}
@app.route("/users/<user_id>", methods=["GET"])
@require_auth
def get_user(user_id):
    data = request.user_data
    result = {
        "user_id": user_id,
        "nickname": data.get("nickname", user_id)
    }
    if "comment" in data:
        result["comment"] = data["comment"]

    return jsonify({
        "message": "User details by",
        "user": result
    }), 200

# PATCH /users/{user_id}
@app.route("/users/<user_id>", methods=["PATCH"])
@require_auth
def patch_user(user_id):
    data = request.get_json()
    users = load_users()

    if user_id not in users:
        return jsonify({"error": "User not found"}), 404

    user = users[user_id]
    updated = {}

    if "nickname" in data:
        nickname = data["nickname"]
        user["nickname"] = nickname if nickname else user_id
        updated["nickname"] = user["nickname"]

    if "comment" in data:
        comment = data["comment"]
        if comment == "":
            user.pop("comment", None)
        else:
            user["comment"] = comment
        updated["comment"] = user.get("comment", "")

    save_users(users)

    return jsonify({
        "message": "User successful",
        "user": [updated]
    }), 200

# POST /close
@app.route("/close", methods=["POST"])
@require_auth
def delete_user(user_id):
    users = load_users()
    if user_id in users:
        del users[user_id]
        save_users(users)
        return jsonify({"message": "Account and data deleted"}), 200
    return jsonify({"error": "User not found"}), 404

if __name__ == '__main__':
    app.run()

if __name__ == '__main__':
    app.run(debug=True)
