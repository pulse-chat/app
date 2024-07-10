from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
import json
import time
import hashlib
import jwt

app = Flask(__name__)
CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
secret_key = "very_important_and_secret_key"

# Load users and clubs from data.json
try:
    with open("data.json", "r") as file:
        data = json.load(file)
except (FileNotFoundError, ValueError):
    data = {"users": {}, "clubs": []}

# Helper functions
def generate_token(myid):
    payload = {
        'exp': time.time() + 1800,
        'gen': time.time(),
        'myid': myid
    }
    return jwt.encode(payload, secret_key, algorithm='HS256')

def validate_token(myid, token):
    try:
        decoded_token = jwt.decode(token, secret_key, algorithms='HS256')
        curr_time = time.time()
        if float(decoded_token["exp"]) <= curr_time or int(decoded_token["myid"]) != myid:
            return 401
        return 200
    except jwt.ExpiredSignatureError:
        return 401
    except jwt.InvalidTokenError:
        return 401

# Routes
@app.route("/register", methods=["POST"])
@cross_origin()
def register():
    req_data = request.get_json()
    username = req_data["username"]
    email = req_data["email"]
    password = req_data["password"]

    hash_object = hashlib.sha256()
    hash_object.update(password.encode())
    hash_password = hash_object.hexdigest()

    data["users"][username] = {
        "email": email,
        "password": hash_password,
        "decks": {"Japanese": [{"front": "Hello", "back": "World"}, {"front": "Foo", "back": "Bar"}, {"front": "Front", "back": "Back"}],
                  "French": [{"front": "Bonjour", "back": "World"}, {"front": "Goodies", "back": "Bar"}, {"front": "Frontier", "back": "Back"}],
                  "Bulgarian": [{"front": "Zdrasti", "back": "Svqt"}, {"front": "Bla", "back": "Bar"}, {"front": "Otpred", "back": "Otzad"}]},
        "description": ""
    }

    with open("data.json", "w") as file:
        json.dump(data, file)

    return jsonify(list(data["users"].keys()))

@app.route("/login", methods=["POST"])
@cross_origin()
def login():
    req_data = request.get_json()
    username = req_data["username"]
    password = req_data["password"]

    if username not in data["users"]:
        return "Username not found", 401

    user = data["users"][username]
    hash_object = hashlib.sha256()
    hash_object.update(password.encode())
    hash_password = hash_object.hexdigest()

    if hash_password != user["password"]:
        return "Incorrect password", 401

    myid = list(data["users"].keys()).index(username)
    return jsonify({"token": generate_token(myid), "myid": myid})

@app.route("/regenerate_token", methods=["POST"])
@cross_origin()
def regenerate_token():
    req_data = request.get_json()
    myid = req_data.get("myid")
    token = req_data.get("token")

    if myid is None:
        return "myid is missing in the request", 400

    try:
        myid = int(myid)
    except ValueError:
        return "myid must be an integer", 400

    if token is None:
        return "token is missing in the request", 400

    valid_code = validate_token(myid, token)
    if valid_code != 200:
        return "Invalid token or myid", valid_code

    return jsonify({"token": generate_token(myid), "myid": myid})

@app.route("/send_message", methods=["POST"])
@cross_origin()
def send_message():
    req_data = request.get_json()
    myid = int(req_data["myid"])
    clubname = req_data["clubname"]
    message = req_data["message"]
    token = req_data.get("token")

    if token is None:
        return "Token cannot be found", 401

    valid_code = validate_token(myid, token)
    if valid_code != 200:
        return "Invalid token or myid", valid_code

    if clubname not in data["clubs"]:
        return "Club not found", 404

    if "messages" not in data:
        data["messages"] = []

    timestamp = time.time()
    data["messages"].append({"myid": myid, "clubname": clubname, "message": message, "timestamp": timestamp})

    with open("data.json", "w") as file:
        json.dump(data, file)

    return jsonify({"myid": myid, "message": message, "timestamp": timestamp})

@app.route("/get_message", methods=["POST"])
@cross_origin()
def get_message():
    req_data = request.get_json()
    clubname = req_data["clubname"]
    last_msg_ts = float(req_data["last_msg_ts"])
    myid = int(req_data["myid"])
    token = req_data.get("token")

    if token is None:
        return "Token cannot be found", 401

    valid_code = validate_token(myid, token)
    if valid_code != 200:
        return "Invalid token or myid", valid_code

    if clubname not in data["clubs"]:
        return "Club not found", 404

    messages = data.get("messages", [])
    new_messages = [msg for msg in messages if msg["clubname"] == clubname and msg["timestamp"] > last_msg_ts]

    return jsonify(new_messages)

@app.route("/get_clubs", methods=["GET"])
@cross_origin()
def get_clubs():
    return jsonify(data["clubs"])

@app.route("/create_club", methods=["POST"])
@cross_origin()
def create_club():
    req_data = request.get_json()
    clubname = req_data["clubname"]

    if clubname in data["clubs"]:
        return "Club already exists", 400

    data["clubs"].append(clubname)
    with open("data.json", "w") as file:
        json.dump(data, file)
    return jsonify(data["clubs"])

@app.route("/add_user_to_club", methods=["POST"])
@cross_origin()
def add_user_to_club():
    req_data = request.get_json()
    clubname = req_data["clubname"]
    myid = int(req_data["myid"])
    token = req_data.get("token")

    if token is None:
        return "Token cannot be found", 401

    valid_code = validate_token(myid, token)
    if valid_code != 200:
        return "Invalid token or myid", valid_code

    if clubname not in data["clubs"]:
        return "Club not found", 404

    user_key = list(data["users"].keys())[myid]
    data["users"][user_key].setdefault("hobbies", []).append(clubname)

    with open("data.json", "w") as file:
        json.dump(data, file)

    usr_dict = data["users"][user_key]
    usr_dict["username"] = user_key
    return jsonify(usr_dict)

@app.route("/add_description_to_user", methods=["POST"])
@cross_origin()
def add_description_to_user():
    req_data = request.get_json()
    myid = int(req_data["myid"])
    description = req_data["description"]
    token = req_data.get("token")

    if token is None:
        return "Token cannot be found", 401

    valid_code = validate_token(myid, token)
    if valid_code != 200:
        return "Invalid token or myid", valid_code

    user_key = list(data["users"].keys())[myid]
    data["users"][user_key]["description"] = description

    with open("data.json", "w") as file:
        json.dump(data, file)
    return jsonify(data["users"][user_key])

@app.route("/get_user", methods=["POST"])
@cross_origin()
def get_user():
    req_data = request.get_json()
    myid = int(req_data["myid"])
    user_key = list(data["users"].keys())[myid]
    usr_dict = data["users"][user_key]
    usr_dict["username"] = user_key
    return jsonify(usr_dict)

@app.route("/get_user_via_token", methods=["POST"])
@cross_origin()
def get_user_via_token():
    req_data = request.get_json()
    token = req_data.get("token")

    if token is None:
        return "Token cannot be found", 401

    try:
        decoded = jwt.decode(token, secret_key, algorithms='HS256')
    except jwt.ExpiredSignatureError:
        return "Token has expired", 401
    except jwt.InvalidTokenError:
        return "Invalid token", 401

    myid = int(decoded["myid"])
    user_key = list(data["users"].keys())[myid]
    usr_dict = data["users"][user_key]
    usr_dict["username"] = user_key
    return jsonify(usr_dict)

@app.route("/get_decks", methods=["POST"])
@cross_origin()
def get_decks():
    req_data = request.get_json()
    myid = int(req_data["myid"])
    token = req_data.get("token")

    if token is None:
        return "Token cannot be found", 401

    valid_code = validate_token(myid, token)
    if valid_code != 200:
        return "Invalid token or myid", valid_code

    user_key = list(data["users"].keys())[myid]
    return jsonify(data["users"][user_key]["decks"])

@app.route("/set_decks", methods=["POST"])
@cross_origin()
def set_decks():
    req_data = request.get_json()
    decks = req_data["decks"]
    myid = int(req_data["myid"])
    token = req_data.get("token")

    if token is None:
        return "Token cannot be found", 401

    valid_code = validate_token(myid, token)
    if valid_code != 200:
        return "Invalid token or myid", valid_code

    user_key = list(data["users"].keys())[myid]
    data["users"][user_key]["decks"] = decks

    with open("data.json", "w") as file:
        json.dump(data, file)
    return jsonify(data["users"][user_key]["decks"])

if __name__ == "__main__":
    app.run(host='0.0.0.0')
