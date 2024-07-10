from flask import Flask, request, jsonify, render_template, send_from_directory, Blueprint
from flask_cors import CORS, cross_origin
import json
import time
import hashlib
import jwt
import os

app = Flask(__name__)
CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['TEMPLATES_AUTO_RELOAD'] = True
secret_key = "supersecretkey"

current_directory = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(current_directory, "data.json"), "r") as file:
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

# Blueprint for API routes
api = Blueprint('api', __name__, url_prefix='/api')

@api.route("/register", methods=["POST"])
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
        "description": ""
    }

    with open(os.path.join(current_directory, "data.json"), "w") as file:
        json.dump(data, file)

    return jsonify(list(data["users"].keys()))

@api.route("/login", methods=["POST"])
@cross_origin()
def login_user():
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

@api.route("/regenerate_token", methods=["POST"])
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

@api.route("/send_message", methods=["POST"])
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

    with open(os.path.join(current_directory, "data.json"), "w") as file:
        json.dump(data, file)

    return jsonify({"myid": myid, "message": message, "timestamp": timestamp})

@api.route("/get_message", methods=["POST"])
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

@api.route("/get_clubs", methods=["GET"])
@cross_origin()
def get_clubs():
    return jsonify(data["clubs"])

@api.route("/create_club", methods=["POST"])
@cross_origin()
def create_club():
    req_data = request.get_json()
    clubname = req_data["clubname"]

    if clubname in data["clubs"]:
        return "Club already exists", 400

    data["clubs"].append(clubname)
    with open(os.path.join(current_directory, "data.json"), "w") as file:
        json.dump(data, file)
    return jsonify(data["clubs"])

@api.route("/add_user_to_club", methods=["POST"])
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

    with open(os.path.join(current_directory, "data.json"), "w") as file:
        json.dump(data, file)

    usr_dict = data["users"][user_key]
    usr_dict["username"] = user_key
    return jsonify(usr_dict)

@api.route("/add_description_to_user", methods=["POST"])
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

    with open(os.path.join(current_directory, "data.json"), "w") as file:
        json.dump(data, file)
    return jsonify(data["users"][user_key])

@api.route("/get_user", methods=["POST"])
@cross_origin()
def get_user():
    req_data = request.get_json()
    myid = int(req_data["myid"])
    user_key = list(data["users"].keys())[myid]
    usr_dict = data["users"][user_key]
    usr_dict["username"] = user_key
    return jsonify(usr_dict)

@api.route("/get_user_via_token", methods=["POST"])
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

# Routes for rendering templates
@app.route('/', methods=['GET'])  # Define a route for the root URL
def render_home():
    return render_template('index.html')

@app.route('/login', methods=['GET'])
def render_login_template():
    return render_template('login.html')

@app.route('/register', methods=['GET'])
def render_register_template():
    return render_template('register.html')
    
# Serve static files (if needed)
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

# Run the application
if __name__ == "__main__":
    app.run(debug=True)
