from flask import Flask, render_template, request, jsonify, redirect, session
import pymongo
from bson.objectid import ObjectId
import hashlib

app = Flask(__name__)
app.secret_key = "TESTING_123"

mongo_pass = "pass_here_123"
client = pymongo.MongoClient(f"mongodb://usr:{mongo_pass}@ip/")
db = client["pulse"]
users = db["users"]

def toHash(password):
    hash_object = hashlib.sha256()
    hash_object.update(password.encode())
    return hash_object.hexdigest()

def getEntryViaId(collection, id):
    entry = collection.find_one({"_id": ObjectId(id)})
    return entry

def idExist(collection, id):
    return id != None and id != "" and getEntryViaId(collection, id) != None

def collectionToList(collection):
    return list(collection.find({}))

def showError(message, redirect):
    #nuh uh rn
    return f"<h1>{message}</h1><p><a href='{redirect}'>Back</a></p>"

@app.route("/",methods=["GET"])
def index():
    return render_template("index.html")

# User management

@app.route("/login", methods=["GET", "POST"])
def login():
    if not request.method == "POST":
        return render_template("login.html")
    try:
        username = request.form.get('username')
        password = toHash(request.form.get('password'))
        user = users.find_one({"username": username})
    except:
        return showError(message="Unable to find user", redirect="/login")
    if user != None and user["password"] == password:
        session["id"] = str(user["_id"])
        return redirect("/")
    return showError(message="Invalid username or password", redirect="/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if not request.method == "POST":
        return render_template("register.html")
    try:
        username = request.form.get('username')
        password = toHash(request.form.get('password'))
    except:
        return showError(message="Invalid info sent", redirect="/register")

    if users.count_documents({"username": username}) > 0:
        return showError(message="Username already exists", redirect="/register")
    users.insert_one({"username": username, "password": password, "admin": False})
    return redirect("/login")

@app.route("/logout", methods=["GET"])
def logout():
    del session["id"]
    return redirect("/login")
