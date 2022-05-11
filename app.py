import os
# os.urandom(24)

from flask_jwt import JWT, jwt_required
from flask_jwt_extended import get_jwt_identity
from flask import Flask, jsonify, request, make_response
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from models import User, db, connect_db

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ['DATABASE_URL'].replace("postgres://", "postgresql://"))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

toolbar = DebugToolbarExtension(app)

connect_db(app)


def identity(payload):
    username = payload['identity']
    return User.get(username, None)


##### USER SIGN UP AND LOGIN #####

@app.route('/signup', methods=["POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Return Token.

    If the there already is a user with that username: return False
    """
    try:
        user = User.signup(
            username=request.json["username"],
            password=request.json["password"],
            first_name=request.json["first_name"],
            last_name=request.json["last_name"],
            email=request.json["email"],
            location=request.json["location"]
        )
        print("user", user.username)
        db.session.commit()

    # Return a better error message!!!
    except IntegrityError:
        return (jsonify({"error": "Duplicate Username/Email"}), 400)


    if user.username:
        token = user.encode_auth_token(user.username)
        serialized = user.serialize_token(token)

        return (jsonify(serialized), 201)

@app.route('/login', methods=["POST"])
def login():
    """ Handle user login and return a token """

    user = User.login(
        username=request.json["username"],
        password=request.json["password"]
    )


    if user:
        token = user.encode_auth_token(user.username)
        serialized = user.serialize_token(token)

        return (jsonify(serialized), 200)

    else:
        return (jsonify({"error": "Invalid Username/Password"}), 400)

##############################################################################
# General user routes:

@app.get('/users/<username>')
def getUser(username):
    """ Get information about a user --> details, matches, rejects"""
    try:
        token = request.headers["token"]

        token_username = User.decode_auth_token(token)

        print("TOKEN USERNAME", token_username, "username", username)

        if username == token_username:
            user = User.query.get_or_404(username)
            serialized = user.serialize

            return (jsonify(serialized), 200)

    except KeyError:
        return (jsonify({"error": "Unauthorized. No token provided."}), 401)

    return "hi"