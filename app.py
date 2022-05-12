import os
# os.urandom(24)
from flask import Flask, jsonify, request, make_response
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, current_user
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from models import User, db, connect_db, Match
from datetime import timedelta


app = Flask(__name__)

app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_SECRET_KEY"] = os.environ['SECRET_KEY']
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ['DATABASE_URL'].replace("postgres://", "postgresql://"))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

jwt = JWTManager(app)
toolbar = DebugToolbarExtension(app)

connect_db(app)


# def identity(payload):
#     username = payload['identity']
#     return User.get(username, None)

# Register a callback function that takes whatever object is passed in as the
# identity when creating JWTs and converts it to a JSON serializable format.
@jwt.user_identity_loader
def user_identity_lookup(user):
    print("user", user)
    return user

# Register a callback function that loads a user from your database whenever
# a protected route is accessed. This should return any python object on a
# successful lookup, or None if the lookup failed for any reason (for example
# if the user has been deleted from the database).
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(username=identity).one_or_none()



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
        access_token = create_access_token(identity=user.username)
        return (jsonify(access_token=access_token), 201)


@app.route('/login', methods=["POST"])
def login():
    """ Handle user login and return a token """

    user = User.login(
        username=request.json["username"],
        password=request.json["password"]
    )

    if user:
        access_token = create_access_token(identity=user.username)
        return (jsonify(access_token=access_token), 200)

    else:
        return (jsonify({"error": "Invalid Username/Password"}), 400)

##############################################################################
# General user routes:

@app.get('/users/<username>')
@jwt_required()
def getUser(username):

    # print(app.config, "CONFIG")
    curr_user = get_jwt_identity()
    print(curr_user)

    """ Get information about a user --> details, matches, rejects"""
    print("CURR USER", current_user)
    if curr_user == username:
        user = User.query.get_or_404(username)
        match = Match.query.filter_by(user=username)
        print(match)
        serialized = user.serialize_user()

        return (jsonify(serialized), 200)

    else:
        return (jsonify({"error": "Unauthorized. No token provided."}), 401)



