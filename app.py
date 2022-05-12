import os
# os.urandom(24)
from flask import Flask, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from models import User, db, connect_db, Match, Reject, Message, DEFAULT_PROFILE_PIC
from datetime import timedelta
from werkzeug.utils import secure_filename
import pgeocode
from aws_calls import upload_image_and_get_url, allowed_file

UPLOAD_FOLDER = './upload_folder'

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
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000

jwt = JWTManager(app)
toolbar = DebugToolbarExtension(app)

dist = pgeocode.GeoDistance('us')


connect_db(app)



@jwt.user_identity_loader
def user_identity_lookup(user):
    """ Register a callback fn that takes whatever obj that is passed in
        as the identity when creating JWTs and converts it to a JSON
        serializable format """

    return user


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    """ Register a callback function that loads a user from your database
        whenever a protected route is accessed. This should return any python
        object on a successful lookup, or None if the lookup failed for any
        reason (for example if the user has been deleted from the database)."""

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
        token = create_access_token(identity=user.username)
        return (jsonify(token=token), 201)


@app.route('/login', methods=["POST"])
def login():
    """ Handle user login and return a token """

    user = User.login(
        username=request.json["username"],
        password=request.json["password"]
    )

    # breakpoint()

    if user:
        token = create_access_token(identity=user.username)
        return (jsonify(token=token), 200)

    else:
        return (jsonify({"error": "Invalid Username/Password"}), 400)

##############################################################################
# General user routes:

@app.get('/users/<username>')
@jwt_required()
def getUser(username):
    """ Get information about a user --> details, matches, rejects"""
    """ On mount, we will get a user
        Need their info, people they matched with, """

    curr_user = get_jwt_identity()

    if curr_user == username:
        user = User.query.get_or_404(username)
        match = Match.query.filter_by(user=username)
        serialized = user.serialize_user()

        return (jsonify(serialized), 200)

    else:
        return (jsonify({"error": "Unauthorized. Incorrect token."}), 401)

### get matches/hope_match/reject within radius
@app.get('/users/<username>/lists')
@jwt_required()
def getUserMatches(username):
    """ Gets a user lists of completed matches, hope to match, and rejected
        within given radius
    """
    curr_user = get_jwt_identity()

    if curr_user == username:
        user = User.query.get_or_404(username)

        # List of usernames curr user rejected
        rejects = [ user.username for user in user.rejects ]

        # List of users that curr user wants to match with
        match_users = [ user for user in user.matches ]

        # List of usernames that curr user is actually matched with
        matched = []
        matched_full = []

        # List of usernames that curr user wants to match with but has not matched them back
        match_requests = []


        # Checks if curr user is matched or still waiting for other to match back
        for other_user in match_users:
            if user in other_user.matches:
                matched.append(other_user.username)
                matched_full.append(other_user.serialize_user())
            else:
                match_requests.append(other_user.username)


        # List of all usernames that should not be shown to curr user
        not_shown_users = [*match_requests, *rejects, *matched, curr_user]

        # Potential list of all users
        potential_users = User.query.filter(User.username.not_in(not_shown_users)).all()

        # Potential list of all users within 100 mi converted to km
        potential_users_by_distance = [other_user.serialize_user() for other_user in potential_users if dist.query_postal_code(user.location, other_user.location) <= 161]
        return (jsonify({"matched": matched_full, "potential_users": potential_users_by_distance  }), 200)

    else:
        return (jsonify({"error": "Unauthorized. "}), 401)

@app.route('/users/<username>/upload', methods=['POST'])
@jwt_required()
def uploadPhoto(username):
    """ Uploads photo file to temp storage, then AWS, then deletes from
    temp storage, updates database with AWS url
    """

    curr_user = get_jwt_identity()
    if curr_user == username:
        user = User.query.get_or_404(username)

        if 'file' not in request.files:
            return (jsonify({"error": "No file found. "}), 400)

        file = request.files['file']
        if file.filename == "":
            return (jsonify({"error": "No filename found. "}), 400)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            url = upload_image_and_get_url(f"./upload_folder/{filename}", username)
            user.image_url = url

            db.session.commit()
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            return (jsonify({"success" : "user image added. "}), 200)
        else:
            return (jsonify({"error": "Invalid file type. "}), 400)

    else:
        return (jsonify({"error": "Unauthorized. "}), 401)


@app.post('/users/<username>/match')
@jwt_required()
def matchUser(username):
    """ Adds a user to current user's match list in database """

    curr_user = get_jwt_identity()

    if curr_user == username:
        user = User.query.get_or_404(username)
        match = User.query.get_or_404(request.json["username"])

        newMatch = Match(user=user.username,match=match.username)
        db.session.add(newMatch)
        db.session.commit()

        return (jsonify({"success": "match added!"}), 200)

    else:
        return (jsonify({"error": "Unauthorized."}), 401)

@app.post('/users/<username>/reject')
@jwt_required()
def rejectUser(username):
    """ Adds a user to current user's reject list in database """

    curr_user = get_jwt_identity()

    if curr_user == username:
        user = User.query.get_or_404(username)
        rejected = User.query.get_or_404(request.json["username"])

        newReject = Reject(user=user.username,rejected=rejected.username)
        db.session.add(newReject)
        db.session.commit()

        return (jsonify({"success": "reject added!"}), 200)

    else:
        return (jsonify({"error": "Unauthorized."}), 401)

@app.patch('/users/<username>')
@jwt_required()
def updateUser(username):
    """ Updates a user's current info.
        first_name, last_name and email default to original if user tries
        to remove.
        profile_pic updates to default if user removes.
    """



    curr_user = get_jwt_identity()

    if curr_user == username:
        breakpoint()
        user = User.query.get_or_404(username)
        user.first_name = request.json["first_name"] or user.first_name,
        user.last_name = request.json["last_name"] or user.last_name,
        user.email = request.json["email"] or user.email,
        # we need the url from aws

        user.image_url = request.json["image_url"] or DEFAULT_PROFILE_PIC,

        user.hobbies = request.json["hobbies"]
        user.interests = request.json["interests"]

        db.session.commit()
        return (jsonify({"success": "user updated!"}), 200)

    else:
        return (jsonify({"error": "Unauthorized."}), 401)

### post send a message

# @app.post('/users<username>/messages')
# @jwt_required()
# def addMessage(username):
#     """ Add a message """

#     curr_user = get_jwt_identity()

#     if curr_user == username:



# ### delete user
