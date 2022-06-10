import os
import click
from dotenv import load_dotenv
from numpy import broadcast
load_dotenv()

from time import localtime, strftime
from flask import Flask, jsonify, request, abort
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from models import User, db, connect_db, Match, Reject, Message, DEFAULT_PROFILE_PIC
from datetime import timedelta
from werkzeug.utils import secure_filename
import pgeocode
from aws_calls import upload_image_and_get_url, allowed_file
from flask_cors import CORS, cross_origin
# from flask.cli import AppGroup
# from twilio.jwt.access_token import AccessToken
# from twilio.jwt.access_token.grants import ChatGrant
# from twilio.rest import Client
# from twilio.base.exceptions import TwilioRestException


from flask_socketio import SocketIO, send, emit, join_room, leave_room

UPLOAD_FOLDER = './upload_folder'

# twilio_client = Client()

app = Flask(__name__)

# Create server using socket and fix cors errors
socketio = SocketIO(app, cors_allowed_origins="*")


CORS(app, resources={r"*": {"origins": "*"}})

app.config['CORS_HEADERS'] = ['Content-Type','Authorization']
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



################################################################################
# """ CHATROOM"""
# chatrooms_cli = AppGroup('chatrooms', help='Manage your chat rooms.')
# app.cli.add_command(chatrooms_cli)


# @chatrooms_cli.command('list', help='list all chat rooms')
# def list():
#     conversations = twilio_client.conversations.conversations.list()
#     for conversation in conversations:
#         print(f'{conversation.friendly_name} ({conversation.sid})')

# @chatrooms_cli.command('create', help='create a chat room')
# @click.argument('name')
# def create(name):
#     conversation = None
#     for conv in twilio_client.conversations.conversations.list():
#         if conv.friendly_name == name:
#             conversation = conv
#             break
#     if conversation is not None:
#         print('Chat room already exists')
#     else:
#         twilio_client.conversations.conversations.create(friendly_name=name)

# @chatrooms_cli.command('delete', help='delete a chat room')
# @click.argument('name')
# def delete(name):
#     conversation = None
#     for conv in twilio_client.conversations.conversations.list():
#         if conv.friendly_name == name:
#             conversation = conv
#             break
#     if conversation is None:
#         print('Chat room not found')
#     else:
#         conversation.delete()


################################################################################


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
@cross_origin()
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
            location=request.json["location"],
            friend_radius=int(request.json["friend_radius"]),
            hobbies=request.json["hobbies"],
            interests=request.json['interests']
        )

        db.session.commit()

    except IntegrityError:
        return (jsonify({"error": "Duplicate Username/Email"}), 400)


    if user.username:
        token = create_access_token(identity=user.username)
        return (jsonify(token=token), 201)


@app.route('/login', methods=["POST"])
@cross_origin()
def login():
    """ Handle user login and return a token """

    user = User.login(
        username=request.json["username"],
        password=request.json["password"]
    )

    if user:
        auth_token = create_access_token(identity=user.username)


        # # create the user (if it does not exist yet)
        # partipant_role_sid = None
        # for role in twilio_client.conversations.roles.list():
        #     if role.friendly_name == 'participant':
        #         participant_role_sid = role.sid
        # try:
        #     twilio_client.conversations.users.create(identity=user.username, role_sid=participant_role_sid)

        # except TwilioRestException as exc:
        #     if exc.status != 409:
        #         raise

        # # add the user to all the conversations
        # conversations = twilio_client.conversations.conversations.list()
        # for conversation in conversations:
        #     try:
        #         conversation.participants.create(identity=user.username)
        #     except TwilioRestException as exc:
        #         if exc.status != 409:
        #             raise

        # # generate an access token
        # twilio_account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
        # twilio_api_key_sid = os.environ.get('TWILIO_API_KEY_SID')
        # twilio_api_key_secret = os.environ.get('TWILIO_API_KEY_SECRET')
        # service_sid = conversations[0].chat_service_sid
        # twilio_token = AccessToken(twilio_account_sid, twilio_api_key_sid,
        #                     twilio_api_key_secret, identity=user.username)
        # twilio_token.add_grant(ChatGrant(service_sid=service_sid))

        # chatrooms = [[conversation.friendly_name, conversation.sid] for conversation in conversations]
        # breakpoint()

        #  chatrooms=chatrooms, twilio_token=twilio_token.to_jwt())
        return (jsonify(token=auth_token), 200)

    else:
        return (jsonify({"error": "Invalid Username/Password"}), 400)

##############################################################################
# General user routes:

@app.get('/users/<username>')
@cross_origin()
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
@cross_origin()
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
        potential_users_by_distance = [other_user.serialize_user() for other_user in potential_users if dist.query_postal_code(user.location, other_user.location) <= user.friend_radius]
        return (jsonify({"matched": matched_full, "potential_users": potential_users_by_distance  }), 200)

    else:
        return (jsonify({"error": "Unauthorized. "}), 401)

@app.route('/users/<username>/upload', methods=['POST'])
@cross_origin()
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

        print("FILE", file)
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
@cross_origin()
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
@cross_origin()
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
@cross_origin()
@jwt_required()
def updateUser(username):
    """ Updates a user's current info.
        first_name, last_name and email default to original if user tries
        to remove.
        profile_pic updates to default if user removes.
    """
    curr_user = get_jwt_identity()

    if curr_user == username:
        user = User.query.get_or_404(username)
        user.first_name = request.json["first_name"] or user.first_name,
        user.last_name = request.json["last_name"] or user.last_name,
        user.email = request.json["email"] or user.email,
        user.hobbies = request.json["hobbies"]
        user.interests = request.json["interests"]
        user.location = request.json["location"] or user.location
        user.friend_radius = int(request.json["friend_radius"]) or user.friend_radius


        db.session.commit()
        return (jsonify({"success": "user updated!"}), 200)

    else:
        return (jsonify({"error": "Unauthorized."}), 401)

@app.route('/users/<username>/messages', methods=["GET", "POST"])
@cross_origin()
@jwt_required
def user_messages(username):
    curr_user = get_jwt_identity()
    if curr_user == username:
        if request.method == "GET":
            return jsonify({"messages": ["test1", "test2", "test3"]})


    else:
        return (jsonify({"error": "Unauthorized"}), 401)

# ### delete user




################################################################################
""" SOCKET IO CHAT """
USERS = {}
ROOMS = ["test"]

@cross_origin()
@jwt_required()
@socketio.on('message')
def handleMessage(data):
    send({'message': data['message'], 'username': data['username'], 'room': data['room']})

# @cross_origin()
# @jwt_required()
# @socketio.on('connect')
# def send_room_name(ROOMS):


#     emit('room_name', ROOMS)


# @cross_origin()
# @jwt_required()
# @socketio.on('message from user', namespace="/messages")
# def receive_message_from_user(message):
#     print('USER MESSAGE: {}'.format(message))
#     print("HELLO")
#     emit('from flask', message.upper(), broadcast=True)
#     #emit?#

@cross_origin()
@jwt_required()
@socketio.on('username', namespace="/private")
def receive_username(payload):
    # USERS.append({username:request.sid})
    USERS[payload['username']] = request.sid
    #request.sid is the name of the room
    # USERS[payload['username']] = payload['token']
    emit('room_name', ROOMS, room=request.sid)
    print(f"\n\nUsername added!\n\n{USERS}\n\n")

@cross_origin()
@jwt_required()
@socketio.on('private_message', namespace='/private')
def private_message(payload):
    print("it reached server side private message")
    recipient_sid = USERS[payload['receiver']]
    print(payload['receiver'])
    message = f"{payload['sender']}: {payload['message']}"

    emit('new_private_message', message, room=recipient_sid)

@cross_origin()
@jwt_required()
@socketio.on('join')
def join(data):

    join_room(data['room'])
    # client joins room. Only people in the room will see messages
    send({'message': data['username'] + " joined the " + data['room'] + " room."}, room=data['room'])
    # Server sends a message to the all clients in the room that the user has joined

@cross_origin()
@jwt_required()
@socketio.on('leave')
def leave(data):

    leave_room(data['room'])
    send({'message': data['username'] + " left the " + data['room'] + " room."}, room=data['room'])


# Python assigns this name to file that is run in CLI
# File will be ran in CLI so statement will be true
if __name__ == 'main':
    socketio.run(app, debug=True)
    # debug=True will rest