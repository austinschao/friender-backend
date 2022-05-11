
# from app import app
import os
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
# from flask_jwt import JWT, jwt_required, current_identity
import jwt
from datetime import datetime, timedelta

bcrypt = Bcrypt()
db = SQLAlchemy()

DEFAULT_PROFILE_PIC = "./static/images/default-pic.png"

"""SQLAlchemy models for Friender."""

############## MATCH MODEL ###########################

class Match(db.Model):
    """ Connection of two matched users to each other. """

    __tablename__ = 'matches'

    username_1_matching = db.Column(
        db.String(20),
        db.ForeignKey('users.username', ondelete="CASCADE"),
        primary_key=True,
    )

    username_2_matching = db.Column(
        db.String(20),
        db.ForeignKey('users.username', ondelete="CASCADE"),
        primary_key=True,
    )


############## REJECT MODEL ###########################

class Reject(db.Model):
    """ Connection rejected user to user who rejected them. """

    __tablename__ = 'rejects'

    user_rejecting = db.Column(
        db.String(20),
        db.ForeignKey('users.username', ondelete="CASCADE"),
        primary_key=True,
    )

    user_rejected = db.Column(
        db.String(20),
        db.ForeignKey('users.username', ondelete="CASCADE"),
        primary_key=True,
    )


############## MESSAGES MODEL ###########################

class Message(db.Model):
    """ Messages in the system. """

    __tablename__ = 'messages'

    id = db.Column(
         db.Integer,
        primary_key=True,
    )

    sender_username = db.Column(
        db.String(20),
        db.ForeignKey('users.username', ondelete='CASCADE'),
        nullable=False,
    )

    receiver_username = db.Column(
        db.String(20),
        db.ForeignKey('users.username', ondelete='CASCADE'),
        nullable=False,
    )

    text = db.Column(
        db.String(140),
        nullable=False,
    )

    timestamp = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )


    # user = db.relationship('User')

    def __repr__(self):
        return f"<Message #{self.id}: {self.text}, {self.timestamp}, {self.sender_username}, {self.receiver_username}>"



############## USER MODEL ###########################

class User(db.Model):
    """ User in the system. """

    __tablename__ = 'users'

    username = db.Column(
        db.String(20),
        primary_key=True
    )

    email = db.Column(
        db.Text,
        nullable=False,
        unique=True
    )

    first_name = db.Column(
        db.String(20),
        nullable=False,
    )

    last_name = db.Column(
        db.String(20),
        nullable=False,
    )

    password = db.Column(
        db.Text,
        nullable=False,
    )

    location = db.Column(
        db.Text,
        nullable=False
        # validator?
    )

    hobbies = db.Column(
        db.Text
    )

    interests = db.Column(
        db.Text,
    )

    image_url = db.Column(
        db.Text,
        default=DEFAULT_PROFILE_PIC
    )

    messages_sent = db.relationship('User',
                                secondary="messages",
                                primaryjoin=(Message.sender_username == username),
                                secondaryjoin=(Message.receiver_username == username),
                                order_by='Message.timestamp.desc()',
                                cascade="all,delete")

    messages_received = db.relationship('User',
                                secondary="messages",
                                primaryjoin=(Message.receiver_username == username),
                                secondaryjoin=(Message.sender_username == username),
                                order_by='Message.timestamp.desc()',
                                cascade="all,delete")

    # Matched?
    matches = db.relationship(
        "User",
        secondary="matches",
        primaryjoin=(Match.username_1_matching == username),
        secondaryjoin=(Match.username_2_matching == username)
    )


    #matches_sent
    # u1 -> u2
    # u2 -> u1

    #matches_received
    # u2 <- u1
    # u1 -> u2

    #if both match each other, add them to the matched table???





    rejects = db.relationship(
        "User",
        secondary="rejects",
        primaryjoin=(Reject.user_rejecting == username),
        secondaryjoin=(Reject.user_rejected == username)
    )

    def __repr__(self):
        return f"<User {self.username}: {self.email}>"

    def serialize_token(self, token):
        """ Serialize to dictionary """

        return {
            "token": token
        }

    @classmethod
    def signup(cls, username, first_name, last_name, email, password, location):
        """Sign up user.

        Hashes password and adds user to system.
        """

        hashed_pwd = bcrypt.generate_password_hash(password).decode('UTF-8')

        user = User(
            username=username,
            email=email,
            password=hashed_pwd,
            first_name=first_name,
            last_name=last_name,
            location=location
        )

        db.session.add(user)

        return user


    @classmethod
    def login(cls, username, password):
        """Find user with `username` and `password`.

        If can't find matching user (or if password is wrong), returns False.
        """

        user = cls.query.filter_by(username=username).first()


        if user:
            is_auth = bcrypt.check_password_hash(user.password, password)
            if is_auth:
                return user

        return False

    def encode_auth_token(self, username):
        """ Generates the Auth Token
            :return: string
        """

        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(days=0, minutes=60),
                'iat': datetime.utcnow(),
                'sub': username
            }
            return jwt.encode(
                payload,
                os.environ['SECRET_KEY'],
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Decodes the auth token
        :param auth_token:
        :return: integer|string
        """

        try:
            payload = jwt.decode(auth_token, os.environ['SECRET_KEY'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'




############################connect-db############################

def connect_db(app):
    """Connect this database to provided Flask app.

    You should call this in your Flask app.
    """

    db.app = app
    db.init_app(app)


