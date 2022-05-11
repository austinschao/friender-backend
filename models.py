
# from app import app
import os
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_jwt import JWT, jwt_required, current_identity
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

    user = db.Column(
        db.String(20),
        db.ForeignKey('users.username', ondelete="CASCADE"),
        primary_key=True,
    )

    match = db.Column(
        db.String(20),
        db.ForeignKey('users.username', ondelete="CASCADE"),
        primary_key=True,
    )


############## REJECT MODEL ###########################

class Reject(db.Model):
    """ Connection rejected user to user who rejected them. """

    __tablename__ = 'rejects'

    user = db.Column(
        db.String(20),
        db.ForeignKey('users.username', ondelete="CASCADE"),
        primary_key=True,
    )

    rejected = db.Column(
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

    sender = db.Column(
        db.String(20),
        db.ForeignKey('users.username', ondelete='CASCADE'),
        nullable=False,
    )

    receiver = db.Column(
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
                                primaryjoin=(Message.sender == username),
                                secondaryjoin=(Message.receiver == username),
                                order_by='Message.timestamp.desc()',
                                cascade="all,delete")

    messages_received = db.relationship('User',
                                secondary="messages",
                                primaryjoin=(Message.receiver == username),
                                secondaryjoin=(Message.sender == username),
                                order_by='Message.timestamp.desc()',
                                cascade="all,delete")


    match = db.relationship(
        "User",
        secondary="matches",
        primaryjoin=(Match.user == username),
        secondaryjoin=(Match.match == username)
    )

    rejects = db.relationship(
        "User",
        secondary="rejects",
        primaryjoin=(Reject.user == username),
        secondaryjoin=(Reject.rejected == username)
    )

    def __repr__(self):
        return f"<User {self.username}: {self.email}>"

    def serialize_token(self, token):
        """ Serialize to dictionary """

        return {
            "token": token
        }

    def serialize_user(self):
        """ Serialize user to dictionary"""
        return {
            "username" : self.username,
            "first_name" : self.first_name,
            "last_name" : self.last_name,
            "email" : self.email,
            "location" : self.location,
            "hobbies" : self.hobbies,
            "interests" : self.interests,
            "image_url" : self.image_url
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
            print("auth token , secret key", auth_token, os.environ['SECRET_KEY'])
            payload = jwt.decode(auth_token, os.environ['SECRET_KEY'])
            print("PAYLOAD", payload, payload['sub'])
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


