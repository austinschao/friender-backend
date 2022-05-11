
# from app import app
import os
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
# from flask_jwt import JWT, jwt_required, current_identity
import jwt
from datetime import datetime, timedelta

bcrypt = Bcrypt()
db = SQLAlchemy()


"""SQLAlchemy models for Friender."""
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

    ## Images?


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
    def authenticate(cls, username, password):
        """Find user with `username` and `password`.

        If can't find matching user (or if password is wrong), returns False.
        """

        user = cls.query.filter_by(username=username)

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


