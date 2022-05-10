import os
os.urandom(24)

from flask_jwt import JWT, jwt_required, current_identity
from flask import Flask, request, flash, redirect
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from werkzeug.security import safe_str_cmp
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


@app.route('/signup', methods=["POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Return Token.

    If the there already is a user with that username: return False
    """

    try:
        user = User.signup(
            username=request.form.username.data,
            password=request.form.password.data,
            email=request.form.email.data,
            location=request.form.location.data
        )
        db.session.commit()

    except IntegrityError:
        return False


    # login(user)

        return token

    else:
        return False

