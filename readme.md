<div id="top"></div>


<!-- ABOUT THE PROJECT -->
# Friender - Find a friend now!
## Frontend: JavaScript - React
## Backend: Python - Flask - Postgres

<p>&nbsp;</p>

### Built With
* [JavaScript](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
* [Python](https://docs.python.org/3/)
* [React](https://reactjs.org/docs/getting-started.html)
* [Flask](https://flask.palletsprojects.com/en/2.1.x/)
* [Flask-SQLALchemy](https://flask-sqlalchemy.palletsprojects.com/en/2.x/)
* [Postgres](https://www.postgresql.org/docs/current/app-psql.html)


<!-- GETTING STARTED -->
## Getting Started

Friender is a full stack application that allows users to find a potential friend. Users will have the ability to match with each other and send private messages (work in progress).

<p>&nbsp;</p>

### Installation

After downloading the code from GitHub:

    $ pip3 install -r requirements.txt

    Installs all of the requirements for the backend

To start the React component of the application:

    $ npm start

To start the backend server:

    $ npm run start-api



<!-- Routes -->
## Routes

- /signup
- /login
- /users/<username>
- /users/<username>/lists
- /users/<username>/upload
- /users/<username>/match
- /users/<username>/reject


<p align="right">(<a href="#top">back to top</a>)</p>

<!-- Features -->
## Features

### AWS S3
- Images saved to Amazon S3 bucket and the URLs generated are saved in the database
### Flask JSON Web Tokens
- Checks for authorization and authentication
### PGEOCODE
- Determines distance between users for friend radius
### BCrypt
- One way encryption for user's passowrd
### SocketIO
- Chat feature between matched users (in progress)


<!-- ROADMAP -->
## Roadmap

Ideas for improving the current setup

- Creating a chat feature between users using SocketIO (in progress)
- Implementing routes to GET/POST requests for messaging


# Made by Austin Chao
*Pair programmed with [Melanie Wong](https://github.com/melawong)*

<p align="right">(<a href="#top">back to top</a>)</p>

