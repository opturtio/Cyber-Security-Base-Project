from os import getenv
from flask import Flask
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

from db import db
db.init_app(app)

from backend.routes import configure_routes
configure_routes(app)

if __name__ == "__main__":
    app.run(debug=True)