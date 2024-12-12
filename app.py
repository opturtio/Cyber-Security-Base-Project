from os import getenv
from flask import Flask
from dotenv import load_dotenv
import os

# Load .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = getenv("SECRET_KEY")

from backend import routes  # noqa: E402, F401

if __name__ == "__main__":
    app.run(debug=True)