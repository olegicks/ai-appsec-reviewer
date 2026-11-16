import base64
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/session")
def load_session():
    raw = base64.b64decode(request.cookies["session"])
    return pickle.loads(raw)
