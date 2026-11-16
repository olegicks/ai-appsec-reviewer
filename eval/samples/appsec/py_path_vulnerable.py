import os

from flask import Flask, request, send_file

app = Flask(__name__)
REPORTS = "/srv/reports"


@app.route("/report")
def report():
    name = request.args.get("file")
    return send_file(os.path.join(REPORTS, name))
