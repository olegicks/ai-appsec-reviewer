from flask import Flask, request, send_from_directory

app = Flask(__name__)
REPORTS = "/srv/reports"


@app.route("/report")
def report():
    name = request.args.get("file")
    return send_from_directory(REPORTS, name)
