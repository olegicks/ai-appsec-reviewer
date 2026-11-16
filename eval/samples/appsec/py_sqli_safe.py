import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    rows = conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
    return {"rows": rows}
