import ipaddress
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = str(ipaddress.ip_address(request.args.get("host")))
    return subprocess.check_output(["ping", "-c", "1", host])
