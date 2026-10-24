import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.post("/tools/ping")
def ping():
    host = request.form["host"]
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)  # cairn-expect
    return out.stdout


@app.get("/tools/lookup")
def lookup():
    name = request.args.get("name", "")
    return os.popen("nslookup " + name).read()  # cairn-expect
