import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.post("/tools/ping")
def ping():
    host = request.form["host"]
    out = subprocess.run(["ping", "-c", "1", "--", host], capture_output=True, text=True)
    return out.stdout


@app.get("/tools/lookup")
def lookup():
    name = request.args.get("name", "")
    out = subprocess.run(["nslookup", "--", name], capture_output=True, text=True)
    return out.stdout
