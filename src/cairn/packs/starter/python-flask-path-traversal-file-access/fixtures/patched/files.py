import os

from flask import Flask, request, send_from_directory
from werkzeug.security import safe_join

app = Flask(__name__)
UPLOAD_DIR = "/srv/app/uploads"


@app.get("/download")
def download():
    name = request.args["name"]
    return send_from_directory(UPLOAD_DIR, name)


@app.get("/notes/<path:note>")
def read_note(note):
    path = safe_join("/srv/app/notes", request.args.get("dir", ""), note)
    if path is None:
        return "not found", 404
    with open(path) as fh:
        return fh.read()
