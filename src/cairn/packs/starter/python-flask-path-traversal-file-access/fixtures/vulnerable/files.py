import os

from flask import Flask, request, send_file

app = Flask(__name__)
UPLOAD_DIR = "/srv/app/uploads"


@app.get("/download")
def download():
    name = request.args["name"]
    return send_file(os.path.join(UPLOAD_DIR, name))  # cairn-expect


@app.get("/notes/<path:note>")
def read_note(note):
    with open(f"/srv/app/notes/{request.args.get('dir', '')}/{note}") as fh:  # cairn-expect
        return fh.read()
