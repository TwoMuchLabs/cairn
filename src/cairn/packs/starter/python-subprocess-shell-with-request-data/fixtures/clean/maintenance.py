import subprocess

from flask import Flask, request

app = Flask(__name__)


def rotate_logs():
    # Fixed command, no request data.
    subprocess.run("logrotate /etc/logrotate.d/app", shell=True, check=True)


@app.post("/reports")
def report():
    fmt = request.form.get("format", "pdf")
    subprocess.run(["render-report", "--format", fmt], check=True)
    return "queued"
