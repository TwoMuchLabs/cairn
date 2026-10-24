from flask import Flask, request, send_file

app = Flask(__name__)


@app.get("/logo")
def logo():
    return send_file("/srv/app/static/logo.png")


@app.post("/feedback")
def feedback():
    with open("/srv/app/feedback.log", "a") as fh:
        fh.write(request.form.get("text", "") + "\n")
    return "thanks"
