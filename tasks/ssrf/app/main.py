from flask import Flask, request, render_template, jsonify
import json
import requests

from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEV_ASSETS = ROOT.parents[2] / 'common' / 'ui' if len(ROOT.parents) > 2 else ROOT / 'static'
app = Flask(__name__, static_folder=str(DEV_ASSETS if DEV_ASSETS.exists() else ROOT / 'static'))


def create_resp(message: str) -> dict[str:str]:
    return jsonify({"message": message})

@app.route("/", methods=["GET"])
def flag():
    return render_template("index.html")

@app.route("/api/send", methods=['POST'])
def pinger():
    data = json.loads(request.data)
    if "url" not in data:
        return create_resp("The IP address was not specified")

    headers = {}
    if "headers" in data:
        headers = data["headers"]
    try:
        data = requests.get(data["url"], headers=headers).text
    except:
        return create_resp("bebebe")

    return create_resp(data)

@app.get('/healthz')
def health():
    return jsonify(status='ready')
