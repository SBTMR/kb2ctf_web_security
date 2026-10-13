from flask import Flask, request, render_template, jsonify
from subprocess import run
import json
import os

from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEV_ASSETS = ROOT.parents[2] / 'common' / 'ui' if len(ROOT.parents) > 2 else ROOT / 'static'
app = Flask(__name__, static_folder=str(DEV_ASSETS if DEV_ASSETS.exists() else ROOT / 'static'))


def create_resp(message: str) -> dict[str:str]:
    return jsonify({"message": message})

@app.route("/")
def main():
    return render_template("index.html")

@app.route("/api/pinger", methods=['POST'])
def pinger():
    data = json.loads(request.data)
    if "ip" not in data:
        return create_resp("The IP address was not specified")

    data = run("ping %s -c 1" % data["ip"], capture_output=True, shell=True, text=True)
    if data.stderr:
        return create_resp(data.stderr)

    return create_resp(data.stdout)

def read_flag():
    return Path(os.environ.get('FLAG_FILE', '/run/lab/flag.txt')).read_text(encoding='utf-8').strip()

@app.get('/healthz')
def health():
    try:
        read_flag()
        return jsonify(status='ready')
    except OSError:
        return jsonify(status='unavailable'), 503
