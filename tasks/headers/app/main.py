from flask import Flask, request, jsonify, render_template
import os
import json

from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEV_ASSETS = ROOT.parents[2] / 'common' / 'ui' if len(ROOT.parents) > 2 else ROOT / 'static'
app = Flask(__name__, static_folder=str(DEV_ASSETS if DEV_ASSETS.exists() else ROOT / 'static'))


@app.route('/')
def main():
    return render_template('index.html')

@app.route('/give_me_my_flag', methods=['FLAG'])
def give_me_my_flag():
    if request.headers.get('Flag-Header') != "I-am-real-flag-owner":
        return jsonify({"bebebe": "no flags for you"})

    try:
        data = json.loads(request.data)
    except:
        return jsonify({"bebebe": "no flags for you"})

    if "flags?" not in data:
        return jsonify({"bebebe": "no flags for you"})

    if type(data["flags?"]) != list:
        return jsonify({"bebebe": "no flags for you"})

    if len(data["flags?"]) != 2:
        return jsonify({"bebebe": "no flags for you"})

    for i in range(len(data["flags?"])):
        if data["flags?"][i] != f"trying to get flag {i+1} time":
            return jsonify({"bebebe": "no flags for you"})

    return jsonify({"here is your flag, little CTFer": read_flag()})

def read_flag():
    return Path(os.environ.get('FLAG_FILE', '/run/lab/flag.txt')).read_text(encoding='utf-8').strip()

@app.get('/healthz')
def health():
    try:
        read_flag()
        return jsonify(status='ready')
    except OSError:
        return jsonify(status='unavailable'), 503
