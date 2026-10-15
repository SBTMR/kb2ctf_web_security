import json
import os
import secrets
from pathlib import Path
from subprocess import DEVNULL, run
from flask import Flask, jsonify, render_template, request, session
from flask import jsonify

ROOT = Path(__file__).resolve().parent
app = Flask(__name__)

def read_flag():
    return 'KB2CTF{blind_rce_demo}'

@app.get('/healthz')
def health():
    return jsonify(status='ready')

app.secret_key = 'kb2ctf_blind_demo_session_key_2026_only_for_local_training'
app.config['SESSION_COOKIE_NAME'] = 'kb2ctf_blind'
STATE_ROOT = Path(os.environ.get('STATE_DIR', '/var/lib/lab/state'))
STATE_ROOT.mkdir(parents=True, exist_ok=True)

def run_diagnostic(ip, marker):
    # Same original shell command as Pinger; stdout/stderr are hidden.
    run('ping %s -c 1' % ip, shell=True, stdout=DEVNULL, stderr=DEVNULL,
        env=dict(os.environ, LAB_MARKER_FILE=str(marker)))

@app.get('/')
def main():
    return render_template('index.html')

@app.post('/api/pinger')
def pinger():
    data = json.loads(request.data)
    if 'ip' not in data:
        return jsonify(message='The IP address was not specified')
    attempt = secrets.token_hex(16)
    directory = STATE_ROOT / attempt
    directory.mkdir()
    session['attempt'] = attempt
    run_diagnostic(data['ip'], directory / 'marker')
    return jsonify(message='bebebe pinged', attempt=attempt)

@app.get('/api/observation')
def observation():
    attempt = session.get('attempt')
    observed = bool(attempt and (STATE_ROOT / attempt / 'marker').is_file())
    return jsonify(attempt=attempt, observed=observed)
