import json
from pathlib import Path
import subprocess
import time
import uuid
import pytest

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]

def compose(*arguments, input_text=None):
    return subprocess.run(['docker','compose','-f','tasks/xss/compose.yaml',*arguments], cwd=ROOT,
                          input=input_text, text=True, capture_output=True, check=True).stdout

def heartbeat():
    return json.loads(compose('exec','-T','xss-bot','cat','/tmp/bot-state.json'))

def wait_for(predicate, seconds=25):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if predicate(): return
        except (OSError, ValueError, subprocess.CalledProcessError):
            pass
        time.sleep(1)
    raise AssertionError('Timed out waiting for the local lab fixture')

@pytest.mark.parametrize('live_client',['xss'],indirect=True)
def test_forum_normal_and_restart(live_client):
    client, base = live_client
    name = 'meme-' + uuid.uuid4().hex[:12]
    credentials = {'username':name,'password':'normal-password'}
    assert client.get(base+'/profile',allow_redirects=False,timeout=5).status_code == 302
    assert client.post(base+'/register',data=credentials,allow_redirects=False,timeout=5).status_code == 303
    response = client.post(base+'/login',data=credentials,allow_redirects=False,timeout=5)
    assert response.status_code == 303
    assert 'HttpOnly' not in response.headers['Set-Cookie']
    assert 'SameSite=Strict' in response.headers['Set-Cookie']
    assert 'KB2CTF{' not in client.get(base+'/profile',timeout=5).text
    created = client.post(base+'/posts',data={'memeId':'cat','caption':'<strong>Normal caption</strong>'},allow_redirects=False,timeout=5)
    assert created.status_code == 303
    post_id = created.headers['Location'].split('#post-')[1]
    assert client.post(base+'/posts/'+post_id+'/comments',data={'body':'<em>Normal comment</em>'},allow_redirects=False,timeout=5).status_code == 303
    html = client.get(base+'/',timeout=5).text
    assert '<strong>Normal caption</strong>' in html and '<em>Normal comment</em>' in html
    assert client.get(base+'/assets/memes/network-routing.png',timeout=5).status_code == 200
    compose('restart','xss')
    wait_for(lambda: client.get(base+'/healthz',timeout=2).status_code == 200)
    assert 'post-'+post_id in client.get(base+'/',timeout=5).text
    assert client.get(base+'/api/me',timeout=5).json()['username'] == name
    assert client.post(base+'/logout',allow_redirects=False,timeout=5).status_code == 303
    assert client.get(base+'/api/me',timeout=5).status_code == 401

def test_browser_sandbox_and_hook_network_fixture():
    script = (Path(__file__).parent/'browser-probe.mjs').read_text(encoding='utf-8')
    assert 'Sandbox and HTTP/WebSocket policy PASS' in compose('exec','-T','xss-bot','node','--input-type=module',input_text=script)

def test_persistent_bot_session_and_navigation_recovery():
    wait_for(lambda: heartbeat()['state'] == 'ready')
    before = heartbeat()
    wait_for(lambda: heartbeat()['visits'] >= before['visits'] + 2)
    steady = heartbeat()
    assert steady['generation'] == before['generation']
    assert steady['logins'] == before['logins']
    try:
        compose('stop','--timeout','2','xss')
        wait_for(lambda: heartbeat()['state'] == 'retrying', seconds=20)
    finally:
        compose('start','xss')
    wait_for(lambda: heartbeat()['state'] == 'ready' and heartbeat()['visits'] > steady['visits'])
    after = heartbeat()
    assert after['generation'] == before['generation']
    assert after['logins'] == before['logins']
