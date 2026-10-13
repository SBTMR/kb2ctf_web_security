from types import SimpleNamespace
import requests

def test_original_sender_and_headers(app_loader, monkeypatch):
    module = app_loader('ssrf')
    calls = []
    def fetch(url, **kwargs):
        calls.append((url, kwargs)); return SimpleNamespace(text='normal sample page')
    monkeypatch.setattr(module.requests, 'get', fetch)
    client = module.app.test_client()
    response = client.post('/api/send', json={'url':'http://ssrf-sample:8080/', 'headers':{'Accept':'text/plain'}})
    assert response.json == {'message':'normal sample page'}
    assert calls == [('http://ssrf-sample:8080/', {'headers':{'Accept':'text/plain'}})]
    assert client.post('/api/send', json={}).json == {'message':'The IP address was not specified'}
    assert client.get('/api/send').status_code == 405

def test_fetch_failure_is_original_message(app_loader, monkeypatch):
    module = app_loader('ssrf')
    def fail(*args, **kwargs): raise requests.Timeout('fixture timeout')
    monkeypatch.setattr(module.requests, 'get', fail)
    response = module.app.test_client().post('/api/send', json={'url':'http://ssrf-sample:8080/'})
    assert response.status_code == 200 and response.json == {'message':'bebebe'}
