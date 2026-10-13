from subprocess import CompletedProcess

def test_original_ping_responses(app_loader, monkeypatch):
    module = app_loader('command-injection')
    monkeypatch.setattr(module, 'run', lambda *args, **kwargs: CompletedProcess(args, 0, 'Local diagnostic complete', ''))
    client = module.app.test_client()
    assert client.get('/').status_code == 200
    assert client.post('/api/pinger', json={'ip':'127.0.0.1'}).json == {'message':'Local diagnostic complete'}
    assert client.post('/api/pinger', json={}).json == {'message':'The IP address was not specified'}
    monkeypatch.setattr(module, 'run', lambda *args, **kwargs: CompletedProcess(args, 1, '', 'diagnostic error'))
    assert client.post('/api/pinger', json={'ip':'127.0.0.1'}).json == {'message':'diagnostic error'}
