def test_homepage_and_original_route(app_loader):
    client = app_loader('headers').app.test_client()
    assert b'You want some flags?' in client.get('/').data
    response = client.get('/give_me_my_flag')
    assert response.status_code == 405 and 'FLAG' in response.headers['Allow']
    assert client.open('/give_me_my_flag', method='FLAG', json={}).json == {'bebebe':'no flags for you'}
    assert client.post('/give_me_my_flag', json={}).status_code == 405

def test_healthcheck_configuration(app_loader, monkeypatch, tmp_path):
    client = app_loader('headers').app.test_client()
    assert client.get('/healthz').status_code == 200
    monkeypatch.setenv('FLAG_FILE', str(tmp_path / 'missing'))
    assert client.get('/healthz').status_code == 503
