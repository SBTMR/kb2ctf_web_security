import uuid
import pytest
pytestmark = pytest.mark.integration

@pytest.mark.parametrize('live_client', ['path-traversal'], indirect=True)
def test_storage_normal(live_client):
    client, base = live_client
    credentials = {'username':'storage-' + uuid.uuid4().hex[:12], 'password':'a'}
    assert client.post(base + '/register', data=credentials, allow_redirects=False, timeout=5).status_code == 302
    assert client.post(base + '/login', data=credentials, timeout=5).status_code == 200
    assert 'burger.jpg' in client.get(base + '/download', timeout=5).text
    text = b'normal storage fixture'
    assert client.post(base + '/upload', files={'file':('notes.txt',text,'text/plain')}, timeout=5).status_code == 200
    download = client.get(base + '/download', params={'filename':'notes.txt'}, timeout=5)
    assert download.content == text
    assert download.headers['Content-Type'].startswith('text/plain')
    assert download.headers['Content-Disposition'].startswith('inline;')
    assert client.post(base + '/logout', allow_redirects=False, timeout=5).status_code == 302
    assert client.get(base + '/download', allow_redirects=False, timeout=5).status_code == 302
