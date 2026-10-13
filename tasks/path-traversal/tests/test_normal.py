import io

def test_authenticated_storage_normal(app_loader):
    client = app_loader('path-traversal').app.test_client()
    assert client.get('/upload').status_code == 302
    assert client.post('/register', data={'username':'alice', 'password':'a'}).status_code == 302
    assert client.post('/login', data={'username':'alice', 'password':'wrong-password'}).status_code == 302
    assert client.post('/login', data={'username':'alice', 'password':'a'}).status_code == 302
    assert b'burger.jpg' in client.get('/download').data
    text = b'normal file'
    assert client.post('/upload', data={'file':(io.BytesIO(text),'заметка.txt')}).status_code == 302
    response = client.get('/download', query_string={'filename':'заметка.txt'})
    assert response.data == text and response.headers['Content-Disposition'].startswith('inline;')
    assert client.get('/download', query_string={'filename':'missing.txt'}).status_code == 302
    assert client.post('/upload').status_code == 302
    assert client.post('/logout').status_code == 302
    assert client.get('/download').status_code == 302

def test_duplicate_registration(app_loader):
    client = app_loader('path-traversal').app.test_client()
    data = {'username':'alice', 'password':'a'}
    assert client.post('/register', data=data).status_code == 302
    assert client.post('/register', data=data).status_code == 302
