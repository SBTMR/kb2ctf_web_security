import hashlib

class Rows:
    def __init__(self, rows): self.rows = rows
    def fetchone(self): return self.rows[0] if self.rows else None
    def fetchall(self): return self.rows

def test_account_flow_with_database_fixture(app_loader, monkeypatch):
    module = app_loader('sql-injection')
    password_hash = hashlib.sha256(b'a').hexdigest()
    def execute(query):
        if query.startswith('SELECT *') and 'AND password' in query:
            return Rows([(2, 'alice', password_hash)] if password_hash in query else [])
        if query.startswith('SELECT message'):
            return Rows([('normal note',)])
        return Rows([])
    monkeypatch.setattr(module, 'execute_db', execute)
    client = module.app.test_client()
    assert client.get('/register').status_code == 200
    assert client.get('/login').status_code == 200
    assert client.get('/notes').status_code == 302
    assert client.post('/register', data={'username':'alice','password':'a'}).status_code == 302
    response = client.post('/login', data={'username':'alice','password':'wrong-password'})
    assert response.status_code == 302 and 'Invalid+credentials' in response.location
    assert client.post('/login', data={'username':'alice','password':'a'}).status_code == 302
    assert b'normal note' in client.get('/notes').data
    assert client.post('/logout').status_code == 302
    assert client.get('/notes').status_code == 302
    module.engine.dispose()
