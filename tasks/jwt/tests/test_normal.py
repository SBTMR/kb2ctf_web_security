from datetime import datetime, timedelta, timezone
import jwt

def member(client):
    assert client.post('/register', data={'username':'alice', 'password':'a'}).status_code == 302
    assert client.post('/login', data={'username':'alice', 'password':'a'}).status_code == 302

def test_original_account_flow(app_loader):
    module = app_loader('jwt'); client = module.app.test_client()
    member(client)
    assert client.get('/flag').status_code == 200
    assert b'You are not an admin bebebe!' in client.get('/flag').data
    assert module.COOKIE == 'flag_token'
    assert module.jwtutil.decode_jwt(client.get_cookie(module.COOKIE).value) == {'username':'alice'}
    assert client.get('/support/config').status_code == 404
    assert client.post('/logout').status_code == 302
    assert client.get('/flag').status_code == 302

def test_invalid_signature_and_optional_expiry(app_loader):
    module = app_loader('jwt'); client = module.app.test_client(); member(client)
    now = datetime.now(timezone.utc)
    payload = {'username':'alice', 'iat':now, 'exp':now + timedelta(minutes=5)}
    client.set_cookie(module.COOKIE, jwt.encode(payload, 'x' * 64, algorithm='HS256'))
    assert client.get('/flag').status_code == 302
    payload['iat'] = now - timedelta(minutes=10); payload['exp'] = now - timedelta(minutes=1)
    client.set_cookie(module.COOKIE, jwt.encode(payload, module.jwtutil.secret, algorithm='HS256'))
    assert client.get('/flag').status_code == 302

def test_registration_does_not_grant_admin(app_loader):
    client = app_loader('jwt').app.test_client()
    assert client.post('/register', data={'username':'admin', 'password':'normal-password'}).status_code == 302
    member(client)
    assert b'KB2CTF{' not in client.get('/flag').data
