import pytest

pytestmark=pytest.mark.integration

@pytest.mark.parametrize('live_client',['jwt'],indirect=True)
def test_live_normal(live_client):
    client,base=live_client
    assert client.get(base+'/',timeout=5).status_code==200
    import uuid
    name='member-'+uuid.uuid4().hex[:12]
    assert client.post(base+'/register',data={'username':name,'password':'a'},allow_redirects=False,timeout=5).status_code==302
    assert client.post(base+'/login',data={'username':name,'password':'a'},timeout=5).status_code==200
    assert 'You are not an admin bebebe!' in client.get(base+'/flag',timeout=5).text
