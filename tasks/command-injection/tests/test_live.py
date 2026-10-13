import pytest

pytestmark=pytest.mark.integration

@pytest.mark.parametrize('live_client',['command-injection'],indirect=True)
def test_live_normal(live_client):
    client,base=live_client
    assert client.get(base+'/',timeout=5).status_code==200
    response=client.post(base+'/api/pinger',json={'ip':'127.0.0.1'},timeout=8)
    assert response.status_code==200
    assert '1 received' in response.json()['message']
