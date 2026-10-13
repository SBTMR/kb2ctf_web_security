import pytest

pytestmark=pytest.mark.integration

@pytest.mark.parametrize('live_client',['blind-rce'],indirect=True)
def test_live_normal(live_client):
    client,base=live_client
    assert client.get(base+'/',timeout=5).status_code==200
    response=client.post(base+'/api/pinger',json={'ip':'127.0.0.1'},timeout=8)
    assert response.status_code==200
    assert set(response.json())=={'message','attempt'}
    assert client.get(base+'/api/observation',timeout=5).json()['observed'] is False
