import pytest

pytestmark=pytest.mark.integration

@pytest.mark.parametrize('live_client',['code-injection'],indirect=True)
def test_live_normal(live_client):
    client,base=live_client
    assert client.get(base+'/',timeout=5).status_code==200
    response=client.post(base+'/api/calculate',json={'sign':'(2 + 3) * 4'},timeout=5)
    assert response.status_code==200 and response.json()['message']==20
