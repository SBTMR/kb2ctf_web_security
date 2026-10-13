import pytest
pytestmark = pytest.mark.integration

@pytest.mark.parametrize('live_client', ['ssrf'], indirect=True)
def test_sender_normal(live_client):
    client, base = live_client
    assert client.get(base + '/', timeout=5).status_code == 200
    response = client.post(base + '/api/send', json={'url':'http://ssrf-sample:8080/', 'headers':{'Accept':'text/plain'}}, timeout=6)
    assert response.status_code == 200 and 'sample-site' in response.json()['message']
    assert client.post(base + '/api/send', json={'url':''}, timeout=5).json() == {'message':'bebebe'}
    assert client.post(base + '/api/send', json={}, timeout=5).json() == {'message':'The IP address was not specified'}
