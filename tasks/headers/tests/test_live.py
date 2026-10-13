import pytest
pytestmark = pytest.mark.integration

@pytest.mark.parametrize('live_client', ['headers'], indirect=True)
def test_live_normal(live_client):
    client, base = live_client
    assert 'You want some flags?' in client.get(base + '/', timeout=5).text
    assert client.get(base + '/give_me_my_flag', timeout=5).status_code == 405
