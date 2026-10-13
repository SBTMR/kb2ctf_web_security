import subprocess
import uuid
import hashlib
import pytest

pytestmark=pytest.mark.integration

@pytest.mark.parametrize("live_client",["sql-injection"],indirect=True)
def test_notes_normal(live_client):
    client,base=live_client
    name="notes-"+uuid.uuid4().hex[:12]
    assert client.post(base+"/register",data={"username":name,"password":"a"},allow_redirects=False,timeout=8).status_code==302
    assert "Invalid credentials" in client.post(base+"/login",data={"username":name,"password":"wrong-password"},timeout=8).text
    response=client.post(base+"/login",data={"username":name,"password":"a"},timeout=8)
    assert response.status_code==200 and "Ваши личные заметки" in response.text
    assert "KB2CTF{" not in response.text
    assert client.post(base+"/logout",allow_redirects=False,timeout=5).status_code==302
    assert client.get(base+"/notes",allow_redirects=False,timeout=5).status_code==302

def test_original_password_storage():
    command=["docker","compose","--file","tasks/sql-injection/compose.yaml","exec","-T","sql-db","psql","-U","postgres","-d","kb2ctf","-Atc",
        "SELECT password FROM users WHERE username LIKE 'notes-%' ORDER BY id DESC LIMIT 1"]
    result=subprocess.run(command,text=True,capture_output=True,check=True)
    assert result.stdout.strip()==hashlib.sha256(b'a').hexdigest()
