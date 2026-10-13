def test_observation_fixture_and_attempt_isolation(app_loader,monkeypatch):
    module=app_loader("blind-rce")
    monkeypatch.setattr(module,"run_diagnostic",lambda host,marker:None)
    client=module.app.test_client()
    assert client.get("/api/observation").json=={"attempt":None,"observed":False}
    first=client.post("/api/pinger",json={"ip":"127.0.0.1"}).json
    assert set(first)=={"attempt","message"}
    assert client.get("/api/observation").json["observed"] is False
    # Controlled fixture tests the observer only, not command execution.
    (module.STATE_ROOT/first["attempt"]/"marker").write_text("fixture",encoding="utf-8")
    assert client.get("/api/observation").json["observed"] is True
    other=module.app.test_client()
    assert other.get("/api/observation").json["observed"] is False
    second=client.post("/api/pinger",json={"ip":"127.0.0.1"}).json
    assert first["attempt"]!=second["attempt"]
    assert client.get("/api/observation").json["observed"] is False

def test_missing_address_has_no_attempt(app_loader):
    client=app_loader("blind-rce").app.test_client()
    assert client.post("/api/pinger",json={}).json=={"message":"The IP address was not specified"}
    assert client.get("/api/observation").json["attempt"] is None
