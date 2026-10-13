def test_arithmetic_and_errors(app_loader):
    client=app_loader("code-injection").app.test_client()
    assert client.get("/").status_code==200
    assert client.post("/api/calculate",json={"sign":"(2 + 3) * 4"}).json["message"]==20
    assert client.post("/api/calculate",json={"sign":"-2.5 + 1"}).json["message"]==-1.5
    assert client.post("/api/calculate",json={"sign":"1 / 0"}).json=={"message":"bebebe"}
    assert client.post("/api/calculate",json={"sign":"("}).json=={"message":"bebebe"}
    assert client.post("/api/calculate",json={}).json=={"message":"Nothing to calculate"}
    assert client.post("/api/calculate",json={"sign":"[1, 2, 3]"}).json=={"message":[1,2,3]}
