import time
from fastapi.testclient import TestClient
from app.main import app, TOKEN

client = TestClient(app)
HEADERS = {"X-Secra-Token": TOKEN}

def test_auth_required():
    assert client.get("/api/engagements").status_code == 401
    assert client.get("/api/health", headers=HEADERS).status_code == 200

def test_reject_unauthorized_engagement():
    p = {"name": "Sample lab", "target": "192.0.2.10", "scope": "192.0.2.0/24",
         "mode": "demo", "authorized": False}
    assert client.post("/api/engagements", headers=HEADERS, json=p).status_code == 400

def test_reject_out_of_scope():
    p = {"name": "Sample lab", "target": "192.0.2.10", "scope": "198.51.100.0/24",
         "mode": "demo", "authorized": True}
    assert client.post("/api/engagements", headers=HEADERS, json=p).status_code == 422

def test_demo_lifecycle():
    p = {"name": "Authorized lab", "target": "192.0.2.10", "scope": "192.0.2.0/24",
         "mode": "demo", "authorized": True, "model": ""}
    r = client.post("/api/engagements", headers=HEADERS, json=p)
    assert r.status_code == 200, r.text
    eid = r.json()["id"]
    assert client.post("/api/engagements/" + eid + "/start", headers=HEADERS).status_code == 200
    status = None
    for _ in range(100):
        status = client.get("/api/engagements/" + eid, headers=HEADERS).json()
        if status["status"] == "completed":
            break
        time.sleep(0.08)
    assert status["status"] == "completed"
    assert len(status["services"]) == 3 and status["mode"] == "demo"
    ev = client.get("/api/engagements/" + eid + "/events", headers=HEADERS).json()
    assert any(x["agent"] == "Report Builder" and x["level"] == "completed" for x in ev)
    report = client.get("/api/engagements/" + eid + "/report", headers=HEADERS)
    assert report.status_code == 200 and "SIMULATED" in report.text
    assert "No vulnerability was automatically confirmed" in report.text

def test_masking_preview():
    r = client.post("/api/privacy-preview", headers=HEADERS, json={"text": "john@example.com 192.0.2.10"})
    assert r.status_code == 200
    assert "192.0.2.10" not in r.json()["masked"]
