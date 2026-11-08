import importlib
from uuid import uuid4
from fastapi.testclient import TestClient

from app.knowledge import catalog, content, select_skills, safe_skill_context
from app.main import app, TOKEN

client = TestClient(app)
H = {"X-Secra-Token": TOKEN}

def test_bundled_skills_present_and_no_unreviewed_paths():
    skills = catalog()
    assert len(skills) >= 12
    for s in skills:
        doc = content(s["id"])
        assert "# " in doc and "Evidence" in doc
        assert "reference" in doc.lower() or "Sources" in doc
        assert len(doc) < 6500

def test_deterministic_selection():
    web = select_skills([{"port": 443, "service": "https"}], limit=12)
    ids = [s["id"] for s in web]
    assert "tls-transport-review" in ids
    assert "http-security-configuration" in ids
    assert "finding-verification" in ids
    ssh = select_skills([{"port": 22, "service": "ssh"}], limit=12)
    assert "network-service-discovery" in [x["id"] for x in ssh]
    assert "tls-transport-review" not in [x["id"] for x in ssh]

def test_unknown_service_does_not_load_untrusted_content():
    ids, body = safe_skill_context([{
        "port": 443, "service": "https", "ip": "192.0.2.10",
        "authorization": "Bearer supersecretvalue"
    }])
    assert "192.0.2.10" not in body
    assert "supersecretvalue" not in body
    assert all(isinstance(x, str) for x in ids)

def test_skill_api_requires_auth():
    assert client.get("/api/skills").status_code == 401
    listing = client.get("/api/skills", headers=H)
    assert listing.status_code == 200
    assert listing.json()["total"] >= 12
    detail = client.get("/api/skills/tls-transport-review", headers=H)
    assert detail.status_code == 200
    assert "TLS" in detail.json()["content"]
    assert client.get("/api/skills/../../../etc/passwd", headers=H).status_code in (404, 422)

def test_no_graph_for_unknown_engagement():
    assert client.get("/api/engagements/"+str(uuid4())+"/graph", headers=H).status_code == 404
