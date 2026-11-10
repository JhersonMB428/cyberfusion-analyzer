"""Panel de "webs analizadas": lista lo que se analizo aunque no haya
formulario, marca si dejo sus datos y nunca expone la IP del visitante."""
import json

import fakeredis
from fastapi.testclient import TestClient

import api.main as M


def test_lista_webs_analizadas(monkeypatch, tmp_path):
    fake = fakeredis.FakeRedis()
    monkeypatch.setattr(M, "r", fake)
    monkeypatch.setattr(M, "LEADS_TOKEN", "t0k")
    leads = tmp_path / "leads.jsonl"
    leads.write_text(json.dumps({"job_id": "b2", "name": "Ana"}) + "\n")
    monkeypatch.setattr(M, "LEADS_FILE", leads)

    M._audit("1.2.3.4", "https://a.com", "a.com", "a1", False, {"utm_source": "linkedin", "utm_medium": "", "utm_campaign": "nov", "utm_content": ""})
    M._audit("5.6.7.8", "https://b.com", "b.com", "b2", False, {k: "" for k in M.UTM_KEYS})
    fake.set("scansum:a1", json.dumps({"score": 82, "level": "medio", "status": "blocked", "coverage": "5/10", "waf": "imunify360"}))

    c = TestClient(M.app)
    assert c.get("/leads/scans.json").status_code == 403
    body = c.get("/leads/scans.json", headers={"X-Leads-Token": "t0k"}).json()
    rows = {x["host"]: x for x in body["scans"]}
    assert rows["a.com"]["score"] == 82 and rows["a.com"]["utm_source"] == "linkedin" and not rows["a.com"]["lead"]
    assert rows["b.com"]["lead"] is True
    assert "1.2.3.4" not in json.dumps(body) and "5.6.7.8" not in json.dumps(body)

    csv = c.get("/leads/scans.csv?token=t0k").text
    assert "a.com" in csv and "1.2.3.4" not in csv
