import json

from fastapi.testclient import TestClient

from app.main import CANARY, app, classify_runtime_evidence, redact

client = TestClient(app)


def lab_payload(mode="patched", canary_present=False):
    return {"mode": mode, "key": CANARY, "canary_present": canary_present,
            "persisted_value": {"Authorization": f"Bearer {CANARY}"},
            "storage_key": "wm-mcp-panels", "timestamp": "2026-09-29T00:00:00Z"}


def test_health_and_target_are_local_and_pinned():
    assert client.get("/api/health").json()["status"] == "ok"
    data = client.get("/api/assessment").json()
    assert data["target"]["version"] == "2.10.0"
    assert data["target"]["commit"] == "ccc2219"
    assert data["target"]["scope"] == "LOCAL_ONLY"
    assert data["finding"]["status"] == "candidate"


def test_graph_identity_and_replay_are_real_endpoints():
    graph = client.get("/api/graph").json()
    assert len(graph["nodes"]) >= 6 and len(graph["edges"]) >= 5
    twin = client.get("/api/identity-test").json()
    assert twin["alice"]["status"] == 200 and twin["bob"]["status"] == 403
    assert twin["evidence_hash"]
    replay = client.post("/api/replay")
    assert replay.json()["before"]["result"] == "FAIL"
    assert replay.json()["after"]["result"] == "PASS"


def test_evidence_is_hashed_and_redacted():
    response = client.post("/api/lab/report", json=lab_payload())
    assert response.status_code == 200
    record = response.json()["record"]
    assert record["evidence_hash"]
    assert CANARY not in json.dumps(record)
    assert "[REDACTED]" in json.dumps(record)


def test_only_synthetic_canary_and_known_modes_are_accepted():
    bad_key = lab_payload()
    bad_key["key"] = "not-a-real-key"
    assert client.post("/api/lab/report", json=bad_key).status_code == 400
    bad_mode = lab_payload(mode="production")
    assert client.post("/api/lab/report", json=bad_mode).status_code == 400
    assert client.get("/lab/unknown").status_code == 404


def test_finding_classification_requires_worldmonitor_runtime_evidence():
    assert classify_runtime_evidence({"mode": "patched", "canary_present": False}) == "CANDIDATE"
    assert classify_runtime_evidence({"mode": "vulnerable", "canary_present": True}) == "CANDIDATE"
    assert classify_runtime_evidence({"mode": "worldmonitor", "canary_present": True}) == "CONFIRMED"


def test_lab_vulnerable_and_patched_states_are_distinct():
    vulnerable = client.post("/api/lab/report", json=lab_payload("vulnerable", True)).json()["record"]
    assert vulnerable["canary_present"] is True
    assert client.get("/api/finding-report").json()["status"] == "CANDIDATE"
    patched = client.post("/api/lab/report", json=lab_payload("patched", False)).json()["record"]
    assert patched["canary_present"] is False
    assert client.get("/api/finding-report").json()["status"] == "CANDIDATE"


def test_recursive_redaction_handles_nested_sensitive_values():
    result = redact({"headers": {"Authorization": CANARY}, "nested": [{"token": CANARY}]})
    assert CANARY not in json.dumps(result)
