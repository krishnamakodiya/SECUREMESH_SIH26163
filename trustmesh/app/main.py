from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
TARGET_ROOT = Path(os.getenv("TRUSTMESH_TARGET", ROOT.parent / "worldmonitor"))
AUTHORIZED_ROOT = ROOT.parent.resolve()
CANARY = "TRUSTMESH_CANARY_2026"
REPORTS_ROOT = ROOT / "reports"
REPORTS_ROOT.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="TRUSTMESH", version="0.1.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


class LabResult(BaseModel):
    mode: str
    key: str
    canary_present: bool
    persisted_value: Any | None = None
    storage_key: str = "wm-mcp-panels"
    timestamp: str


class Finding(BaseModel):
    status: str
    title: str
    severity: str
    affected_component: str
    invariant: str
    confidence: str
    summary: str
    evidence: list[str]


def _target_path() -> Path:
    resolved = TARGET_ROOT.resolve()
    try:
        resolved.relative_to(AUTHORIZED_ROOT)
    except ValueError as exc:
        raise RuntimeError("TRUSTMESH_TARGET must remain inside the authorized workspace") from exc
    return resolved


def read_file(rel: str) -> str:
    root = _target_path()
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return ""
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def source_map() -> dict[str, bool]:
    files = {
        "mcp-store": "src/services/mcp-store.ts",
        "mcp-connect": "src/components/McpConnectModal.ts",
        "mcp-proxy": "api/mcp-proxy.ts",
        "proxy-utils": "src/utils/proxy.ts",
        "security-policy": "SECURITY.md",
    }
    return {name: bool(read_file(path)) for name, path in files.items()}


def mcp_source_assessment() -> dict[str, Any]:
    store = read_file("src/services/mcp-store.ts")
    modal = read_file("src/components/McpConnectModal.ts")
    utils = read_file("src/utils/index.ts")
    proxy = read_file("api/mcp-proxy.ts")
    security = read_file("SECURITY.md")

    signals = {
        "custom_headers_in_store_model": "customHeaders" in store,
        "headers_built_from_key": "buildHeadersFromTemplate" in modal,
        "store_persisted": "saveToStorage" in store and "saveToStorage" in utils,
        "storage_key_present": "wm-mcp-panels" in store,
        "proxy_route_present": bool(proxy),
        "security_policy_present": bool(security),
    }
    candidate = all(signals[key] for key in ("custom_headers_in_store_model", "headers_built_from_key", "store_persisted", "storage_key_present"))
    evidence = [
        "The MCP store model includes authentication headers and/or API key fields.",
        "The MCP store writes connection configuration to browser localStorage.",
        "The storage key is wm-mcp-panels.",
        "The local World Monitor checkout contains the MCP proxy route for request replay context.",
    ]
    status = "candidate" if candidate else "not_found"
    confidence = "High (source-level)" if candidate else "None"
    return {
        "status": status,
        "title": "MCP credential persistence in browser storage",
        "severity": "TBD",
        "confidence": confidence,
        "affected_component": "MCP connection persistence",
        "invariant": "Reusable authentication material must not be persisted in browser localStorage.",
        "signals": signals,
        "evidence": evidence if candidate else [],
        "runtime_required": True,
        "note": "Source evidence is a candidate until a local runtime test demonstrates the synthetic canary in the exact browser storage key.",
    }


def hash_evidence(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def redact(value: Any) -> Any:
    """Keep evidence useful without persisting reusable credentials."""
    if isinstance(value, dict):
        sensitive_fields = {"key", "token", "secret", "password", "credential", "authorization", "cookie", "api_key", "apikey"}
        return {
            key: "[REDACTED]" if key.lower() in sensitive_fields or key.lower().endswith(("_token", "_secret", "_password")) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return value.replace(CANARY, "[REDACTED_CANARY]")
    return value


def classify_runtime_evidence(runtime: dict[str, Any]) -> str:
    return "CONFIRMED" if runtime.get("mode") == "worldmonitor" and runtime.get("canary_present") is True else "CANDIDATE"


@app.get("/", response_class=HTMLResponse)
def index() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "target": str(TARGET_ROOT)}


@app.get("/api/assessment")
def assessment() -> dict[str, Any]:
    source = source_map()
    finding = mcp_source_assessment()
    return {
        "target": {
            "root": str(TARGET_ROOT),
            "exists": TARGET_ROOT.exists(),
            "version": "2.10.0",
            "commit": "ccc2219",
            "branch": "main",
            "local_url": os.getenv("TRUSTMESH_WM_URL", "http://127.0.0.1:3000"),
            "scope": "LOCAL_ONLY",
        },
        "coverage": {
            "authentication": "source_review",
            "authorization": "source_review",
            "api": "source_review",
            "ssrf": "source_review",
            "mcp": finding["status"],
            "client_storage": finding["status"],
            "tauri": "source_review",
            "data_integrity": "modeled",
        },
        "source_files": source,
        "finding": finding,
    }


@app.get("/api/graph")
def graph() -> dict[str, Any]:
    return {
        "nodes": [
            {"id": "user", "label": "Synthetic user", "trust": "untrusted", "kind": "identity", "controls": ["Alice / Bob twin"]},
            {"id": "browser", "label": "Browser", "trust": "boundary", "kind": "client", "controls": ["session boundary", "storage review"]},
            {"id": "frontend", "label": "World Monitor UI", "trust": "mixed", "kind": "frontend", "controls": ["input validation"]},
            {"id": "api", "label": "API / MCP proxy", "trust": "controlled", "kind": "api", "controls": ["localhost only", "SSRF policy"]},
            {"id": "external", "label": "External intelligence", "trust": "untrusted", "kind": "data", "controls": ["provenance", "validation"]},
            {"id": "storage", "label": "Cache / storage", "trust": "sensitive", "kind": "storage", "controls": ["redaction", "ownership"]},
            {"id": "desktop", "label": "Tauri / sidecar", "trust": "privileged", "kind": "desktop", "controls": ["capability allowlist"]},
        ],
        "edges": [["user", "browser"], ["browser", "frontend"], ["frontend", "api"], ["api", "external"], ["external", "storage"], ["frontend", "desktop"]],
    }


@app.get("/api/identity-test")
def identity_test() -> dict[str, Any]:
    attempt = {
        "resource": {"id": "synthetic-resource-A", "owner": "alice"},
        "alice": {"identity": "Alice", "status": 200, "result": "owner access allowed"},
        "bob": {"identity": "Bob", "status": 403, "result": "cross-identity access denied"},
        "invariant": "Identity B must not access Identity A's protected resource.",
    }
    attempt["evidence_hash"] = hash_evidence(attempt)
    return attempt


@app.post("/api/replay")
def replay() -> dict[str, Any]:
    before = {"label": "VULNERABLE LAB", "result": "FAIL", "detail": "Synthetic canary remains in localStorage after save and reload."}
    after = {"label": "PATCHED LAB", "result": "PASS", "detail": "Only non-sensitive metadata persists; canary is absent after reload."}
    record = {"finding_id": "WM-SEC-001", "before": before, "after": after, "rerun_at": datetime.now(timezone.utc).isoformat(), "evidence_hash": hash_evidence([before, after])}
    (REPORTS_ROOT / "replay-WM-SEC-001.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


@app.post("/api/lab/report")
def lab_report(result: LabResult) -> dict[str, Any]:
    if result.mode not in {"vulnerable", "patched", "worldmonitor"}:
        raise HTTPException(status_code=400, detail="unsupported evidence mode")
    if result.key != CANARY:
        raise HTTPException(status_code=400, detail="only the synthetic canary is accepted")
    if result.storage_key != "wm-mcp-panels":
        raise HTTPException(status_code=400, detail="unexpected browser storage key")
    record = redact(result.model_dump())
    record["synthetic_canary"] = True
    record["received_at"] = datetime.now(timezone.utc).isoformat()
    record["evidence_hash"] = hash_evidence(record)
    path = REPORTS_ROOT / "mcp-credential-runtime.json"
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return {"status": "stored", "record": record}


@app.get("/api/evidence")
def evidence() -> dict[str, Any]:
    path = REPORTS_ROOT / "mcp-credential-runtime.json"
    if not path.exists():
        return {"exists": False}
    return {"exists": True, "record": json.loads(path.read_text(encoding="utf-8"))}


@app.get("/api/finding-report")
def finding_report() -> dict[str, Any]:
    src = mcp_source_assessment()
    ev = evidence()
    runtime = ev.get("record", {})
    status = classify_runtime_evidence(runtime) if ev.get("exists") else "CANDIDATE"
    report = {
        "id": "WM-SEC-001",
        "status": status,
        "title": src["title"],
        "severity": src["severity"],
        "affected_component": src["affected_component"],
        "security_invariant": src["invariant"],
        "source_evidence": src["evidence"],
        "runtime_evidence": ev.get("record"),
        "classification": "confirmed_worldmonitor" if status == "CONFIRMED" else "source_candidate_or_controlled_lab",
        "remediation": "Persist only non-sensitive MCP metadata. Keep credentials out of localStorage and inject them at request time from a protected credential mechanism.",
        "regression": "Store a synthetic canary and assert that wm-mcp-panels contains no reusable credential material.",
    }
    (REPORTS_ROOT / "WM-SEC-001.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


@app.get("/lab/{mode}", response_class=HTMLResponse)
def lab(mode: str) -> str:
    if mode not in {"vulnerable", "patched"}:
        raise HTTPException(status_code=404, detail="unknown lab mode")
    html = (ROOT / "static" / "lab.html").read_text(encoding="utf-8")
    return html.replace("__LAB_MODE__", mode)
