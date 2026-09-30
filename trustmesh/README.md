# TRUSTMESH

TRUSTMESH is a local, safety-first security assessment command center for the authorized World Monitor checkout.

The sibling `../worldmonitor/` directory is the original open-source [koala73/worldmonitor](https://github.com/koala73/worldmonitor) checkout used as the local assessment target. This project pins World Monitor `2.10.0` at commit `ccc2219`; TRUSTMESH does not modify or probe its public deployment.

## Run

```bash
cd trustmesh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. The default target is the sibling `worldmonitor/` checkout. `TRUSTMESH_TARGET` may point only to a checkout inside this authorized workspace.

Start World Monitor separately with `npm run dev` from `worldmonitor/`; its local Vite URL is normally `http://localhost:3000/`.

## Method

The UI follows `DISCOVER → MODEL → TEST → PROVE → REPLAY → VERIFY`. It models authentication, authorization, MCP/client storage, SSRF, integrity, desktop IPC, and secret boundaries. The graph and evidence ledger are backed by API data, not decorative state.

The MCP credential hypothesis is source-level candidate evidence until a local runtime test against the exact World Monitor checkout records the synthetic `TRUSTMESH_CANARY_2026`. Existing canary packets from `/lab/vulnerable` are controlled-lab evidence and never promote a World Monitor finding.

The local World Monitor UI exposes the MCP connector behind its Pro entitlement gate. TRUSTMESH reached that local entry point without bypassing the gate; therefore the current packet is deliberately `CANDIDATE`, not a confirmed World Monitor vulnerability. Evidence ingestion accepts only the synthetic canary, rejects other modes/keys, and redacts credential-shaped values before writing JSON reports.

Run focused verification with `source .venv/bin/activate && pytest -q`.

The third-pass local assessment is recorded in `reports/third-pass-local-assessment.json`. It found no independently reproducible World Monitor weakness in the permitted local test surface; the MCP item remains a source candidate because its UI is entitlement-gated.

## Safety

Only localhost and synthetic identities/resources are in scope. Never enter real credentials, API keys, customer data, or production URLs. The controlled lab intentionally demonstrates vulnerable and patched browser-storage behavior.
