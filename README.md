# TRUSTMESH

## Smart India Hackathon 2026 Project

TRUSTMESH is a local, safety-first security assessment and intelligence-integrity verification platform for **World Monitor**. It models trust boundaries, runs deterministic security checks, records reproducible evidence, separates hypotheses from findings, and replays controlled remediation tests.

## Repository Layout

```text
SIH-TRUSTMESH/
├── trustmesh/     # TRUSTMESH FastAPI command center, lab, reports, and tests
└── worldmonitor/  # pinned upstream World Monitor checkout used as the local target
```

`worldmonitor/` is the original open-source repository cloned from [koala73/worldmonitor](https://github.com/koala73/worldmonitor), pinned for this project to version `2.10.0`, commit `ccc2219`. TRUSTMESH assesses this local checkout only; it does not modify or probe the public deployment.

## Current Assessment

- Scope: `LOCAL_ONLY`
- World Monitor URL: `http://localhost:3000`
- TRUSTMESH URL: `http://127.0.0.1:8000`
- Focused World Monitor security checks: **190 passed, 0 failed**
- TRUSTMESH tests: **7 passed**
- Confirmed World Monitor vulnerabilities: **none**
- MCP credential persistence: `SOURCE CANDIDATE / NOT CONFIRMED`
- Controlled lab replay: vulnerable `FAIL` → patched `PASS`

## Run Locally

Start the pinned World Monitor checkout:

```bash
cd worldmonitor
npm install
npm run dev
```

In another terminal, start TRUSTMESH:

```bash
cd trustmesh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` for the TRUSTMESH demo and `http://localhost:3000` for the local World Monitor target.

## Safety Boundaries

Only localhost endpoints, synthetic Alice/Bob identities, synthetic resources, and `TRUSTMESH_CANARY_2026` are permitted. No real credentials, production URLs, customer data, destructive tests, or entitlement bypasses are used. Evidence is hashed and credential-shaped values are redacted before persistence.

## Documentation

- [TRUSTMESH README](trustmesh/README.md)
- [Demo sequence](trustmesh/DEMO.md)
- [PPT content](trustmesh/PPT_CONTENT.md)
- [Third-pass assessment](trustmesh/reports/third-pass-local-assessment.json)

## Attribution

World Monitor is an independent open-source project by [koala73/worldmonitor](https://github.com/koala73/worldmonitor). This repository contains TRUSTMESH and a pinned local checkout used only as the authorized assessment target. Refer to the upstream repository and its license for World Monitor terms.
