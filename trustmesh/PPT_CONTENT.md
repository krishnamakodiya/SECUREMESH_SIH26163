# PPT Content

## Problem

Security assessment tools report URLs and scanners; they rarely prove whether a trust boundary held, why it failed, or whether remediation worked.

## Solution

TRUSTMESH maps World Monitor's attack surface as trust boundaries, executes deterministic local tests, stores reproducible evidence, and replays the exact test after remediation.

## Differentiators

- Identity Twin for Alice/Bob authorization comparison.
- MCP credential persistence hypothesis with synthetic canary evidence.
- Intelligence Integrity path for provenance and validation transitions.
- Controlled vulnerable/patched lab with actual regression replay.
- Strict separation between World Monitor findings, source hypotheses, and lab demonstrations.

## Demo proof

World Monitor `2.10.0` / `ccc2219` runs locally. The command center shows the target, structured graph, test boundaries, evidence hash, and a real replay that produces `FAIL` before the patch and `PASS` after it.

## Safety

Localhost only. No production probing. No real credentials. No denial-of-service or destructive testing.
