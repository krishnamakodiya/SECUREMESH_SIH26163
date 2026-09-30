# TRUSTMESH Demo

1. Start World Monitor locally, then start TRUSTMESH.
2. Show Target / environment: World Monitor `2.10.0`, commit `ccc2219`, local-only scope.
3. Walk through Attack surface and Trust graph.
4. Use Identity twin to create Alice's synthetic Resource A and deny Bob.
5. Open Controlled lab and run vulnerable, then patched, using only `TRUSTMESH_CANARY_2026`.
6. Open Evidence ledger and show the hash and runtime packet.
7. Open Replay / verify and run the exact FAIL → PASS regression.
8. Open Findings to distinguish the World Monitor source candidate from controlled-lab evidence.
9. Open Intelligence integrity and explain the external source → validation → provenance path.

Runtime note: the MCP connector is visible in the local checkout but gated behind the Pro entitlement in the unauthenticated demo environment. Show the source candidate and controlled lab proof separately; do not bypass the gate or enter any credential other than the synthetic canary.
