# Unified Garcar governance contract — review-only candidate

**Scope.** governance_contract.py is a standalone Python 3.11+ / Pydantic v2 library. It is not mounted on either current FastAPI application. No existing production API behavior, routing, dispatch permissions, governance votes, or deployments are changed by this candidate.

## Proposed adapter sequence

1. Normalize source/provider messages into explicitly approved action metadata and compute a SHA-256 digest over the intended immutable action payload. Do not store prompt bodies, sensitive customer rows, secrets, or provider-specific blobs in context.
2. Authenticate the caller and run an independent, versioned policy engine. record_decision records the policy result, but **does not decide policy or authenticate the actor**.
3. record_decision rejects ALLOW when requires_hitl=True, records HOLD_HITL with one unique ticket, and rejects repeated decisions.
4. resolve_hitl requires a **trusted application-provided reviewer authorization callback**; a claimed reviewer_id string is not authentication. It enforces ticket/request binding and one-time terminal resolution; do not pass lambda _: True in production.
5. Approval is not execution. Any external tool dispatch needs separately authenticated, exact-action authorization and a provider-verified result receipt. Neither the approval event nor execution_allowed=True establishes successful execution.
6. Gate any future router under a reviewed, authenticated API deployment. The intended garcar-supernova-os gateway is port **8090**; this candidate intentionally does not change the existing governance-core app's historical port configuration.

## Validation

From repository root: python -m pip install 'pydantic>=2,<3' pytest and python -m pytest tests/test_governance_contract.py -q.

Local candidate: 14 passing tests, including 40 concurrent decision appends, invalid/duplicate tickets, approval/rejection replay holds, tamper detection and database reopening. **Remote GitHub Actions CI has not been independently confirmed**.

## Remaining security gates

- A hash chain detects ordinary unauthorized modifications, but not malicious recomputation of the complete chain or deletion of a terminal segment. Anchor and verify the latest (seq, entry_hash) outside the DB.
- SQLite WAL serializes writers of **one database file**; it does not synchronize distinct replicas, independent volumes, or multiple sites. Use one durable controlled volume with secure backups/permissions; synchronous=FULL does not replace operational backups.
- Python deterministic JSON encoding is **not** standardized RFC 8785 JCS across languages. Sorted object insertion order has no effect on its hash; changing field values or encoded bytes does. Avoid assuming hashes match between independent JavaScript/Go serializers without cross-language test vectors.
- frozen=True does not recursively freeze nested dictionaries and lists. Payload/context hashes are captured at the append point. Treat input objects as read-only after validation, and use immutable/deep-copied payloads for long-lived approval binding.
- The ledger checks row hashes and decision/ticket transitions but does not authenticate reviewers cryptographically, attest a result, verify external execution, prevent privileged DB tampering, or replace the existing repository's volatile agent/voting stores.
- **Do not merge or deploy** until an authenticated route/agent identity integration, proof-of-effect receipt model, complete security regressions, and independent CI/deployment evidence are reviewed. Existing zero-human-governance-core issue #7 tracks the broader migration.
