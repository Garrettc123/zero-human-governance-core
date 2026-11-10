# Governance hardening: operator-controlled agent lifecycle

## Scope
This review branch adds fail-closed authentication to `POST /agents/register` and `PUT /agents/{agent_id}/status`. It does **not** claim to make the whole governance service production-ready.

## Breaking change and secret provisioning
Before deploying, provision a random `GOVERNANCE_ADMIN_TOKEN` (minimum 32 characters) in the service's secret manager. Never place it in git, build logs, browser JavaScript, or customer-facing pages. Use TLS and send it only in the `X-Garcar-Admin-Token` header from an operator-controlled provisioning service.

- No configured token or fewer than 32 characters: HTTP 503, no mutation.
- Missing or invalid token: HTTP 403, no mutation.
- Valid operator token: existing request schemas remain unchanged.

The legacy `governance/orchestrator.py` registers itself directly. That legacy registration path will be **blocked** after deployment until a separate operator-controlled provisioning workflow exists. Do not give autonomous workers the administrator token; provision the agent identity out of band, then deliver an agent-scoped credential securely.

## Verification steps before merge or deploy
1. Confirm unit tests and new authorization regression tests pass on the pull request's exact head commit.
2. Verify requests without the admin header never create agents or alter their status.
3. Verify missing token configuration fails closed, without a developer bypass.
4. Provision service secret only after operator approval. Validate identity and rotation in the target environment.
5. Confirm legacy clients are migrated to owner-controlled registration or will fail safely.
6. Perform live staging checks, rollback planning, and an independent access-control review.

## Known unresolved issues (not fixed by this branch)
- Governance `agents_db`, `proposals_db`, `votes_db`, and `audit_chain` are process-memory stores and must become transactional durable storage.
- The dashboard and some read endpoints expose governance metadata without the same operator protection. Audit before connecting sensitive production data.
- `try_execute_proposal` sets a proposal to `executed` and appends an internal record; it does not demonstrate an external side effect or independently verified outcome. Distinguish approval from execution in a future migration.
- `governance/orchestrator.py` currently cycles hard-coded opportunities with estimated values; do not present them as real market research or verified revenue.
- `governance/security.py` contains XOR-based MVP encryption; prohibit this for production secrets and personal data.
- At assessment time, the latest governance CI/deployment workflow was failing. A passing review build and deployment verification are mandatory before claiming readiness.

No deployment, key rotation, external communication, or production data mutation is performed by this branch.
