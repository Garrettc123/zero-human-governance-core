# Proposal approval is not execution

This branch corrects a critical accounting/observability defect: successful agent votes previously changed a proposal to `executed`, set `executed_at`, added a record to `executed_actions`, and returned `execution_triggered=true` despite no external action being performed.

## New semantics
- Threshold met: proposal becomes `approved`; a `proposal_approved` audit event records the vote evidence and `external_execution_verified=false`.
- `executed_at` remains null until an external execution with a verified receipt is implemented.
- `GET /executions` and the `executed` metrics do not count votes as external execution.
- `execution_triggered` is false because this code does not trigger an external runner.
- Rejected and pending voting behavior is otherwise unchanged.

## Breaking changes / follow-up
- Downstream dashboards that previously displayed `executed` for vote-only proposals must handle `approved` explicitly.
- A future runner must validate identity, policy, approved action envelope, idempotency, explicit operator authorization where required, actual external API result, and a durable execution receipt **before** advancing a proposal to `executed`. Do not introduce a synthetic execution record.
- Existing in-memory state is non-durable and remains unsuitable for production. It is outside this branch.
- PR #5 independently adds administrator authentication for registration and status writes; merge and verify separately, then resolve any conflicts if needed.

## Review gates
- Confirm modified governance tests pass on the exact head commit.
- Verify an approved proposal is excluded from execution counts and lacks `executed_at`.
- Confirm no integration relies on votes to claim external side effects.
- Review API consumers before merging. No live deployment is performed by this change.
