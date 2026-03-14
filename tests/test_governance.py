"""Comprehensive pytest suite for the Zero-Human Governance Core.

Coverage:
  - Cryptographic utilities (Ed25519 sign/verify, hash chaining)
  - Agent registration and registry
  - Governance proposals (submit, list, get)
  - Voting with threshold-based execution
  - Multi-sig requirements for high-risk proposals
  - Policy enforcement
  - Audit trail integrity and chain verification
  - Dashboard and metrics endpoints
"""

import pytest
from httpx import AsyncClient

from governance.crypto import (
    compute_chain_hash,
    compute_hash,
    generate_keypair,
    sign_data,
    verify_signature,
)
from governance.main import (
    GENESIS_HASH,
    RISK_THRESHOLDS,
    MIN_VOTES_REQUIRED,
    audit_chain,
    executed_actions,
)
from tests.conftest import sign_proposal, sign_vote


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Cryptographic Utilities
# ═══════════════════════════════════════════════════════════════════════════════


class TestCrypto:
    def test_generate_keypair_returns_two_base64_strings(self):
        private_key, public_key = generate_keypair()
        assert isinstance(private_key, str) and len(private_key) > 0
        assert isinstance(public_key, str) and len(public_key) > 0
        assert private_key != public_key

    def test_sign_and_verify_roundtrip(self):
        private_key, public_key = generate_keypair()
        data = {"action": "test", "value": 42}
        sig = sign_data(private_key, data)
        assert verify_signature(public_key, data, sig) is True

    def test_verify_fails_with_wrong_key(self):
        private_key, _ = generate_keypair()
        _, other_public = generate_keypair()
        data = {"action": "test"}
        sig = sign_data(private_key, data)
        assert verify_signature(other_public, data, sig) is False

    def test_verify_fails_with_tampered_data(self):
        private_key, public_key = generate_keypair()
        data = {"action": "test", "value": 1}
        sig = sign_data(private_key, data)
        tampered = {"action": "test", "value": 999}
        assert verify_signature(public_key, tampered, sig) is False

    def test_verify_fails_with_bad_signature(self):
        _, public_key = generate_keypair()
        data = {"x": 1}
        assert verify_signature(public_key, data, "badsignature==") is False

    def test_compute_hash_deterministic(self):
        data = {"b": 2, "a": 1}
        assert compute_hash(data) == compute_hash({"a": 1, "b": 2})

    def test_compute_chain_hash_changes_with_previous(self):
        entry = {"entry_id": "abc", "action": "test"}
        h1 = compute_chain_hash(entry, GENESIS_HASH)
        h2 = compute_chain_hash(entry, "other_hash")
        assert h1 != h2

    def test_keypairs_are_unique(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert kp1 != kp2


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Agent Registry
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.anyio
class TestAgentRegistry:
    async def test_register_agent_returns_keypair(self, client: AsyncClient):
        resp = await client.post(
            "/agents/register",
            json={"name": "Agent-1", "capabilities": ["scan"], "permissions": ["vote"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["agent_id"]
        assert body["public_key"]
        assert body["private_key"]  # one-time secret
        assert body["status"] == "active"

    async def test_private_key_not_in_list_response(self, client: AsyncClient, registered_agent):
        resp = await client.get("/agents")
        assert resp.status_code == 200
        for agent in resp.json():
            assert "private_key" not in agent

    async def test_get_agent_by_id(self, client: AsyncClient, registered_agent):
        agent_id = registered_agent["agent_id"]
        resp = await client.get(f"/agents/{agent_id}")
        assert resp.status_code == 200
        assert resp.json()["agent_id"] == agent_id

    async def test_get_unknown_agent_returns_404(self, client: AsyncClient):
        resp = await client.get("/agents/nonexistent-id")
        assert resp.status_code == 404

    async def test_update_agent_status_suspend(self, client: AsyncClient, registered_agent):
        agent_id = registered_agent["agent_id"]
        resp = await client.put(f"/agents/{agent_id}/status?status=suspended")
        assert resp.status_code == 200
        assert resp.json()["status"] == "suspended"

    async def test_update_agent_status_invalid(self, client: AsyncClient, registered_agent):
        agent_id = registered_agent["agent_id"]
        resp = await client.put(f"/agents/{agent_id}/status?status=flying")
        assert resp.status_code == 400

    async def test_registration_logged_in_audit(self, client: AsyncClient):
        await client.post(
            "/agents/register",
            json={"name": "AuditAgent", "capabilities": [], "permissions": []},
        )
        assert any(e["action"] == "agent_registered" for e in audit_chain)

    async def test_multiple_agents_have_unique_ids(self, client: AsyncClient):
        ids = set()
        for i in range(5):
            resp = await client.post(
                "/agents/register",
                json={"name": f"Agent-{i}", "capabilities": [], "permissions": []},
            )
            ids.add(resp.json()["agent_id"])
        assert len(ids) == 5


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Governance Proposals
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.anyio
class TestProposals:
    async def test_submit_proposal_success(self, client: AsyncClient, registered_agent):
        agent_id = registered_agent["agent_id"]
        private_key = registered_agent["private_key"]
        sig = sign_proposal(
            private_key,
            agent_id,
            title="My Proposal",
            description="Do something useful",
            proposed_action="do_it",
            risk_level="low",
        )

        resp = await client.post(
            "/proposals",
            json={
                "title": "My Proposal",
                "description": "Do something useful",
                "proposed_action": "do_it",
                "risk_level": "low",
                "action_params": {},
                "agent_id": agent_id,
                "signature": sig,
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "pending"
        assert body["proposed_by"] == agent_id
        assert body["required_threshold"] == RISK_THRESHOLDS["low"]

    async def test_proposal_with_invalid_risk_level(self, client: AsyncClient, registered_agent):
        agent_id = registered_agent["agent_id"]
        private_key = registered_agent["private_key"]
        sig = sign_proposal(private_key, agent_id, risk_level="extreme")
        resp = await client.post(
            "/proposals",
            json={
                "title": "Bad Risk",
                "description": "Bad",
                "proposed_action": "bad",
                "risk_level": "extreme",
                "action_params": {},
                "agent_id": agent_id,
                "signature": sig,
            },
        )
        assert resp.status_code == 400

    async def test_proposal_invalid_signature_rejected(self, client: AsyncClient, registered_agent):
        agent_id = registered_agent["agent_id"]
        wrong_private, _ = generate_keypair()  # different private key
        sig = sign_proposal(
            wrong_private,
            agent_id,
            title="Bad Sig",
            description="Test description",
            proposed_action="noop",
            risk_level="low",
        )
        resp = await client.post(
            "/proposals",
            json={
                "title": "Bad Sig",
                "description": "Test description",
                "proposed_action": "noop",
                "risk_level": "low",
                "action_params": {},
                "agent_id": agent_id,
                "signature": sig,
            },
        )
        assert resp.status_code == 403

    async def test_unregistered_agent_cannot_propose(self, client: AsyncClient):
        fake_private, _ = generate_keypair()
        fake_id = "00000000-0000-0000-0000-000000000000"
        sig = sign_proposal(fake_private, fake_id, risk_level="low")
        resp = await client.post(
            "/proposals",
            json={
                "title": "Ghost Proposal",
                "description": "test",
                "proposed_action": "noop",
                "risk_level": "low",
                "action_params": {},
                "agent_id": fake_id,
                "signature": sig,
            },
        )
        assert resp.status_code == 404

    async def test_agent_without_permission_cannot_propose(self, client: AsyncClient):
        # Register agent with no permissions
        r = await client.post(
            "/agents/register",
            json={"name": "NoPerms", "capabilities": [], "permissions": []},
        )
        agent = r.json()
        sig = sign_proposal(agent["private_key"], agent["agent_id"], risk_level="low")
        resp = await client.post(
            "/proposals",
            json={
                "title": "No-perm Proposal",
                "description": "test",
                "proposed_action": "noop",
                "risk_level": "low",
                "action_params": {},
                "agent_id": agent["agent_id"],
                "signature": sig,
            },
        )
        assert resp.status_code == 403

    async def test_list_proposals(self, client: AsyncClient, registered_agent):
        agent_id = registered_agent["agent_id"]
        private_key = registered_agent["private_key"]
        for i in range(3):
            sig = sign_proposal(
                private_key,
                agent_id,
                title=f"Proposal {i}",
                description="Test description",
                proposed_action="noop",
                risk_level="low",
            )
            await client.post(
                "/proposals",
                json={
                    "title": f"Proposal {i}",
                    "description": "Test description",
                    "proposed_action": "noop",
                    "risk_level": "low",
                    "action_params": {},
                    "agent_id": agent_id,
                    "signature": sig,
                },
            )
        resp = await client.get("/proposals")
        assert resp.status_code == 200
        assert len(resp.json()) == 3

    async def test_get_proposal_by_id(self, client: AsyncClient, registered_agent):
        agent_id = registered_agent["agent_id"]
        private_key = registered_agent["private_key"]
        sig = sign_proposal(
            private_key,
            agent_id,
            title="Single",
            description="Test description",
            proposed_action="noop",
            risk_level="low",
        )
        create_resp = await client.post(
            "/proposals",
            json={
                "title": "Single",
                "description": "Test description",
                "proposed_action": "noop",
                "risk_level": "low",
                "action_params": {},
                "agent_id": agent_id,
                "signature": sig,
            },
        )
        proposal_id = create_resp.json()["proposal_id"]
        resp = await client.get(f"/proposals/{proposal_id}")
        assert resp.status_code == 200
        assert resp.json()["proposal_id"] == proposal_id

    async def test_get_unknown_proposal_returns_404(self, client: AsyncClient):
        resp = await client.get("/proposals/nonexistent-id")
        assert resp.status_code == 404

    async def test_list_proposals_filter_by_status(self, client: AsyncClient, registered_agent):
        agent_id = registered_agent["agent_id"]
        private_key = registered_agent["private_key"]
        sig = sign_proposal(
            private_key,
            agent_id,
            title="Filtered",
            description="Test description",
            proposed_action="noop",
            risk_level="low",
        )
        await client.post(
            "/proposals",
            json={
                "title": "Filtered",
                "description": "Test description",
                "proposed_action": "noop",
                "risk_level": "low",
                "action_params": {},
                "agent_id": agent_id,
                "signature": sig,
            },
        )
        resp = await client.get("/proposals?status=pending")
        assert resp.status_code == 200
        assert all(p["status"] == "pending" for p in resp.json())


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Voting & Threshold Execution
# ═══════════════════════════════════════════════════════════════════════════════


async def _submit_proposal(client, agent, title="TestProp", risk_level="low"):
    sig = sign_proposal(
        agent["private_key"],
        agent["agent_id"],
        title=title,
        description="Test description",
        proposed_action="noop",
        risk_level=risk_level,
    )
    resp = await client.post(
        "/proposals",
        json={
            "title": title,
            "description": "Test description",
            "proposed_action": "noop",
            "risk_level": risk_level,
            "action_params": {},
            "agent_id": agent["agent_id"],
            "signature": sig,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["proposal_id"]


async def _cast_vote(client, agent, proposal_id, vote, reason=""):
    sig = sign_vote(agent["private_key"], agent["agent_id"], proposal_id, vote, reason=reason)
    return await client.post(
        f"/proposals/{proposal_id}/vote",
        json={
            "vote": vote,
            "reason": reason,
            "agent_id": agent["agent_id"],
            "signature": sig,
        },
    )


@pytest.mark.anyio
class TestVoting:
    async def test_vote_approved_and_executed(self, client: AsyncClient, two_agents):
        proposer, voter = two_agents
        # With 2 active agents (1 eligible voter), 1 yes-vote ≥ 50% threshold → execute
        proposal_id = await _submit_proposal(client, proposer, risk_level="low")
        resp = await _cast_vote(client, voter, proposal_id, vote=True)
        assert resp.status_code == 200
        body = resp.json()
        assert body["execution_triggered"] is True
        assert body["proposal_status"] == "executed"
        assert len(executed_actions) == 1

    async def test_vote_rejected_when_threshold_unreachable(self, client: AsyncClient, two_agents):
        proposer, voter = two_agents
        # 1 eligible voter, 1 no-vote → threshold unreachable → reject
        proposal_id = await _submit_proposal(client, proposer, risk_level="low")
        resp = await _cast_vote(client, voter, proposal_id, vote=False)
        assert resp.status_code == 200
        body = resp.json()
        assert body["proposal_status"] == "rejected"

    async def test_duplicate_vote_rejected(self, client: AsyncClient, two_agents):
        proposer, voter = two_agents
        proposal_id = await _submit_proposal(client, proposer, risk_level="low")
        await _cast_vote(client, voter, proposal_id, vote=True)
        resp = await _cast_vote(client, voter, proposal_id, vote=True)
        assert resp.status_code == 400

    async def test_proposer_cannot_vote(self, client: AsyncClient, two_agents):
        proposer, _ = two_agents
        proposal_id = await _submit_proposal(client, proposer, risk_level="low")
        resp = await _cast_vote(client, proposer, proposal_id, vote=True)
        assert resp.status_code == 400

    async def test_vote_on_nonexistent_proposal(self, client: AsyncClient, registered_agent):
        resp = await _cast_vote(client, registered_agent, "bad-id", vote=True)
        assert resp.status_code == 404

    async def test_vote_on_closed_proposal_fails(self, client: AsyncClient, two_agents):
        proposer, voter = two_agents
        proposal_id = await _submit_proposal(client, proposer, risk_level="low")
        # Execute proposal
        await _cast_vote(client, voter, proposal_id, vote=True)
        # Try to vote again on an already-executed proposal
        resp = await _cast_vote(client, voter, proposal_id, vote=True)
        assert resp.status_code == 400

    async def test_get_proposal_votes(self, client: AsyncClient, two_agents):
        proposer, voter = two_agents
        proposal_id = await _submit_proposal(client, proposer, risk_level="low")
        await _cast_vote(client, voter, proposal_id, vote=True)
        resp = await client.get(f"/proposals/{proposal_id}/votes")
        assert resp.status_code == 200
        body = resp.json()
        assert body["summary"]["votes_for"] == 1

    async def test_invalid_vote_signature_rejected(self, client: AsyncClient, two_agents):
        proposer, voter = two_agents
        proposal_id = await _submit_proposal(client, proposer, risk_level="low")
        # Sign with a different (wrong) private key
        wrong_private, _ = generate_keypair()
        sig = sign_vote(wrong_private, voter["agent_id"], proposal_id, True)
        resp = await client.post(
            f"/proposals/{proposal_id}/vote",
            json={
                "vote": True,
                "reason": "",
                "agent_id": voter["agent_id"],
                "signature": sig,
            },
        )
        assert resp.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Multi-Sig (High / Critical Risk)
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.anyio
class TestMultiSig:
    async def test_high_risk_requires_two_votes(self, client: AsyncClient):
        """high-risk proposal needs MIN_VOTES_REQUIRED=2 and ≥67% threshold."""
        agents = []
        for i in range(3):  # 1 proposer + 2 eligible voters
            r = await client.post(
                "/agents/register",
                json={
                    "name": f"Voter-{i}",
                    "capabilities": [],
                    "permissions": ["propose", "vote"],
                },
            )
            agents.append(r.json())

        proposer = agents[0]
        proposal_id = await _submit_proposal(client, proposer, risk_level="high")

        # 1 yes-vote from 2 eligible → 50% < 67% threshold → not executed yet
        r1 = await _cast_vote(client, agents[1], proposal_id, vote=True)
        assert r1.json()["execution_triggered"] is False

        # 2 yes-votes from 2 eligible -> 100% >= 67% AND count>=2 -> execute
        r2 = await _cast_vote(client, agents[2], proposal_id, vote=True)
        assert r2.json()["execution_triggered"] is True
        assert r2.json()["proposal_status"] == "executed"

    async def test_critical_risk_requires_three_votes(self, client: AsyncClient):
        """critical-risk needs MIN_VOTES_REQUIRED=3 and ≥80% threshold."""
        agents = []
        for i in range(5):
            r = await client.post(
                "/agents/register",
                json={
                    "name": f"CritVoter-{i}",
                    "capabilities": [],
                    "permissions": ["propose", "vote"],
                },
            )
            agents.append(r.json())

        proposer = agents[0]
        proposal_id = await _submit_proposal(client, proposer, risk_level="critical")

        # 2 yes from 4 eligible = 50% < 80% → not executed
        await _cast_vote(client, agents[1], proposal_id, vote=True)
        r2 = await _cast_vote(client, agents[2], proposal_id, vote=True)
        assert r2.json()["execution_triggered"] is False

        # 3 yes from 4 eligible = 75% < 80% → still not executed
        r3 = await _cast_vote(client, agents[3], proposal_id, vote=True)
        assert r3.json()["execution_triggered"] is False

        # 4 yes from 4 eligible = 100% ≥ 80% AND ≥ 3 votes → execute
        r4 = await _cast_vote(client, agents[4], proposal_id, vote=True)
        assert r4.json()["execution_triggered"] is True

    async def test_min_votes_threshold_constants(self):
        assert MIN_VOTES_REQUIRED["high"] == 2
        assert MIN_VOTES_REQUIRED["critical"] == 3
        assert RISK_THRESHOLDS["high"] == pytest.approx(0.67)
        assert RISK_THRESHOLDS["critical"] == pytest.approx(0.80)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Policy Enforcement
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.anyio
class TestPolicyEnforcement:
    async def test_agent_with_vote_permission_can_vote(self, client: AsyncClient, two_agents):
        proposer, voter = two_agents
        # Both have 'vote' permission (from conftest fixture)
        allowed = await client.post(
            "/policy/check",
            json={"agent_id": voter["agent_id"], "action": "vote"},
        )
        assert allowed.json()["allowed"] is True

    async def test_suspended_agent_cannot_propose(self, client: AsyncClient, registered_agent):
        agent_id = registered_agent["agent_id"]
        await client.put(f"/agents/{agent_id}/status?status=suspended")
        sig = sign_proposal(
            registered_agent["private_key"],
            agent_id,
            title="Suspended Attempt",
            description="Test description",
            proposed_action="noop",
            risk_level="low",
        )
        resp = await client.post(
            "/proposals",
            json={
                "title": "Suspended Attempt",
                "description": "Test description",
                "proposed_action": "noop",
                "risk_level": "low",
                "action_params": {},
                "agent_id": agent_id,
                "signature": sig,
            },
        )
        assert resp.status_code == 403

    async def test_suspended_agent_cannot_vote(self, client: AsyncClient, two_agents):
        proposer, voter = two_agents
        proposal_id = await _submit_proposal(client, proposer, risk_level="low")
        # Suspend the voter
        await client.put(f"/agents/{voter['agent_id']}/status?status=suspended")
        resp = await _cast_vote(client, voter, proposal_id, vote=True)
        assert resp.status_code == 403

    async def test_policy_check_unknown_agent(self, client: AsyncClient):
        resp = await client.post(
            "/policy/check",
            json={"agent_id": "ghost-id", "action": "vote"},
        )
        assert resp.status_code == 200
        assert resp.json()["allowed"] is False

    async def test_policy_violation_logged_in_audit(self, client: AsyncClient):
        r = await client.post(
            "/agents/register",
            json={"name": "ViolationAgent", "capabilities": [], "permissions": []},
        )
        agent = r.json()
        sig = sign_proposal(
            agent["private_key"],
            agent["agent_id"],
            title="Violation",
            description="Test description",
            proposed_action="noop",
            risk_level="low",
        )
        await client.post(
            "/proposals",
            json={
                "title": "Violation",
                "description": "Test description",
                "proposed_action": "noop",
                "risk_level": "low",
                "action_params": {},
                "agent_id": agent["agent_id"],
                "signature": sig,
            },
        )
        violations = await client.get("/policy/violations")
        assert violations.status_code == 200
        assert len(violations.json()) >= 1

    async def test_wildcard_permission_allows_all(self, client: AsyncClient):
        r = await client.post(
            "/agents/register",
            json={"name": "SuperAgent", "capabilities": [], "permissions": ["*"]},
        )
        agent = r.json()
        resp = await client.post(
            "/policy/check",
            json={"agent_id": agent["agent_id"], "action": "anything"},
        )
        assert resp.json()["allowed"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Audit Trail
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.anyio
class TestAuditTrail:
    async def test_audit_chain_valid_after_operations(self, client: AsyncClient, two_agents):
        proposer, voter = two_agents
        proposal_id = await _submit_proposal(client, proposer, risk_level="low")
        await _cast_vote(client, voter, proposal_id, vote=True)
        resp = await client.get("/audit/verify")
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is True
        assert body["chain_length"] > 0

    async def test_audit_entries_returned(self, client: AsyncClient, registered_agent):
        resp = await client.get("/audit")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
        # At least the registration event
        assert len(resp.json()) >= 1

    async def test_audit_filter_by_agent(self, client: AsyncClient, registered_agent):
        agent_id = registered_agent["agent_id"]
        resp = await client.get(f"/audit?agent_id={agent_id}")
        assert resp.status_code == 200
        for entry in resp.json():
            assert entry["agent_id"] == agent_id

    async def test_audit_filter_by_action(self, client: AsyncClient, registered_agent):
        resp = await client.get("/audit?action=agent_registered")
        assert resp.status_code == 200
        for entry in resp.json():
            assert entry["action"] == "agent_registered"

    async def test_audit_chain_hash_chaining(self, client: AsyncClient, registered_agent):
        # Register a second agent to add more entries
        await client.post(
            "/agents/register",
            json={"name": "Agent2", "capabilities": [], "permissions": []},
        )
        # Verify each entry's previous_hash matches the preceding entry's entry_hash
        for i in range(1, len(audit_chain)):
            assert audit_chain[i]["previous_hash"] == audit_chain[i - 1]["entry_hash"]

    async def test_audit_chain_starts_from_genesis(self, client: AsyncClient, registered_agent):
        assert audit_chain[0]["previous_hash"] == GENESIS_HASH

    async def test_empty_chain_is_valid(self, client: AsyncClient):
        resp = await client.get("/audit/verify")
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    async def test_audit_limit_parameter(self, client: AsyncClient):
        # Register several agents to fill audit chain
        for i in range(10):
            await client.post(
                "/agents/register",
                json={"name": f"A{i}", "capabilities": [], "permissions": []},
            )
        resp = await client.get("/audit?limit=3")
        assert resp.status_code == 200
        assert len(resp.json()) <= 3


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Executions
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.anyio
class TestExecutions:
    async def test_executions_list_empty_initially(self, client: AsyncClient):
        resp = await client.get("/executions")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_executed_proposal_appears_in_executions(self, client: AsyncClient, two_agents):
        proposer, voter = two_agents
        proposal_id = await _submit_proposal(client, proposer, risk_level="low")
        await _cast_vote(client, voter, proposal_id, vote=True)
        resp = await client.get("/executions")
        assert resp.status_code == 200
        assert len(resp.json()) == 1
        assert resp.json()[0]["proposal_id"] == proposal_id


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Metrics & System Endpoints
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.anyio
class TestMetrics:
    async def test_root_endpoint(self, client: AsyncClient):
        resp = await client.get("/")
        assert resp.status_code == 200
        body = resp.json()
        assert body["system"] == "Zero-Human Governance Core"
        assert body["version"] == "2.0.0"
        assert body["status"] == "operational"

    async def test_health_endpoint(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    async def test_metrics_structure(self, client: AsyncClient, two_agents):
        proposer, voter = two_agents
        proposal_id = await _submit_proposal(client, proposer, risk_level="low")
        await _cast_vote(client, voter, proposal_id, vote=True)
        resp = await client.get("/metrics")
        assert resp.status_code == 200
        body = resp.json()
        assert body["agents"]["total"] == 2
        assert body["agents"]["active"] == 2
        assert body["proposals"]["total"] == 1
        assert body["proposals"]["executed"] == 1

    async def test_dashboard_html_response(self, client: AsyncClient):
        resp = await client.get("/dashboard")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Governance" in resp.text

    async def test_dashboard_data_endpoint(self, client: AsyncClient, registered_agent):
        resp = await client.get("/dashboard/data")
        assert resp.status_code == 200
        body = resp.json()
        assert "metrics" in body
        assert "agents" in body
        assert "proposals" in body
        assert "executions" in body
        assert "audit_sample" in body
        assert "audit_verification" in body
