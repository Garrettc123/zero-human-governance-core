"""Shared pytest fixtures for the governance test suite."""

import pytest
from httpx import AsyncClient, ASGITransport

# ── Import app & crypto (handle both package and module paths) ────────────────
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from governance.main import (
    app,
    agents_db,
    proposals_db,
    votes_db,
    audit_chain,
    executed_actions,
)
from governance.crypto import generate_keypair, sign_data


# ── Helpers ───────────────────────────────────────────────────────────────────


def make_agent_payload(name: str, capabilities=None, permissions=None) -> dict:
    return {
        "name": name,
        "capabilities": capabilities or ["market_scan"],
        "permissions": permissions or ["propose", "vote"],
    }


def sign_proposal(private_key: str, agent_id: str, **kwargs) -> str:
    """Sign a proposal payload.  All fields default to the same values used in
    the POST body so signatures always match the request."""
    payload = {
        "title": kwargs.get("title", "Test Proposal"),
        "description": kwargs.get("description", "Test description"),
        "proposed_action": kwargs.get("proposed_action", "noop"),
        "risk_level": kwargs.get("risk_level", "low"),
        "action_params": kwargs.get("action_params", {}),
        "agent_id": agent_id,
    }
    return sign_data(private_key, payload)


def sign_vote(private_key: str, agent_id: str, proposal_id: str, vote: bool, reason: str = "") -> str:
    payload = {
        "proposal_id": proposal_id,
        "vote": vote,
        "reason": reason,
        "agent_id": agent_id,
    }
    return sign_data(private_key, payload)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def clear_state():
    """Reset all in-memory stores before each test."""
    agents_db.clear()
    proposals_db.clear()
    votes_db.clear()
    audit_chain.clear()
    executed_actions.clear()
    yield


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    """Async HTTP client bound to the FastAPI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def registered_agent(client):
    """Register a default agent and return its full registration payload."""
    resp = await client.post(
        "/agents/register",
        json=make_agent_payload("TestAgent"),
    )
    assert resp.status_code == 200
    return resp.json()


@pytest.fixture
async def two_agents(client):
    """Return two registered agents."""
    r1 = await client.post(
        "/agents/register",
        json=make_agent_payload("AgentAlpha"),
    )
    r2 = await client.post(
        "/agents/register",
        json=make_agent_payload("AgentBeta"),
    )
    assert r1.status_code == 200
    assert r2.status_code == 200
    return r1.json(), r2.json()
