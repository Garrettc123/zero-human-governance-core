"""Regression tests: agent provisioning and status changes must fail closed."""

import pytest
from httpx import ASGITransport, AsyncClient

from governance.main import app, agents_db, audit_chain


@pytest.mark.anyio
async def test_registration_requires_operator_credential():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as anonymous:
        response = await anonymous.post(
            "/agents/register",
            json={"name": "PrivilegeSeeker", "capabilities": ["all"], "permissions": ["*"]},
        )
    assert response.status_code == 403
    assert agents_db == {}
    assert audit_chain == []


@pytest.mark.anyio
async def test_registration_rejects_invalid_operator_credential(client):
    response = await client.post(
        "/agents/register",
        headers={"X-Garcar-Admin-Token": "incorrect-secret"},
        json={"name": "Unauthorized", "permissions": ["*"]},
    )
    assert response.status_code == 403
    assert not agents_db


@pytest.mark.anyio
async def test_missing_secret_fails_closed(client, monkeypatch):
    monkeypatch.delenv("GOVERNANCE_ADMIN_TOKEN", raising=False)
    response = await client.post(
        "/agents/register",
        json={"name": "Unauthorized", "permissions": ["*"]},
    )
    assert response.status_code == 503
    assert not agents_db


@pytest.mark.anyio
async def test_short_secret_fails_closed(client, monkeypatch):
    monkeypatch.setenv("GOVERNANCE_ADMIN_TOKEN", "short")
    response = await client.post(
        "/agents/register",
        json={"name": "Unauthorized", "permissions": ["*"]},
    )
    assert response.status_code == 503
    assert not agents_db


@pytest.mark.anyio
async def test_authenticated_registration_retains_declared_permissions(client):
    response = await client.post(
        "/agents/register",
        json={"name": "Authorized", "capabilities": ["scan"], "permissions": ["propose"]},
    )
    assert response.status_code == 200
    assert response.json()["permissions"] == ["propose"]
    assert response.json()["agent_id"] in agents_db


@pytest.mark.anyio
async def test_anonymous_status_change_cannot_suspend_agent(client, registered_agent):
    agent_id = registered_agent["agent_id"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as anonymous:
        response = await anonymous.put(f"/agents/{agent_id}/status?status=suspended")
    assert response.status_code == 403
    assert agents_db[agent_id]["status"] == "active"


@pytest.mark.anyio
async def test_wrong_token_cannot_suspend_agent(client, registered_agent):
    agent_id = registered_agent["agent_id"]
    response = await client.put(
        f"/agents/{agent_id}/status?status=suspended",
        headers={"X-Garcar-Admin-Token": "incorrect-secret"},
    )
    assert response.status_code == 403
    assert agents_db[agent_id]["status"] == "active"


@pytest.mark.anyio
async def test_authorized_operator_can_suspend_agent(client, registered_agent):
    agent_id = registered_agent["agent_id"]
    response = await client.put(f"/agents/{agent_id}/status?status=suspended")
    assert response.status_code == 200
    assert agents_db[agent_id]["status"] == "suspended"
