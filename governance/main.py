"""Zero-Human Governance Core — FastAPI Application.

Implements:
  • Cryptographic agent identity (Ed25519 keypairs)
  • Governance proposals with threshold-based voting
  • Immutable audit trail with cryptographic chain
  • Agent registry with capabilities and permissions
  • Policy enforcement (blocks unauthorized actions)
  • Multi-sig approval for high-risk operations
  • Governance dashboard (HTML + JSON)
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

try:
    from .crypto import (
        compute_chain_hash,
        compute_hash,
        generate_keypair,
        sign_data,
        verify_signature,
    )
except ImportError:
    from crypto import (  # type: ignore[no-redef]
        compute_chain_hash,
        compute_hash,
        generate_keypair,
        sign_data,
        verify_signature,
    )

# ── Application ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="Zero-Human Governance Core",
    description="Cryptographic governance and orchestration for autonomous AI agents",
    version="2.0.0",
)

# ── Constants ─────────────────────────────────────────────────────────────────

# Minimum fraction of *eligible* voters that must approve.
# low and medium share the simple majority (50%) threshold; high and
# critical require super-majority votes to model multi-sig approval.
RISK_THRESHOLDS: Dict[str, float] = {
    "low": 0.50,
    "medium": 0.50,
    "high": 0.67,
    "critical": 0.80,
}

# Minimum number of distinct yes-votes required (multi-sig)
MIN_VOTES_REQUIRED: Dict[str, int] = {
    "low": 1,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

GENESIS_HASH = "0" * 64

# ── In-Memory Stores ──────────────────────────────────────────────────────────
# Replace with a persistent database (e.g. PostgreSQL + SQLAlchemy) in production.

agents_db: Dict[str, Dict] = {}        # agent_id → agent record
proposals_db: Dict[str, Dict] = {}     # proposal_id → proposal record
votes_db: Dict[str, List[Dict]] = {}   # proposal_id → list of vote records
audit_chain: List[Dict] = []           # ordered, tamper-evident log
executed_actions: List[Dict] = []      # executed proposal records

# ── Pydantic Models ───────────────────────────────────────────────────────────


class AgentRegistrationRequest(BaseModel):
    name: str = Field(..., description="Human-readable agent name")
    capabilities: List[str] = Field(
        default=[],
        description="Things this agent can do (e.g. 'market_scan')",
    )
    permissions: List[str] = Field(
        default=[],
        description="Allowed governance actions (e.g. 'propose', 'vote')",
    )


class AgentRegistrationResponse(BaseModel):
    agent_id: str
    name: str
    public_key: str
    private_key: str = Field(
        ...,
        description="ONE-TIME: store securely — server does NOT persist this",
    )
    capabilities: List[str]
    permissions: List[str]
    status: str
    created_at: str


class AgentInfo(BaseModel):
    agent_id: str
    name: str
    public_key: str
    capabilities: List[str]
    permissions: List[str]
    status: str
    created_at: str
    last_active: str


class ProposalRequest(BaseModel):
    title: str
    description: str
    proposed_action: str = Field(..., description="Action executed if the proposal passes")
    risk_level: str = Field(default="medium", description="low | medium | high | critical")
    action_params: Dict[str, Any] = Field(default_factory=dict)
    agent_id: str = Field(..., description="ID of the submitting agent")
    signature: str = Field(
        ...,
        description="Ed25519 signature of the proposal payload (sorted-key JSON)",
    )


class ProposalResponse(BaseModel):
    proposal_id: str
    title: str
    description: str
    proposed_action: str
    risk_level: str
    action_params: Dict[str, Any]
    proposed_by: str
    status: str
    votes_for: List[str]
    votes_against: List[str]
    required_threshold: float
    min_votes_required: int
    created_at: str
    executed_at: Optional[str]
    signature: str


class VoteRequest(BaseModel):
    vote: bool = Field(..., description="True = approve, False = reject")
    reason: str = Field(default="")
    agent_id: str
    signature: str = Field(..., description="Ed25519 signature over the vote payload")


class VoteResponse(BaseModel):
    vote_id: str
    proposal_id: str
    voter_id: str
    vote: bool
    reason: str
    timestamp: str
    signature: str
    proposal_status: str
    execution_triggered: bool


class AuditEntryModel(BaseModel):
    entry_id: str
    timestamp: str
    agent_id: str
    action: str
    resource: str
    details: Dict[str, Any]
    previous_hash: str
    entry_hash: str
    signature: str


class AuditVerificationResponse(BaseModel):
    valid: bool
    chain_length: int
    issues: List[str]


class PolicyCheckRequest(BaseModel):
    agent_id: str
    action: str
    resource: str = ""


class PolicyCheckResponse(BaseModel):
    allowed: bool
    reason: str
    agent_id: str
    action: str


# ── Helper Functions ──────────────────────────────────────────────────────────


def utcnow() -> str:
    """Current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def get_active_agents() -> List[Dict]:
    return [a for a in agents_db.values() if a["status"] == "active"]


def verify_agent_request(agent_id: str, signed_data: dict, signature: str) -> None:
    """Verify a signed request from an agent.

    Raises HTTPException(404) if the agent does not exist,
    HTTPException(403) if inactive or signature invalid.
    """
    if agent_id not in agents_db:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    agent = agents_db[agent_id]
    if agent["status"] != "active":
        raise HTTPException(
            status_code=403, detail=f"Agent '{agent_id}' is not active"
        )
    if not verify_signature(agent["public_key"], signed_data, signature):
        raise HTTPException(status_code=403, detail="Invalid agent signature")
    agents_db[agent_id]["last_active"] = utcnow()


def append_audit_entry(
    agent_id: str,
    action: str,
    resource: str,
    details: Dict[str, Any],
    private_key_b64: Optional[str] = None,
) -> Dict:
    """Append a new entry to the cryptographic audit chain.

    Each entry stores a SHA-256 hash that incorporates the previous entry's
    hash, creating a tamper-evident chain.  If *private_key_b64* is provided
    the entry is additionally signed with that key.
    """
    previous_hash = audit_chain[-1]["entry_hash"] if audit_chain else GENESIS_HASH
    entry_id = str(uuid.uuid4())
    timestamp = utcnow()

    core: Dict[str, Any] = {
        "entry_id": entry_id,
        "timestamp": timestamp,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "details": details,
        "previous_hash": previous_hash,
    }

    entry_hash = compute_chain_hash(core, previous_hash)

    if private_key_b64:
        signature = sign_data(private_key_b64, {**core, "entry_hash": entry_hash})
    else:
        # Use the entry hash as a self-referential integrity proof
        signature = entry_hash

    entry = {**core, "entry_hash": entry_hash, "signature": signature}
    audit_chain.append(entry)
    return entry


def check_policy(agent_id: str, action: str) -> tuple:
    """Return (allowed: bool, reason: str) for an agent/action pair."""
    if agent_id not in agents_db:
        return False, f"Agent '{agent_id}' not registered"
    agent = agents_db[agent_id]
    if agent["status"] != "active":
        return False, f"Agent '{agent_id}' is suspended or inactive"
    permissions = agent.get("permissions", [])
    if action in permissions or "*" in permissions or "all" in permissions:
        return True, f"Agent '{agent_id}' has permission for '{action}'"
    capabilities = agent.get("capabilities", [])
    if action in capabilities:
        return True, f"Agent '{agent_id}' has capability '{action}'"
    return False, f"Agent '{agent_id}' is not permitted to perform '{action}'"


def _get_eligible_voters(proposal_id: str) -> List[Dict]:
    """Active agents that are eligible to vote (excludes the proposer)."""
    proposer = proposals_db[proposal_id]["proposed_by"]
    return [a for a in get_active_agents() if a["agent_id"] != proposer]


def try_execute_proposal(proposal_id: str) -> bool:
    """Check voting thresholds and execute or reject the proposal if decided.

    Returns True if the proposal was executed.
    """
    proposal = proposals_db[proposal_id]
    if proposal["status"] != "pending":
        return False

    eligible = _get_eligible_voters(proposal_id)
    total_eligible = len(eligible)
    if total_eligible == 0:
        return False

    votes_for = len(proposal["votes_for"])
    votes_against = len(proposal["votes_against"])
    total_votes = votes_for + votes_against

    threshold = proposal["required_threshold"]
    min_votes = proposal["min_votes_required"]

    # Approval: enough yes-votes and fraction of eligible voters satisfied.
    # total_eligible > 0 is guaranteed by the early-return guard above.
    if votes_for >= min_votes and votes_for / total_eligible >= threshold:
        execution_record = {
            "execution_id": str(uuid.uuid4()),
            "proposal_id": proposal_id,
            "proposal_title": proposal["title"],
            "proposed_action": proposal["proposed_action"],
            "action_params": proposal["action_params"],
            "risk_level": proposal["risk_level"],
            "executed_at": utcnow(),
            "votes_for": votes_for,
            "votes_against": votes_against,
            "total_eligible": total_eligible,
        }
        executed_actions.append(execution_record)
        proposal["status"] = "executed"
        proposal["executed_at"] = execution_record["executed_at"]
        append_audit_entry(
            agent_id="governance_system",
            action="proposal_executed",
            resource=f"proposal:{proposal_id}",
            details=execution_record,
        )
        return True

    # Early rejection: remaining possible votes cannot reach threshold
    remaining = total_eligible - total_votes
    max_possible_for = votes_for + remaining
    if max_possible_for < min_votes or (
        total_eligible > 0 and max_possible_for / total_eligible < threshold
    ):
        proposal["status"] = "rejected"
        proposal["executed_at"] = utcnow()
        append_audit_entry(
            agent_id="governance_system",
            action="proposal_rejected",
            resource=f"proposal:{proposal_id}",
            details={
                "proposal_id": proposal_id,
                "votes_for": votes_for,
                "votes_against": votes_against,
                "total_eligible": total_eligible,
                "reason": "threshold unreachable",
            },
        )

    return False


# ── Endpoints: System ─────────────────────────────────────────────────────────


@app.get("/", tags=["System"])
async def root():
    """System status."""
    return {
        "system": "Zero-Human Governance Core",
        "version": "2.0.0",
        "status": "operational",
        "agents": len(agents_db),
        "active_agents": len(get_active_agents()),
        "proposals": len(proposals_db),
        "executed_actions": len(executed_actions),
        "audit_entries": len(audit_chain),
        "timestamp": utcnow(),
    }


@app.get("/health", tags=["System"])
async def health():
    """Health check."""
    return {"status": "healthy", "timestamp": utcnow()}


# ── Endpoints: Agent Registry ─────────────────────────────────────────────────


@app.post("/agents/register", response_model=AgentRegistrationResponse, tags=["Agents"])
async def register_agent(request: AgentRegistrationRequest):
    """Register a new AI agent and issue an Ed25519 keypair.

    The **private key** is returned exactly once in this response and is
    *never* stored server-side.  The caller must persist it securely.
    """
    private_key, public_key = generate_keypair()
    agent_id = str(uuid.uuid4())
    now = utcnow()
    agent = {
        "agent_id": agent_id,
        "name": request.name,
        "public_key": public_key,
        "capabilities": request.capabilities,
        "permissions": request.permissions,
        "status": "active",
        "created_at": now,
        "last_active": now,
    }
    agents_db[agent_id] = agent
    append_audit_entry(
        agent_id=agent_id,
        action="agent_registered",
        resource=f"agent:{agent_id}",
        details={"name": request.name, "capabilities": request.capabilities},
    )
    return {**agent, "private_key": private_key}


@app.get("/agents", response_model=List[AgentInfo], tags=["Agents"])
async def list_agents():
    """List all registered agents."""
    return list(agents_db.values())


@app.get("/agents/{agent_id}", response_model=AgentInfo, tags=["Agents"])
async def get_agent(agent_id: str):
    """Get a specific agent's details."""
    if agent_id not in agents_db:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return agents_db[agent_id]


@app.put("/agents/{agent_id}/status", tags=["Agents"])
async def update_agent_status(agent_id: str, status: str):
    """Update an agent's status (active | suspended | inactive)."""
    if agent_id not in agents_db:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    if status not in ("active", "suspended", "inactive"):
        raise HTTPException(
            status_code=400,
            detail="status must be 'active', 'suspended', or 'inactive'",
        )
    old_status = agents_db[agent_id]["status"]
    agents_db[agent_id]["status"] = status
    append_audit_entry(
        agent_id="governance_system",
        action="agent_status_updated",
        resource=f"agent:{agent_id}",
        details={"agent_id": agent_id, "old_status": old_status, "new_status": status},
    )
    return {"agent_id": agent_id, "status": status, "updated_at": utcnow()}


# ── Endpoints: Governance Proposals ──────────────────────────────────────────


@app.post("/proposals", response_model=ProposalResponse, tags=["Governance"])
async def submit_proposal(request: ProposalRequest):
    """Submit a governance proposal (any registered agent may submit).

    The request body must include an Ed25519 *signature* of the proposal
    payload (sorted-key JSON) so the server can verify authorship.
    """
    if request.risk_level not in RISK_THRESHOLDS:
        raise HTTPException(
            status_code=400,
            detail=f"risk_level must be one of {list(RISK_THRESHOLDS)}",
        )

    signed_payload = {
        "title": request.title,
        "description": request.description,
        "proposed_action": request.proposed_action,
        "risk_level": request.risk_level,
        "action_params": request.action_params,
        "agent_id": request.agent_id,
    }
    verify_agent_request(request.agent_id, signed_payload, request.signature)

    # Policy check
    allowed, reason = check_policy(request.agent_id, "propose")
    if not allowed:
        allowed, reason = check_policy(request.agent_id, "submit_proposals")
    if not allowed:
        append_audit_entry(
            agent_id=request.agent_id,
            action="policy_violation",
            resource="proposals",
            details={"attempted_action": "submit_proposal", "reason": reason},
        )
        raise HTTPException(status_code=403, detail=f"Policy violation: {reason}")

    proposal_id = str(uuid.uuid4())
    now = utcnow()
    proposal: Dict[str, Any] = {
        "proposal_id": proposal_id,
        "title": request.title,
        "description": request.description,
        "proposed_action": request.proposed_action,
        "risk_level": request.risk_level,
        "action_params": request.action_params,
        "proposed_by": request.agent_id,
        "status": "pending",
        "votes_for": [],
        "votes_against": [],
        "required_threshold": RISK_THRESHOLDS[request.risk_level],
        "min_votes_required": MIN_VOTES_REQUIRED[request.risk_level],
        "created_at": now,
        "executed_at": None,
        "signature": request.signature,
    }
    proposals_db[proposal_id] = proposal
    votes_db[proposal_id] = []

    append_audit_entry(
        agent_id=request.agent_id,
        action="proposal_submitted",
        resource=f"proposal:{proposal_id}",
        details={
            "proposal_id": proposal_id,
            "title": request.title,
            "risk_level": request.risk_level,
            "required_threshold": RISK_THRESHOLDS[request.risk_level],
            "min_votes_required": MIN_VOTES_REQUIRED[request.risk_level],
        },
    )
    return proposal


@app.get("/proposals", response_model=List[ProposalResponse], tags=["Governance"])
async def list_proposals(
    status: Optional[str] = None, risk_level: Optional[str] = None
):
    """List proposals, optionally filtered by status or risk_level."""
    results = list(proposals_db.values())
    if status:
        results = [p for p in results if p["status"] == status]
    if risk_level:
        results = [p for p in results if p["risk_level"] == risk_level]
    return results


@app.get("/proposals/{proposal_id}", response_model=ProposalResponse, tags=["Governance"])
async def get_proposal(proposal_id: str):
    """Get a specific proposal."""
    if proposal_id not in proposals_db:
        raise HTTPException(
            status_code=404, detail=f"Proposal '{proposal_id}' not found"
        )
    return proposals_db[proposal_id]


@app.post(
    "/proposals/{proposal_id}/vote",
    response_model=VoteResponse,
    tags=["Governance"],
)
async def vote_on_proposal(proposal_id: str, request: VoteRequest):
    """Cast a signed vote on a pending proposal.

    Rules:
    * The proposer may not vote on their own proposal.
    * Each agent may vote at most once.
    * The proposal is automatically executed (or rejected) once a voting
      threshold is reached.
    """
    if proposal_id not in proposals_db:
        raise HTTPException(
            status_code=404, detail=f"Proposal '{proposal_id}' not found"
        )
    proposal = proposals_db[proposal_id]
    if proposal["status"] != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Proposal is not pending (status: {proposal['status']})",
        )

    # Policy check
    allowed, reason = check_policy(request.agent_id, "vote")
    if not allowed:
        raise HTTPException(status_code=403, detail=f"Policy violation: {reason}")

    # Signature verification
    signed_payload = {
        "proposal_id": proposal_id,
        "vote": request.vote,
        "reason": request.reason,
        "agent_id": request.agent_id,
    }
    verify_agent_request(request.agent_id, signed_payload, request.signature)

    # Proposer cannot vote
    if request.agent_id == proposal["proposed_by"]:
        raise HTTPException(
            status_code=400,
            detail="The proposing agent may not vote on their own proposal",
        )

    # Duplicate vote guard
    if (
        request.agent_id in proposal["votes_for"]
        or request.agent_id in proposal["votes_against"]
    ):
        raise HTTPException(
            status_code=400, detail="Agent has already voted on this proposal"
        )

    vote_id = str(uuid.uuid4())
    timestamp = utcnow()
    vote_record = {
        "vote_id": vote_id,
        "proposal_id": proposal_id,
        "voter_id": request.agent_id,
        "vote": request.vote,
        "reason": request.reason,
        "timestamp": timestamp,
        "signature": request.signature,
    }
    votes_db[proposal_id].append(vote_record)

    if request.vote:
        proposal["votes_for"].append(request.agent_id)
    else:
        proposal["votes_against"].append(request.agent_id)

    append_audit_entry(
        agent_id=request.agent_id,
        action="vote_cast",
        resource=f"proposal:{proposal_id}",
        details={
            "proposal_id": proposal_id,
            "vote": request.vote,
            "reason": request.reason,
            "votes_for": len(proposal["votes_for"]),
            "votes_against": len(proposal["votes_against"]),
        },
    )

    execution_triggered = try_execute_proposal(proposal_id)

    return {
        **vote_record,
        "proposal_status": proposal["status"],
        "execution_triggered": execution_triggered,
    }


@app.get("/proposals/{proposal_id}/votes", tags=["Governance"])
async def get_proposal_votes(proposal_id: str):
    """Get all votes for a proposal."""
    if proposal_id not in proposals_db:
        raise HTTPException(
            status_code=404, detail=f"Proposal '{proposal_id}' not found"
        )
    proposal = proposals_db[proposal_id]
    eligible = _get_eligible_voters(proposal_id)
    return {
        "proposal_id": proposal_id,
        "votes": votes_db.get(proposal_id, []),
        "summary": {
            "votes_for": len(proposal["votes_for"]),
            "votes_against": len(proposal["votes_against"]),
            "total_eligible": len(eligible),
            "required_threshold": proposal["required_threshold"],
            "min_votes_required": proposal["min_votes_required"],
        },
    }


# ── Endpoints: Audit Trail ────────────────────────────────────────────────────


@app.get("/audit", response_model=List[AuditEntryModel], tags=["Audit"])
async def get_audit_trail(
    agent_id: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 100,
):
    """Return the cryptographic audit trail, optionally filtered."""
    results = audit_chain
    if agent_id:
        results = [e for e in results if e["agent_id"] == agent_id]
    if action:
        results = [e for e in results if e["action"] == action]
    return results[-limit:]


@app.get("/audit/verify", response_model=AuditVerificationResponse, tags=["Audit"])
async def verify_audit_chain():
    """Verify audit-chain integrity by recomputing and comparing all hashes."""
    issues: List[str] = []
    if not audit_chain:
        return {"valid": True, "chain_length": 0, "issues": []}

    previous_hash = GENESIS_HASH
    for i, entry in enumerate(audit_chain):
        core = {
            k: v for k, v in entry.items() if k not in ("entry_hash", "signature")
        }
        expected_hash = compute_chain_hash(core, previous_hash)
        if entry["entry_hash"] != expected_hash:
            issues.append(
                f"Entry {i} (id={entry['entry_id'][:8]}): hash mismatch"
            )
        if entry["previous_hash"] != previous_hash:
            issues.append(
                f"Entry {i} (id={entry['entry_id'][:8]}): chain link broken"
            )
        previous_hash = entry["entry_hash"]

    return {"valid": len(issues) == 0, "chain_length": len(audit_chain), "issues": issues}


# ── Endpoints: Executions ─────────────────────────────────────────────────────


@app.get("/executions", tags=["Executions"])
async def list_executed_actions():
    """List all executed governance actions."""
    return executed_actions


# ── Endpoints: Policy ─────────────────────────────────────────────────────────


@app.post("/policy/check", response_model=PolicyCheckResponse, tags=["Policy"])
async def check_agent_policy(request: PolicyCheckRequest):
    """Check whether an agent is permitted to perform an action."""
    allowed, reason = check_policy(request.agent_id, request.action)
    return {
        "allowed": allowed,
        "reason": reason,
        "agent_id": request.agent_id,
        "action": request.action,
    }


@app.get("/policy/violations", tags=["Policy"])
async def get_policy_violations():
    """Return all policy violation events from the audit trail."""
    return [e for e in audit_chain if e["action"] == "policy_violation"]


# ── Endpoints: Metrics ────────────────────────────────────────────────────────


@app.get("/metrics", tags=["System"])
async def get_metrics():
    """System-wide governance metrics."""
    return {
        "agents": {
            "total": len(agents_db),
            "active": len(get_active_agents()),
            "suspended": sum(
                1 for a in agents_db.values() if a["status"] == "suspended"
            ),
        },
        "proposals": {
            "total": len(proposals_db),
            "pending": sum(
                1 for p in proposals_db.values() if p["status"] == "pending"
            ),
            "approved": sum(
                1
                for p in proposals_db.values()
                if p["status"] in ("approved", "executed")
            ),
            "rejected": sum(
                1 for p in proposals_db.values() if p["status"] == "rejected"
            ),
            "executed": len(executed_actions),
        },
        "audit": {
            "total_entries": len(audit_chain),
            "violations": sum(
                1 for e in audit_chain if e["action"] == "policy_violation"
            ),
        },
        "timestamp": utcnow(),
    }


# ── Dashboard ─────────────────────────────────────────────────────────────────

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Zero-Human Governance Core</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background:#0d1117; color:#e6edf3; }
    .navbar { background:#161b22!important; border-bottom:1px solid #30363d; }
    .card { background:#161b22; border:1px solid #30363d; }
    .card-header { background:#21262d; border-bottom:1px solid #30363d; font-weight:600; }
    td, th { color:#e6edf3!important; border-color:#30363d!important; }
    .badge-low    { background:#2ea043; }
    .badge-medium { background:#d29922; }
    .badge-high   { background:#d97706; }
    .badge-critical { background:#f85149; }
    .badge-pending  { background:#388bfd; }
    .badge-executed { background:#2ea043; }
    .badge-rejected { background:#f85149; }
    .badge-active   { background:#2ea043; }
    .badge-suspended{ background:#f85149; }
    .hash { color:#8b949e; font-size:.75em; font-family:monospace; }
    .refresh { font-size:.8em; color:#8b949e; }
  </style>
</head>
<body>
<nav class="navbar navbar-dark px-4 py-2 d-flex justify-content-between">
  <span class="navbar-brand fw-bold">&#128737; Zero-Human Governance Core</span>
  <span class="refresh" id="ts">Loading…</span>
</nav>

<div class="container-fluid mt-4 px-4">
  <!-- Stat cards -->
  <div class="row g-3 mb-4">
    <div class="col-md-3"><div class="card p-3">
      <div class="text-muted small">Active Agents</div>
      <h2 id="s-agents">—</h2>
      <small class="text-muted" id="s-agents-total"></small>
    </div></div>
    <div class="col-md-3"><div class="card p-3">
      <div class="text-muted small">Pending Proposals</div>
      <h2 id="s-pending">—</h2>
      <small class="text-muted" id="s-proposals-total"></small>
    </div></div>
    <div class="col-md-3"><div class="card p-3">
      <div class="text-muted small">Executed Actions</div>
      <h2 id="s-exec">—</h2>
      <small class="text-muted" id="s-rate"></small>
    </div></div>
    <div class="col-md-3"><div class="card p-3">
      <div class="text-muted small">Audit Entries</div>
      <h2 id="s-audit">—</h2>
      <small class="text-muted" id="s-violations"></small>
    </div></div>
  </div>

  <div class="row g-3 mb-4">
    <!-- Agents -->
    <div class="col-md-4"><div class="card h-100">
      <div class="card-header">&#128100; Active Agents</div>
      <div class="card-body p-0">
        <table class="table table-sm mb-0">
          <thead><tr><th>Name</th><th>Status</th><th>Capabilities</th></tr></thead>
          <tbody id="t-agents"><tr><td colspan="3" class="text-center text-muted p-3">Loading…</td></tr></tbody>
        </table>
      </div>
    </div></div>
    <!-- Proposals -->
    <div class="col-md-8"><div class="card h-100">
      <div class="card-header">&#128203; Governance Proposals</div>
      <div class="card-body p-0">
        <table class="table table-sm mb-0">
          <thead><tr><th>Title</th><th>Risk</th><th>Status</th><th>Votes ✓/✗</th><th>Threshold</th></tr></thead>
          <tbody id="t-proposals"><tr><td colspan="5" class="text-center text-muted p-3">Loading…</td></tr></tbody>
        </table>
      </div>
    </div></div>
  </div>

  <div class="row g-3 mb-4">
    <!-- Executions -->
    <div class="col-md-5"><div class="card h-100">
      <div class="card-header">&#9889; Executed Actions</div>
      <div class="card-body p-0">
        <table class="table table-sm mb-0">
          <thead><tr><th>Action</th><th>Risk</th><th>Votes</th><th>Time</th></tr></thead>
          <tbody id="t-exec"><tr><td colspan="4" class="text-center text-muted p-3">No executions yet</td></tr></tbody>
        </table>
      </div>
    </div></div>
    <!-- Audit log -->
    <div class="col-md-7"><div class="card h-100">
      <div class="card-header">
        &#128269; Audit Trail
        <span class="badge ms-2" id="chain-badge">Verifying…</span>
      </div>
      <div class="card-body p-0" style="max-height:420px;overflow-y:auto">
        <div id="audit-log" class="p-2 small">Loading…</div>
      </div>
    </div></div>
  </div>
</div>

<script>
async function refresh() {
  try {
    const [m, agents, proposals, execs, audit, verify] = await Promise.all([
      fetch('/metrics').then(r=>r.json()),
      fetch('/agents').then(r=>r.json()),
      fetch('/proposals').then(r=>r.json()),
      fetch('/executions').then(r=>r.json()),
      fetch('/audit?limit=60').then(r=>r.json()),
      fetch('/audit/verify').then(r=>r.json()),
    ]);

    document.getElementById('s-agents').textContent = m.agents.active;
    document.getElementById('s-agents-total').textContent = m.agents.total + ' total';
    document.getElementById('s-pending').textContent = m.proposals.pending;
    document.getElementById('s-proposals-total').textContent = m.proposals.total + ' total';
    document.getElementById('s-exec').textContent = m.proposals.executed;
    const tot = m.proposals.approved + m.proposals.rejected;
    document.getElementById('s-rate').textContent = tot
      ? Math.round(m.proposals.approved/tot*100)+'% approval rate' : '—';
    document.getElementById('s-audit').textContent = m.audit.total_entries;
    document.getElementById('s-violations').textContent = m.audit.violations + ' violations';

    const cb = document.getElementById('chain-badge');
    cb.textContent = verify.valid ? '✓ Chain Valid' : '⚠ Chain Issues';
    cb.className = 'badge ms-2 ' + (verify.valid ? 'bg-success' : 'bg-danger');

    document.getElementById('t-agents').innerHTML = agents.length
      ? agents.map(a=>`<tr>
          <td><strong>${a.name}</strong><br><span class="hash">${a.agent_id.slice(0,8)}…</span></td>
          <td><span class="badge badge-${a.status}">${a.status}</span></td>
          <td><small>${(a.capabilities||[]).slice(0,3).join(', ')||'—'}</small></td>
        </tr>`).join('')
      : '<tr><td colspan="3" class="text-center text-muted p-3">No agents</td></tr>';

    document.getElementById('t-proposals').innerHTML = proposals.length
      ? proposals.slice(-20).reverse().map(p=>`<tr>
          <td><strong>${p.title}</strong></td>
          <td><span class="badge badge-${p.risk_level}">${p.risk_level}</span></td>
          <td><span class="badge badge-${p.status}">${p.status}</span></td>
          <td>${(p.votes_for||[]).length} / ${(p.votes_against||[]).length}</td>
          <td>${Math.round(p.required_threshold*100)}%</td>
        </tr>`).join('')
      : '<tr><td colspan="5" class="text-center text-muted p-3">No proposals</td></tr>';

    document.getElementById('t-exec').innerHTML = execs.length
      ? execs.slice(-20).reverse().map(e=>`<tr>
          <td><small>${e.proposed_action}</small></td>
          <td><span class="badge badge-${e.risk_level}">${e.risk_level}</span></td>
          <td>${e.votes_for}/${e.total_eligible}</td>
          <td><small>${new Date(e.executed_at).toLocaleTimeString()}</small></td>
        </tr>`).join('')
      : '<tr><td colspan="4" class="text-center text-muted p-3">No executions yet</td></tr>';

    document.getElementById('audit-log').innerHTML = audit.length
      ? audit.slice().reverse().map(e=>`
          <div class="border-bottom border-secondary pb-1 mb-1">
            <span class="badge bg-secondary">${e.action}</span>
            <small class="ms-2 text-muted">${new Date(e.timestamp).toLocaleTimeString()}</small><br>
            <small>Agent: ${e.agent_id.slice(0,16)}… | ${e.resource}</small><br>
            <span class="hash">hash:${e.entry_hash.slice(0,16)}… prev:${e.previous_hash.slice(0,16)}…</span>
          </div>`).join('')
      : '<p class="text-muted text-center">No audit entries</p>';

    document.getElementById('ts').textContent = 'Updated: ' + new Date().toLocaleTimeString();
  } catch(e) { console.error(e); }
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""


@app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
async def dashboard():
    """Governance dashboard: active agents, proposals, executions, audit trail."""
    return _DASHBOARD_HTML


@app.get("/dashboard/data", tags=["Dashboard"])
async def dashboard_data():
    """All dashboard data as a single JSON response."""
    verify_result = await verify_audit_chain()
    metrics_result = await get_metrics()
    return {
        "metrics": metrics_result,
        "agents": list(agents_db.values()),
        "proposals": list(proposals_db.values()),
        "executions": executed_actions,
        "audit_sample": audit_chain[-50:],
        "audit_verification": {
            "valid": verify_result["valid"],
            "chain_length": verify_result["chain_length"],
            "issues": verify_result["issues"],
        },
    }


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    print("🚀 Zero-Human Governance Core starting on http://0.0.0.0:8001")
    print("📊 Dashboard: http://localhost:8001/dashboard")
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=False)
