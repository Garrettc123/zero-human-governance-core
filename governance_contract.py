"""Shared, fail-closed governance contracts and local WAL evidence ledger.

Additive contract only: NOT an authenticated HTTP endpoint, execution dispatcher,
external receipt verifier, or globally anchored audit log. Both repos must carry
identical bytes of this module. No arbitrary direct HITL event append is exposed.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

GENESIS_HASH = "0" * 64
SHA256_PATTERN = r"^[a-f0-9]{64}$"
ProviderName = Literal["openai", "anthropic", "gemini", "ollama"]
RiskTier = Literal["low", "medium", "high", "critical"]
DecisionStatus = Literal["ALLOW", "DENY", "HOLD_HITL"]
HITLResolutionStatus = Literal["APPROVED", "REJECTED"]
LedgerEventType = Literal["GOVERNANCE_DECISION", "HITL_OVERRIDE"]


def canonical_json_bytes(payload: dict[str, Any] | list[Any]) -> bytes:
    """Deterministic Python JSON encoding; not RFC 8785 cross-language JCS."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def normalize_utc(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp requires a timezone offset")
    return parsed.astimezone(timezone.utc).isoformat()


class GovernanceStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True,
                              frozen=True)


class NormalizedGovernanceRequest(GovernanceStrictModel):
    request_id: str = Field(min_length=8, max_length=128)
    provider: ProviderName
    model: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=128)
    action_type: str = Field(min_length=1, max_length=128)
    payload_hash: str = Field(pattern=SHA256_PATTERN)
    risk_tier: RiskTier
    requires_hitl: bool = False
    context: dict[str, Any] = Field(default_factory=dict)
    created_at_utc: str = Field(min_length=20, max_length=64)

    @field_validator("created_at_utc")
    @classmethod
    def timestamp_utc(cls, value: str) -> str:
        return normalize_utc(value)

    @field_validator("context")
    @classmethod
    def json_only_context(cls, value: dict[str, Any]) -> dict[str, Any]:
        # Explicitly reject non-JSON objects / NaNs before hashing the snapshot.
        canonical_json_bytes(value)
        return value

    @model_validator(mode="after")
    def critical_requires_hitl(self) -> "NormalizedGovernanceRequest":
        if self.risk_tier == "critical" and not self.requires_hitl:
            raise ValueError("critical request must require HITL")
        return self


class HITLOverrideRequest(GovernanceStrictModel):
    ticket_id: str = Field(min_length=8, max_length=128)
    request_id: str = Field(min_length=8, max_length=128)
    reviewer_id: str = Field(min_length=1, max_length=128)
    resolution: HITLResolutionStatus
    reason: str = Field(min_length=1, max_length=1000)
    resolved_at_utc: str = Field(min_length=20, max_length=64)

    @field_validator("resolved_at_utc")
    @classmethod
    def timestamp_utc(cls, value: str) -> str:
        return normalize_utc(value)


class GovernanceDecisionResponse(GovernanceStrictModel):
    request_id: str = Field(min_length=8, max_length=128)
    decision: DecisionStatus
    rule_ids: tuple[str, ...] = Field(min_length=1)
    hitl_ticket_id: str | None = Field(default=None, max_length=128)
    execution_allowed: bool
    prev_hash: str = Field(pattern=SHA256_PATTERN)
    entry_hash: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def fail_closed(self) -> "GovernanceDecisionResponse":
        if self.execution_allowed != (self.decision == "ALLOW"):
            raise ValueError("execution_allowed must equal decision == ALLOW")
        if (self.decision == "HOLD_HITL") != (self.hitl_ticket_id is not None):
            raise ValueError("HOLD_HITL requires a ticket; other decisions forbid one")
        if self.hitl_ticket_id == "":
            raise ValueError("ticket must be non-empty")
        return self


class _DecisionEvent(GovernanceStrictModel):
    request_id: str = Field(min_length=8, max_length=128)
    payload_hash: str = Field(pattern=SHA256_PATTERN)
    context_hash: str = Field(pattern=SHA256_PATTERN)
    risk_tier: RiskTier
    requires_hitl: bool
    decision: DecisionStatus
    rule_ids: tuple[str, ...] = Field(min_length=1)
    hitl_ticket_id: str | None


class LedgerRecord(GovernanceStrictModel):
    seq: int = Field(ge=1)
    event_type: LedgerEventType
    request_id: str = Field(min_length=8, max_length=128)
    subject_id: str = Field(min_length=1, max_length=128)
    canonical_payload_json: str = Field(min_length=2)
    prev_hash: str = Field(pattern=SHA256_PATTERN)
    entry_hash: str = Field(pattern=SHA256_PATTERN)
    recorded_at_utc: str = Field(min_length=20, max_length=64)

    def compute_expected_hash(self) -> str:
        return sha256_hex(canonical_json_bytes({
            "seq": self.seq, "event_type": self.event_type,
            "request_id": self.request_id, "subject_id": self.subject_id,
            "canonical_payload_json": self.canonical_payload_json,
            "prev_hash": self.prev_hash, "recorded_at_utc": self.recorded_at_utc,
        }))


class WALGovernanceLedger:
    """Single-DB atomic chained evidence; approvals are NOT execution receipts."""

    def __init__(self, db_path: str | Path, busy_timeout_ms: int = 5000) -> None:
        if not isinstance(busy_timeout_ms, int) or busy_timeout_ms < 1:
            raise ValueError("busy_timeout_ms must be a positive integer")
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.busy_timeout_ms = busy_timeout_ms
        with closing(self._connect()) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute("""CREATE TABLE IF NOT EXISTS governance_ledger (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL CHECK(event_type IN ('GOVERNANCE_DECISION','HITL_OVERRIDE')),
                    request_id TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    canonical_payload_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    recorded_at_utc TEXT NOT NULL)""")
                conn.execute("CREATE INDEX IF NOT EXISTS ix_gov_request ON governance_ledger(request_id)")
                conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS ux_one_decision
                                ON governance_ledger(request_id)
                                WHERE event_type='GOVERNANCE_DECISION'""")
                conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS ux_one_resolution
                                ON governance_ledger(request_id)
                                WHERE event_type='HITL_OVERRIDE'""")
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=self.busy_timeout_ms / 1000,
                               isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    @staticmethod
    def _append_locked(conn: sqlite3.Connection, event_type: LedgerEventType,
                       request_id: str, subject_id: str,
                       payload_model: GovernanceStrictModel) -> LedgerRecord:
        last = conn.execute("SELECT seq, entry_hash FROM governance_ledger ORDER BY seq DESC LIMIT 1").fetchone()
        seq = int(last["seq"]) + 1 if last else 1
        prev = str(last["entry_hash"]) if last else GENESIS_HASH
        payload = canonical_json_bytes(payload_model.model_dump(mode="json")).decode("utf-8")
        ts = datetime.now(timezone.utc).isoformat()
        record = LedgerRecord(seq=seq, event_type=event_type, request_id=request_id,
                              subject_id=subject_id, canonical_payload_json=payload,
                              prev_hash=prev, entry_hash=GENESIS_HASH, recorded_at_utc=ts)
        record = record.model_copy(update={"entry_hash": record.compute_expected_hash()})
        conn.execute("""INSERT INTO governance_ledger
                    (seq,event_type,request_id,subject_id,canonical_payload_json,prev_hash,entry_hash,recorded_at_utc)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    (seq, event_type, request_id, subject_id, payload, prev, record.entry_hash, ts))
        return record

    def record_decision(self, *, request: NormalizedGovernanceRequest,
                        decision: DecisionStatus, rule_ids: tuple[str, ...],
                        hitl_ticket_id: str | None = None) -> GovernanceDecisionResponse:
        if not rule_ids or any(not isinstance(r, str) or not r.strip() for r in rule_ids):
            raise ValueError("at least one non-empty rule ID required")
        if request.requires_hitl and decision == "ALLOW":
            raise ValueError("HITL-required request cannot be directly ALLOWed")
        if decision == "HOLD_HITL":
            if not hitl_ticket_id or len(hitl_ticket_id) < 8 or hitl_ticket_id == request.request_id:
                raise ValueError("HOLD_HITL requires distinct valid ticket")
        elif hitl_ticket_id is not None:
            raise ValueError("only HOLD_HITL permits a ticket")
        event = _DecisionEvent(
            request_id=request.request_id, payload_hash=request.payload_hash,
            context_hash=sha256_hex(canonical_json_bytes(request.context)),
            risk_tier=request.risk_tier, requires_hitl=request.requires_hitl,
            decision=decision, rule_ids=rule_ids, hitl_ticket_id=hitl_ticket_id)
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if conn.execute("SELECT 1 FROM governance_ledger WHERE event_type='GOVERNANCE_DECISION' AND request_id=?",
                                (request.request_id,)).fetchone():
                    raise ValueError("request already evaluated")
                if hitl_ticket_id and conn.execute("SELECT 1 FROM governance_ledger WHERE event_type='GOVERNANCE_DECISION' AND subject_id=?",
                                                   (hitl_ticket_id,)).fetchone():
                    raise ValueError("HITL ticket already used")
                receipt = self._append_locked(conn, "GOVERNANCE_DECISION", request.request_id,
                                              hitl_ticket_id or request.request_id, event)
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return GovernanceDecisionResponse(
            request_id=request.request_id, decision=decision, rule_ids=rule_ids,
            hitl_ticket_id=hitl_ticket_id, execution_allowed=(decision == "ALLOW"),
            prev_hash=receipt.prev_hash, entry_hash=receipt.entry_hash)

    def resolve_hitl(self, override: HITLOverrideRequest, *,
                     reviewer_authorizer: Callable[[HITLOverrideRequest], bool] | None = None
                     ) -> LedgerRecord:
        """Append a one-time resolution after trusted authenticated reviewer check.

        A caller-controlled reviewer_id alone does not prove identity. A trusted
        endpoint must authenticate and authorize the reviewer; absent the
        callback, this method refuses all overrides.
        """
        if reviewer_authorizer is None:
            raise PermissionError("trusted reviewer authorizer required")
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("""SELECT canonical_payload_json, subject_id FROM governance_ledger
                            WHERE event_type='GOVERNANCE_DECISION' AND request_id=?""",
                            (override.request_id,)).fetchone()
                if row is None:
                    raise ValueError("unknown request; no HITL decision")
                decision = _DecisionEvent.model_validate_json(row["canonical_payload_json"])
                if (decision.decision != "HOLD_HITL" or
                        decision.hitl_ticket_id != override.ticket_id or
                        row["subject_id"] != override.ticket_id):
                    raise ValueError("ticket/request mismatch or not on hold")
                if conn.execute("SELECT 1 FROM governance_ledger WHERE event_type='HITL_OVERRIDE' AND request_id=?",
                                (override.request_id,)).fetchone():
                    raise ValueError("HITL ticket already resolved")
                if not reviewer_authorizer(override):
                    raise PermissionError("reviewer not authenticated/authorized")
                receipt = self._append_locked(conn, "HITL_OVERRIDE", override.request_id,
                                              override.ticket_id, override)
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return receipt

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Check linked hashes AND internal event state; no external tail anchoring."""
        errors: list[str] = []
        with closing(self._connect()) as conn:
            # Read one consistent snapshot, independent of parallel appenders.
            conn.execute("BEGIN")
            try:
                integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
                rows = conn.execute("SELECT * FROM governance_ledger ORDER BY seq").fetchall()
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        if integrity != "ok":
            errors.append(f"SQLite integrity check failed: {integrity}")
        prev, expected_seq = GENESIS_HASH, 1
        decisions: dict[str, _DecisionEvent] = {}
        tickets: set[str] = set()
        resolved: set[str] = set()
        for row in rows:
            try:
                record = LedgerRecord.model_validate(dict(row))
                if record.seq != expected_seq:
                    errors.append(f"sequence discontinuity at {record.seq}, expected {expected_seq}")
                if record.prev_hash != prev:
                    errors.append(f"prev_hash mismatch at {record.seq}")
                if record.entry_hash != record.compute_expected_hash():
                    errors.append(f"entry_hash mismatch at {record.seq}")
                payload = json.loads(record.canonical_payload_json)
                if canonical_json_bytes(payload).decode("utf-8") != record.canonical_payload_json:
                    errors.append(f"noncanonical payload at {record.seq}")
                if record.event_type == "GOVERNANCE_DECISION":
                    d = _DecisionEvent.model_validate_json(record.canonical_payload_json)
                    if d.request_id != record.request_id or record.request_id in decisions:
                        errors.append(f"duplicate or inconsistent request at {record.seq}")
                    if d.requires_hitl and d.decision == "ALLOW":
                        errors.append(f"HITL bypass at {record.seq}")
                    if d.decision == "HOLD_HITL":
                        if not d.hitl_ticket_id or d.hitl_ticket_id in tickets or record.subject_id != d.hitl_ticket_id:
                            errors.append(f"invalid or reused ticket at {record.seq}")
                        else:
                            tickets.add(d.hitl_ticket_id)
                    elif d.hitl_ticket_id is not None or record.subject_id != d.request_id:
                        errors.append(f"invalid decision subject at {record.seq}")
                    decisions[record.request_id] = d
                else:
                    o = HITLOverrideRequest.model_validate(payload)
                    d = decisions.get(record.request_id)
                    if (d is None or d.decision != "HOLD_HITL" or
                            d.hitl_ticket_id != o.ticket_id or o.request_id != record.request_id or
                            record.subject_id != o.ticket_id or record.request_id in resolved):
                        errors.append(f"invalid/replayed override at {record.seq}")
                    resolved.add(record.request_id)
                prev, expected_seq = record.entry_hash, record.seq + 1
            except Exception as exc:
                errors.append(f"invalid entry at seq={row['seq']}: {type(exc).__name__}")
                prev, expected_seq = row["entry_hash"], row["seq"] + 1
        return not errors, errors
