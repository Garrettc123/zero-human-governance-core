"""Shared contract test matrix; copy unchanged into both target repos."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import sqlite3

import pytest
from pydantic import ValidationError

from governance_contract import (
    GENESIS_HASH, HITLOverrideRequest, NormalizedGovernanceRequest,
    WALGovernanceLedger, canonical_json_bytes, sha256_hex,
)


def request(i=1, *, risk="low", requires_hitl=False):
    return NormalizedGovernanceRequest(
        request_id=f"request-{i:05d}", provider="openai", model="gpt-6",
        actor_id="worker-01", action_type="analyze", payload_hash="a" * 64,
        risk_tier=risk, requires_hitl=requires_hitl,
        context={"evidence": ["one", "two"]},
        created_at_utc="2026-11-23T15:00:00Z")


def override(i=1, *, ticket="ticket-00001", resolution="APPROVED"):
    return HITLOverrideRequest(ticket_id=ticket, request_id=f"request-{i:05d}",
                               reviewer_id="owner", resolution=resolution,
                               reason="Reviewed evidence and scope",
                               resolved_at_utc="2026-11-23T16:00:00+00:00")


def test_canonical_json_key_order_and_unicode():
    assert canonical_json_bytes({"b": 2, "a": "ñ"}) == canonical_json_bytes({"a": "ñ", "b": 2})
    assert sha256_hex(canonical_json_bytes({"a": 1})) == sha256_hex(b'{"a":1}')


def test_strict_unknown_and_invalid_timestamp():
    with pytest.raises(ValidationError):
        NormalizedGovernanceRequest.model_validate({**request().model_dump(), "tool_calls": []})
    with pytest.raises(ValidationError):
        NormalizedGovernanceRequest.model_validate({**request().model_dump(), "created_at_utc":"2026-11-23T09:00:00"})
    with pytest.raises(ValidationError):
        NormalizedGovernanceRequest.model_validate({**request().model_dump(), "requires_hitl":1})


def test_critical_requires_hitl():
    with pytest.raises(ValidationError):
        request(risk="critical")
    assert request(risk="critical", requires_hitl=True).risk_tier == "critical"


def test_allow_and_deny_chain(tmp_path):
    l = WALGovernanceLedger(tmp_path / "ledger.db")
    a = l.record_decision(request=request(1), decision="ALLOW", rule_ids=("R1",))
    d = l.record_decision(request=request(2), decision="DENY", rule_ids=("R2",))
    assert a.execution_allowed is True and d.execution_allowed is False
    assert a.prev_hash == GENESIS_HASH and d.prev_hash == a.entry_hash
    assert l.verify_chain() == (True, [])


def test_no_direct_allow_for_hitl(tmp_path):
    l = WALGovernanceLedger(tmp_path / "ledger.db")
    with pytest.raises(ValueError, match="HITL"):
        l.record_decision(request=request(requires_hitl=True), decision="ALLOW", rule_ids=("R1",))
    assert l.verify_chain() == (True, [])


def test_hold_and_approval_chain(tmp_path):
    l = WALGovernanceLedger(tmp_path / "ledger.db")
    d = l.record_decision(request=request(risk="critical", requires_hitl=True),
                          decision="HOLD_HITL", hitl_ticket_id="ticket-00001", rule_ids=("R3",))
    with pytest.raises(PermissionError):
        l.resolve_hitl(override())
    with pytest.raises(PermissionError):
        l.resolve_hitl(override(), reviewer_authorizer=lambda _: False)
    o = l.resolve_hitl(override(), reviewer_authorizer=lambda o: o.reviewer_id == "owner")
    assert d.execution_allowed is False  # Approval is NOT an execution receipt.
    assert o.prev_hash == d.entry_hash
    assert l.verify_chain() == (True, [])
    with pytest.raises(ValueError, match="already resolved"):
        l.resolve_hitl(override(), reviewer_authorizer=lambda _: True)


def test_rejected_hold_is_terminal(tmp_path):
    l = WALGovernanceLedger(tmp_path / "l.db")
    l.record_decision(request=request(),decision="HOLD_HITL",hitl_ticket_id="ticket-00001",rule_ids=("R",))
    l.resolve_hitl(override(resolution="REJECTED"), reviewer_authorizer=lambda _: True)
    with pytest.raises(ValueError):
        l.resolve_hitl(override(), reviewer_authorizer=lambda _: True)
    assert l.verify_chain() == (True, [])


def test_wrong_ticket_request_and_unheld(tmp_path):
    l = WALGovernanceLedger(tmp_path / "l.db")
    l.record_decision(request=request(),decision="HOLD_HITL",hitl_ticket_id="ticket-00001",rule_ids=("R",))
    with pytest.raises(ValueError,match="mismatch"):
        l.resolve_hitl(override(ticket="ticket-99999"), reviewer_authorizer=lambda _: True)
    with pytest.raises(ValueError,match="unknown"):
        l.resolve_hitl(override(i=2), reviewer_authorizer=lambda _: True)
    l.record_decision(request=request(2), decision="DENY",rule_ids=("R",))
    with pytest.raises(ValueError,match="mismatch"):
        l.resolve_hitl(override(i=2), reviewer_authorizer=lambda _: True)
    assert l.verify_chain() == (True, [])


def test_duplicate_decision_and_ticket(tmp_path):
    l = WALGovernanceLedger(tmp_path / "l.db")
    l.record_decision(request=request(), decision="HOLD_HITL", hitl_ticket_id="ticket-00001", rule_ids=("R",))
    with pytest.raises(ValueError,match="already evaluated"):
        l.record_decision(request=request(), decision="DENY",rule_ids=("R",))
    with pytest.raises(ValueError,match="ticket already used"):
        l.record_decision(request=request(2),decision="HOLD_HITL",hitl_ticket_id="ticket-00001",rule_ids=("R",))
    assert l.verify_chain() == (True, [])


@pytest.mark.parametrize("column,newval", [
    ("canonical_payload_json", '{"bad":"payload"}'),
    ("prev_hash", "1" * 64),
    ("entry_hash", "1" * 64),
])
def test_detect_single_row_tampering(tmp_path,column,newval):
    l = WALGovernanceLedger(tmp_path / "l.db")
    l.record_decision(request=request(),decision="DENY",rule_ids=("R",))
    with sqlite3.connect(l.db_path) as db:
        db.execute(f"UPDATE governance_ledger SET {column}=? WHERE seq=1",(newval,))
    valid, errors = l.verify_chain()
    assert not valid and errors


def test_concurrent_appenders_have_no_forks(tmp_path):
    l = WALGovernanceLedger(tmp_path / "l.db", busy_timeout_ms=15000)
    def job(i):
        return l.record_decision(request=request(i), decision="DENY",rule_ids=("R",))
    with ThreadPoolExecutor(max_workers=8) as p:
        records=list(p.map(job,range(1,41)))
    assert len({r.entry_hash for r in records})==40
    assert l.verify_chain() == (True, [])
    with sqlite3.connect(l.db_path) as db:
        assert db.execute("SELECT COUNT(*), MIN(seq),MAX(seq) FROM governance_ledger").fetchone() == (40,1,40)


def test_reopen_persists_chain(tmp_path):
    path=tmp_path / "l.db"
    WALGovernanceLedger(path).record_decision(request=request(),decision="DENY",rule_ids=("R",))
    assert WALGovernanceLedger(path).verify_chain() == (True, [])
