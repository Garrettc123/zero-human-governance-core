#!/usr/bin/env python3
"""
Zero-Human AI Governance Core
Enterprise-grade cryptographic governance and orchestration for autonomous AI agents.
Maintains human control while enabling full AI autonomy.
"""

import os
import json
import hashlib
import hmac
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AgentState(Enum):
    """Valid states for autonomous agents."""
    IDLE = "idle"
    ACTIVE = "active"
    PAUSED = "paused"
    RESTRICTED = "restricted"
    TERMINATED = "terminated"


class ActionType(Enum):
    """Types of actions agents can perform."""
    EXECUTE = "execute"
    QUERY = "query"
    MODIFY = "modify"
    DELETE = "delete"
    INTEGRATE = "integrate"


@dataclass
class GovernanceRule:
    """A governance rule that agents must follow."""
    id: str
    name: str
    description: str
    action_type: ActionType
    conditions: Dict[str, Any]
    constraints: Dict[str, Any]
    priority: int
    enabled: bool
    created_at: str
    updated_at: str


@dataclass
class AgentManifest:
    """Agent manifest with cryptographic verification."""
    agent_id: str
    name: str
    capabilities: List[str]
    permissions: List[str]
    state: AgentState
    signature: str
    created_at: str
    updated_at: str
    version: str


@dataclass
class AuditLog:
    """Immutable audit log entry."""
    id: str
    timestamp: str
    agent_id: str
    action: str
    resource: str
    result: str
    details: Dict[str, Any]
    signature: str


class CryptographicGovernance:
    """Core governance engine with cryptographic verification."""

    def __init__(self, master_key: Optional[str] = None):
        """Initialize governance with optional master key."""
        self.master_key = master_key or os.getenv('GOVERNANCE_MASTER_KEY', 'dev-key')
        self.agents: Dict[str, AgentManifest] = {}
        self.rules: Dict[str, GovernanceRule] = {}
        self.audit_logs: List[AuditLog] = []
        self.action_queue: asyncio.Queue = asyncio.Queue()
        self.permission_cache: Dict[str, Dict[str, bool]] = {}
        logger.info("Governance engine initialized")

    def sign_manifest(self, manifest: AgentManifest) -> str:
        """Create cryptographic signature for agent manifest."""
        manifest_json = json.dumps(asdict(manifest), sort_keys=True)
        signature = hmac.new(
            self.master_key.encode(),
            manifest_json.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature

    def verify_manifest(self, manifest: AgentManifest) -> bool:
        """Verify agent manifest signature."""
        expected_signature = self.sign_manifest(manifest)
        is_valid = hmac.compare_digest(manifest.signature, expected_signature)
        if not is_valid:
            logger.warning(f"Invalid signature for agent {manifest.agent_id}")
        return is_valid

    def register_agent(self, agent_id: str, name: str, capabilities: List[str],
                       permissions: List[str] = None) -> AgentManifest:
        """Register a new autonomous agent."""
        if agent_id in self.agents:
            raise ValueError(f"Agent {agent_id} already registered")

        manifest = AgentManifest(
            agent_id=agent_id,
            name=name,
            capabilities=capabilities,
            permissions=permissions or [],
            state=AgentState.IDLE,
            signature="",
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat(),
            version="1.0.0"
        )

        manifest.signature = self.sign_manifest(manifest)
        self.agents[agent_id] = manifest
        logger.info(f"Agent {agent_id} registered successfully")
        return manifest

    def create_rule(self, name: str, description: str, action_type: ActionType,
                    conditions: Dict[str, Any], constraints: Dict[str, Any],
                    priority: int = 5) -> GovernanceRule:
        """Create a new governance rule."""
        rule_id = hashlib.sha256(f"{name}{datetime.utcnow()}".encode()).hexdigest()[:16]

        rule = GovernanceRule(
            id=rule_id,
            name=name,
            description=description,
            action_type=action_type,
            conditions=conditions,
            constraints=constraints,
            priority=priority,
            enabled=True,
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat()
        )

        self.rules[rule_id] = rule
        logger.info(f"Governance rule {rule_id} created: {name}")
        return rule

    def evaluate_permission(self, agent_id: str, action: ActionType,
                           resource: str) -> bool:
        """Evaluate if agent has permission for action."""
        if agent_id not in self.agents:
            logger.warning(f"Unknown agent {agent_id}")
            return False

        agent = self.agents[agent_id]

        # Check cache
        cache_key = f"{agent_id}:{action.value}:{resource}"
        if cache_key in self.permission_cache:
            return self.permission_cache[cache_key]

        # Evaluate rules (sorted by priority)
        sorted_rules = sorted(self.rules.values(), key=lambda r: r.priority)

        for rule in sorted_rules:
            if not rule.enabled:
                continue

            if rule.action_type != action:
                continue

            # Check conditions match
            conditions_met = self._check_conditions(agent, rule.conditions, resource)

            if conditions_met:
                # Check constraints
                constraints_met = self._check_constraints(agent, rule.constraints)
                result = constraints_met
                self.permission_cache[cache_key] = result
                logger.info(f"Permission evaluated for {agent_id}: {action.value} = {result}")
                return result

        # Default deny
        self.permission_cache[cache_key] = False
        return False

    def _check_conditions(self, agent: AgentManifest, conditions: Dict[str, Any],
                         resource: str) -> bool:
        """Check if conditions are met."""
        if not conditions:
            return True

        for condition, value in conditions.items():
            if condition == "agent_has_capability":
                if value not in agent.capabilities:
                    return False
            elif condition == "resource_type":
                if resource != value:
                    return False
            elif condition == "agent_state":
                if agent.state.value != value:
                    return False

        return True

    def _check_constraints(self, agent: AgentManifest, constraints: Dict[str, Any]) -> bool:
        """Check if constraints are satisfied."""
        if not constraints:
            return True

        if agent.state == AgentState.RESTRICTED:
            return False

        if agent.state == AgentState.TERMINATED:
            return False

        return True

    def execute_action(self, agent_id: str, action: ActionType, resource: str,
                      details: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute an action with governance checks."""
        if not self.evaluate_permission(agent_id, action, resource):
            result = "denied"
            logger.warning(f"Action denied for {agent_id}: {action.value}")
        else:
            result = "executed"
            logger.info(f"Action executed for {agent_id}: {action.value} on {resource}")

        # Create audit log
        log_id = hashlib.sha256(f"{agent_id}{action}{resource}{datetime.utcnow()}".encode()).hexdigest()[:16]
        audit_log = AuditLog(
            id=log_id,
            timestamp=datetime.utcnow().isoformat(),
            agent_id=agent_id,
            action=action.value,
            resource=resource,
            result=result,
            details=details or {},
            signature=""
        )

        audit_log.signature = hmac.new(
            self.master_key.encode(),
            json.dumps(asdict(audit_log), sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()

        self.audit_logs.append(audit_log)
        return {"status": result, "log_id": log_id}

    def set_agent_state(self, agent_id: str, new_state: AgentState) -> bool:
        """Update agent state with governance verification."""
        if agent_id not in self.agents:
            logger.error(f"Agent {agent_id} not found")
            return False

        agent = self.agents[agent_id]
        old_state = agent.state
        agent.state = new_state
        agent.updated_at = datetime.utcnow().isoformat()

        logger.info(f"Agent {agent_id} state changed: {old_state.value} -> {new_state.value}")
        return True

    def get_governance_report(self) -> Dict[str, Any]:
        """Generate comprehensive governance report."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "total_agents": len(self.agents),
            "agent_states": {
                agent_id: agent.state.value
                for agent_id, agent in self.agents.items()
            },
            "total_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules.values() if r.enabled),
            "audit_logs_count": len(self.audit_logs),
            "recent_actions": [asdict(log) for log in self.audit_logs[-10:]],
        }

    def export_governance_state(self, filepath: str) -> None:
        """Export current governance state."""
        state = {
            "agents": {aid: asdict(a) for aid, a in self.agents.items()},
            "rules": {rid: asdict(r) for rid, r in self.rules.items()},
            "audit_logs": [asdict(log) for log in self.audit_logs],
            "exported_at": datetime.utcnow().isoformat()
        }

        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2)

        logger.info(f"Governance state exported to {filepath}")


def governance_protected(action_type: ActionType):
    """Decorator for governance-protected functions."""
    def decorator(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            agent_id = kwargs.get('agent_id') or (args[0] if args else None)
            resource = kwargs.get('resource') or (args[1] if len(args) > 1 else None)

            if not hasattr(self, '_governance'):
                # Fallback if governance not available
                return await func(self, *args, **kwargs)

            if not self._governance.evaluate_permission(agent_id, action_type, resource):
                raise PermissionError(f"Action {action_type.value} not permitted for {agent_id}")

            return await func(self, *args, **kwargs)
        return wrapper
    return decorator


# Example usage
if __name__ == "__main__":
    # Initialize governance
    governance = CryptographicGovernance()

    # Register agents
    governance.register_agent(
        "agent_lead_classifier",
        "Lead Classification Agent",
        ["classify", "analyze", "report"],
        ["read_leads", "write_classifications"]
    )

    governance.register_agent(
        "agent_copywriter",
        "Email Copywriter Agent",
        ["write", "edit", "optimize"],
        ["read_data", "write_content"]
    )

    # Create governance rules
    governance.create_rule(
        name="Lead Classification Permissions",
        description="Controls who can classify leads",
        action_type=ActionType.EXECUTE,
        conditions={"agent_has_capability": "classify"},
        constraints={},
        priority=1
    )

    governance.create_rule(
        name="Content Writing Restrictions",
        description="Controls content writing capabilities",
        action_type=ActionType.MODIFY,
        conditions={"agent_has_capability": "write"},
        constraints={},
        priority=2
    )

    # Test permissions
    print("\n=== Governance Test Results ===")
    print(f"Lead Classifier can execute: {governance.evaluate_permission('agent_lead_classifier', ActionType.EXECUTE, 'leads')}")
    print(f"Copywriter can modify: {governance.evaluate_permission('agent_copywriter', ActionType.MODIFY, 'content')}")

    # Execute actions
    governance.execute_action("agent_lead_classifier", ActionType.EXECUTE, "leads", {"count": 100})
    governance.execute_action("agent_copywriter", ActionType.MODIFY, "content", {"emails": 5})

    # Generate report
    report = governance.get_governance_report()
    print(f"\n=== Governance Report ===")
    print(json.dumps(report, indent=2))

    # Export state
    governance.export_governance_state("governance_state.json")
    print("\nGovernance state exported successfully")
