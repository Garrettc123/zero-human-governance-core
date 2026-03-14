"""Autonomous AI Orchestrator — scans for opportunities and submits signed proposals."""

import asyncio
import requests
from datetime import datetime

try:
    from .crypto import generate_keypair, sign_data
except ImportError:
    from crypto import generate_keypair, sign_data  # type: ignore[no-redef]

GOVERNANCE_API = "http://localhost:8001"


class AutonomousOrchestrator:
    """AI agent that autonomously proposes business opportunities."""

    def __init__(self):
        self.running = True
        self.agent_id: str = ""
        self.private_key: str = ""
        self._opportunities = [
            {"title": "AI SaaS Platform", "value": 150_000, "risk": "medium"},
            {"title": "Data Monetization Engine", "value": 75_000, "risk": "low"},
            {"title": "Automated Consulting Service", "value": 50_000, "risk": "low"},
            {"title": "Enterprise AI Integration", "value": 200_000, "risk": "high"},
            {"title": "Subscription Analytics Tool", "value": 100_000, "risk": "medium"},
        ]
        self._opp_index = 0

    # ------------------------------------------------------------------
    # Agent lifecycle
    # ------------------------------------------------------------------

    def register(self) -> bool:
        """Register this orchestrator as a governance agent.

        Generates a fresh Ed25519 keypair, sends the public key to the
        governance API, and stores the private key locally for signing.
        """
        try:
            response = requests.post(
                f"{GOVERNANCE_API}/agents/register",
                json={
                    "name": "AutonomousOrchestrator-v2",
                    "capabilities": ["market_scan", "opportunity_analysis"],
                    "permissions": ["propose", "vote"],
                },
                timeout=10,
            )
            if response.status_code == 200:
                data = response.json()
                self.agent_id = data["agent_id"]
                self.private_key = data["private_key"]
                print(
                    f"✅ Registered as agent {self.agent_id[:8]}… "
                    f"(key: {data['public_key'][:16]}…)"
                )
                return True
            print(f"⚠️  Registration failed: {response.text}")
        except Exception as exc:
            print(f"⚠️  Could not reach governance API: {exc}")
        return False

    # ------------------------------------------------------------------
    # Core loop
    # ------------------------------------------------------------------

    async def scan_market(self) -> dict:
        """Return the next opportunity in round-robin fashion."""
        opp = self._opportunities[self._opp_index % len(self._opportunities)]
        self._opp_index += 1
        return opp

    async def submit_proposal(self, opportunity: dict) -> str | None:
        """Sign and submit a proposal to the governance system."""
        payload = {
            "title": opportunity["title"],
            "description": (
                f"Build {opportunity['title']} with estimated "
                f"${opportunity['value']:,} revenue"
            ),
            "proposed_action": f"launch_{opportunity['title'].lower().replace(' ', '_')}",
            "risk_level": opportunity["risk"],
            "action_params": {"estimated_value": opportunity["value"]},
            "agent_id": self.agent_id,
        }

        # Sign the proposal payload with this agent's private key
        signed_data = {
            "title": payload["title"],
            "description": payload["description"],
            "proposed_action": payload["proposed_action"],
            "risk_level": payload["risk_level"],
            "action_params": payload["action_params"],
            "agent_id": self.agent_id,
        }
        signature = sign_data(self.private_key, signed_data)
        payload["signature"] = signature

        try:
            response = requests.post(
                f"{GOVERNANCE_API}/proposals", json=payload, timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                print(
                    f"✅ Proposal submitted: {opportunity['title']} "
                    f"(ID: {data['proposal_id'][:8]}…)"
                )
                return data["proposal_id"]
            print(f"⚠️  Proposal rejected: {response.status_code} – {response.text}")
        except Exception as exc:
            print(f"⚠️  Error submitting proposal: {exc}")
        return None

    async def run(self):
        """Main orchestration loop."""
        print("🤖 Autonomous Orchestrator starting…")

        if not self.register():
            print("❌ Could not register — governance API unavailable")
            return

        print("🔍 Scanning markets for opportunities…\n")
        while self.running:
            opp = await self.scan_market()
            print(
                f"💡 Opportunity found: {opp['title']} "
                f"(${opp['value']:,}, risk={opp['risk']})"
            )
            await self.submit_proposal(opp)
            await asyncio.sleep(30)


if __name__ == "__main__":
    orchestrator = AutonomousOrchestrator()
    asyncio.run(orchestrator.run())
