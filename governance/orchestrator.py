import asyncio
import requests
import random
from datetime import datetime

GOVERNANCE_API = "http://localhost:8001"

class AutonomousOrchestrator:
    """AI that proposes business opportunities"""
    
    def __init__(self):
        self.running = True
        
    async def scan_market(self):
        """Scan for business opportunities"""
        opportunities = [
            {"title": "AI SaaS Platform", "value": 150000, "risk": "medium"},
            {"title": "Data Monetization Engine", "value": 75000, "risk": "low"},
            {"title": "Automated Consulting Service", "value": 50000, "risk": "low"},
            {"title": "Enterprise AI Integration", "value": 200000, "risk": "high"},
            {"title": "Subscription Analytics Tool", "value": 100000, "risk": "medium"},
        ]
        return random.choice(opportunities)
    
    async def submit_proposal(self, opportunity):
        """Submit proposal to governance system"""
        proposal = {
            "title": opportunity["title"],
            "description": f"Build {opportunity['title']} with estimated ${opportunity['value']} revenue",
            "risk_level": opportunity["risk"],
            "estimated_value": opportunity["value"],
            "status": "pending",
            "created_at": datetime.now().timestamp()
        }
        
        try:
            response = requests.post(f"{GOVERNANCE_API}/proposals", json=proposal)
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Proposal submitted: {opportunity['title']} (ID: {data['proposal_id']})")
                return data["proposal_id"]
        except Exception as e:
            print(f"⚠️  Error submitting proposal: {e}")
        return None
    
    async def run(self):
        """Main orchestration loop"""
        print("🤖 Autonomous Orchestrator started")
        print("🔍 Scanning markets for opportunities...\n")
        
        while self.running:
            # Scan market
            opportunity = await self.scan_market()
            print(f"💡 Found opportunity: {opportunity['title']} (${opportunity['value']:,})")
            
            # Submit to governance
            await self.submit_proposal(opportunity)
            
            # Wait before next scan
            await asyncio.sleep(30)  # Submit proposal every 30 seconds

if __name__ == "__main__":
    orchestrator = AutonomousOrchestrator()
    asyncio.run(orchestrator.run())