from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import hashlib
import time
from datetime import datetime
import json

app = FastAPI(title="Zero-Human Governance Core")

class Proposal(BaseModel):
    id: str
    title: str
    description: str
    risk_level: str
    estimated_value: float
    status: str = "pending"
    created_at: float
    approved_by: Optional[str] = None
    signature: Optional[str] = None

proposals_db = {}

def generate_signature(proposal_id: str, approver: str) -> str:
    """Generate cryptographic signature for approval"""
    data = f"{proposal_id}{approver}{time.time()}"
    return hashlib.sha256(data.encode()).hexdigest()

@app.get("/")
def root():
    return {
        "system": "Zero-Human Governance Core",
        "status": "operational",
        "proposals_count": len(proposals_db),
        "pending_approvals": len([p for p in proposals_db.values() if p.status == "pending"])
    }

@app.post("/proposals")
def create_proposal(proposal: Proposal):
    """AI submits a business proposal"""
    proposal.id = hashlib.sha256(f"{proposal.title}{time.time()}".encode()).hexdigest()[:16]
    proposal.created_at = time.time()
    proposals_db[proposal.id] = proposal
    return {"proposal_id": proposal.id, "status": "submitted", "message": "Awaiting human approval"}

@app.get("/proposals")
def list_proposals():
    """List all proposals"""
    return {"proposals": list(proposals_db.values()), "total": len(proposals_db)}

@app.post("/proposals/{proposal_id}/approve")
def approve_proposal(proposal_id: str, approver: str = "human_operator"):
    """Human approves a proposal"""
    if proposal_id not in proposals_db:
        raise HTTPException(status_code=404, detail="Proposal not found")
    
    proposal = proposals_db[proposal_id]
    proposal.status = "approved"
    proposal.approved_by = approver
    proposal.signature = generate_signature(proposal_id, approver)
    
    return {
        "message": "Proposal approved",
        "proposal_id": proposal_id,
        "signature": proposal.signature,
        "can_execute": True
    }

@app.post("/proposals/{proposal_id}/reject")
def reject_proposal(proposal_id: str, reason: str = "No reason provided"):
    """Human rejects a proposal"""
    if proposal_id not in proposals_db:
        raise HTTPException(status_code=404, detail="Proposal not found")
    
    proposal = proposals_db[proposal_id]
    proposal.status = "rejected"
    
    return {"message": "Proposal rejected", "proposal_id": proposal_id, "reason": reason}

@app.get("/metrics")
def get_metrics():
    """System metrics"""
    return {
        "total_proposals": len(proposals_db),
        "pending": len([p for p in proposals_db.values() if p.status == "pending"]),
        "approved": len([p for p in proposals_db.values() if p.status == "approved"]),
        "rejected": len([p for p in proposals_db.values() if p.status == "rejected"]),
        "uptime": "operational"
    }

if __name__ == "__main__":
    import uvicorn
    print("🚀 Zero-Human Governance Core starting...")
    print("📊 Dashboard: http://localhost:8001")
    uvicorn.run(app, host="0.0.0.0", port=8001)