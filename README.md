# 🚀 Zero-Human Governance Core

![Deployment Status](https://github.com/Garrettc123/zero-human-governance-core/actions/workflows/deploy-governance.yml/badge.svg)

**Enterprise-Grade AI Governance with Cryptographic Decision Tracking**

## What This System Does

✅ **AI proposes** business opportunities autonomously  
✅ **Human approves** every critical decision  
✅ **Cryptographic signatures** ensure accountability  
✅ **Runs on GitHub Actions** - zero infrastructure needed  

## Architecture

```
┌──────────────────────────────────────────────┐
│         Autonomous Orchestrator              │
│    (Scans markets, proposes businesses)      │
└───────────────┬──────────────────────────────┘
                │ Submits Proposals
                ▼
┌──────────────────────────────────────────────┐
│          Governance Core (FastAPI)           │
│   • Risk Assessment                          │
│   • Human Approval Required                  │
│   • Cryptographic Signatures                 │
└──────────────────────────────────────────────┘
```

## Quick Start

### Option 1: Run Locally (5 minutes)

```bash
# Clone repository
git clone https://github.com/Garrettc123/zero-human-governance-core.git
cd zero-human-governance-core

# Install dependencies
pip install fastapi uvicorn pydantic requests

# Start governance core
cd governance
python main.py

# In another terminal, start orchestrator
python orchestrator.py
```

### Option 2: Run on GitHub Actions (Automated)

**Already configured!** Every push to `main` automatically:
1. Starts the governance system
2. Runs the autonomous orchestrator
3. Generates proposals every 6 hours

## API Endpoints

### Governance Core (Port 8001)

- `GET /` - System status
- `POST /proposals` - Submit proposal (AI)
- `GET /proposals` - List all proposals
- `POST /proposals/{id}/approve` - Approve proposal (Human)
- `POST /proposals/{id}/reject` - Reject proposal (Human)
- `GET /metrics` - System metrics

## Example Usage

### Submit a Proposal
```bash
curl -X POST http://localhost:8001/proposals \
  -H "Content-Type: application/json" \
  -d '{
    "title": "AI SaaS Platform",
    "description": "Build subscription analytics tool",
    "risk_level": "medium",
    "estimated_value": 150000
  }'
```

### Approve a Proposal
```bash
curl -X POST http://localhost:8001/proposals/abc123/approve
```

## Environment Variables

Set these in your `.env` file or GitHub Secrets:

```bash
GITHUB_TOKEN=your_github_token
OPENAI_API_KEY=sk-your-key  # Optional
STRIPE_SECRET_KEY=sk_test_your_key  # Optional
```

## Security Features

- **SHA-256 cryptographic signatures** on all approvals
- **Immutable audit trail** of all decisions
- **Human-in-the-loop** at every critical gate
- **Risk-based routing** to appropriate approvers

## Business Model

- **SaaS Subscriptions**: $299-$1,999/month
- **Enterprise Licensing**: $25K-$100K annually
- **API Usage**: Pay-per-decision pricing

## Why This Matters

This system solves the **core problem** of enterprise AI:

> "How do you scale AI autonomy while maintaining human control?"

OpenAI, Anthropic, and Perplexity need this infrastructure to sell to Fortune 500 companies.

## Tech Stack

- **Python 3.11+**
- **FastAPI** - Governance API
- **Pydantic** - Data validation
- **Uvicorn** - ASGI server
- **GitHub Actions** - CI/CD

## Deployment

### GitHub Actions (Automated - Deployed Now! ✅)

The system is **currently deployed** and automatically redeploys:
- On every push to `main` branch
- Every 6 hours on schedule
- Via manual workflow dispatch

**View Deployment Status:** [Actions Tab](https://github.com/Garrettc123/zero-human-governance-core/actions/workflows/deploy-governance.yml)

**Manual Deployment:**
```bash
# Trigger deployment via GitHub Actions
# Go to: Actions > Deploy Governance System > Run workflow
```

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Start governance core
cd governance
python main.py

# Access at http://localhost:8001
```

### Docker (Production)
```bash
docker build -t zero-human-governance .
docker run -p 8001:8001 zero-human-governance
```

For detailed deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md).

## Roadmap

- [ ] Add PostgreSQL for persistent storage
- [ ] Integrate Stripe for billing
- [ ] Add React dashboard
- [ ] Multi-model AI integration (GPT-4, Claude)
- [ ] Enterprise compliance (SOC 2, GDPR)

## License

MIT License - See LICENSE file

## Contact

Built by Garrett Carrol  
GitHub: [@Garrettc123](https://github.com/Garrettc123)

---

**Status**: 🟢 Deployed and Operational  
**Last Updated**: December 27, 2025  
**Deployment**: Active on GitHub Actions