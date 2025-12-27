# Deployment Guide

## 🚀 Zero-Human Governance Core Deployment

This document provides instructions for deploying the Zero-Human Governance Core system.

## Deployment Methods

### 1. Automatic Deployment (Recommended)

The system automatically deploys on every push to the `main` branch via GitHub Actions.

**Workflow File:** `.github/workflows/deploy-governance.yml`

**Triggers:**
- Push to `main` branch
- Scheduled runs every 6 hours
- Manual workflow dispatch

### 2. Manual Deployment via GitHub Actions

1. Go to the [Actions tab](https://github.com/Garrettc123/zero-human-governance-core/actions)
2. Select "Deploy Governance System" workflow
3. Click "Run workflow" button
4. Select the branch (usually `main`)
5. Click "Run workflow"

### 3. Local Deployment

For local testing and development:

```bash
# Install dependencies
pip install fastapi uvicorn pydantic requests

# Start governance core
cd governance
python main.py

# The API will be available at http://localhost:8001
```

## Deployment Status

The system is currently deployed and running on GitHub Actions infrastructure.

**Current Status:** ✅ Active

**Last Deployment:** Check [workflow runs](https://github.com/Garrettc123/zero-human-governance-core/actions/workflows/deploy-governance.yml)

## Environment Variables

Configure these in GitHub Repository Settings > Secrets:

- `GITHUB_TOKEN` - Automatically provided by GitHub Actions
- `OPENAI_API_KEY` - (Optional) For AI integrations
- `STRIPE_SECRET_KEY` - (Optional) For payment processing

## Deployment Architecture

```
GitHub Actions Runner
  ├── Install Python 3.11
  ├── Install Dependencies (fastapi, uvicorn, pydantic, requests)
  ├── Start Governance Core (port 8001)
  └── Health Check
```

## Health Check

To verify the deployment is running:

```bash
curl http://localhost:8001/
```

Expected response:
```json
{
  "system": "Zero-Human Governance Core",
  "status": "operational",
  "proposals_count": 0,
  "pending_approvals": 0
}
```

## API Endpoints

Once deployed, the following endpoints are available:

- `GET /` - System status
- `POST /proposals` - Submit proposal
- `GET /proposals` - List all proposals
- `POST /proposals/{id}/approve` - Approve proposal
- `POST /proposals/{id}/reject` - Reject proposal
- `GET /metrics` - System metrics

## Monitoring

Monitor deployments through:

1. **GitHub Actions Logs:** Check workflow run logs for deployment details
2. **System Metrics:** Access `/metrics` endpoint for operational metrics
3. **Proposal Status:** Use `/proposals` endpoint to track proposal activity

## Troubleshooting

### Deployment Fails

1. Check GitHub Actions logs for error messages
2. Verify all dependencies are correctly specified
3. Ensure Python version compatibility (3.11+)

### Service Not Responding

1. Check if the service started successfully in logs
2. Verify port 8001 is not blocked
3. Review health check output

### Dependencies Issues

```bash
# Reinstall dependencies
pip install --upgrade fastapi uvicorn pydantic requests
```

## Production Deployment (Future)

For production deployment to cloud infrastructure:

### Docker Deployment

```bash
# Build image
docker build -t zero-human-governance .

# Run container
docker run -p 8001:8001 zero-human-governance
```

### Cloud Platforms

- **AWS:** Deploy to ECS, EKS, or EC2
- **Google Cloud:** Deploy to Cloud Run or GKE
- **Azure:** Deploy to Container Instances or AKS
- **Heroku:** Use Heroku CLI for deployment

## Rollback

To rollback to a previous version:

1. Go to Actions tab
2. Find the last successful deployment
3. Re-run that workflow
4. Or revert the commit and push to main

## Security Considerations

- All approvals are cryptographically signed
- Audit trail maintained for all decisions
- Environment variables stored securely in GitHub Secrets
- HTTPS recommended for production deployments

## Support

For issues or questions:
- Open an issue on GitHub
- Check existing [workflow runs](https://github.com/Garrettc123/zero-human-governance-core/actions)
- Review the [README](README.md)

---

**Last Updated:** December 27, 2025
