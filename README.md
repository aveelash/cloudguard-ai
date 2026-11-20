# CloudGuard AI 🛡️

### Azure security, compliance, and AI-powered risk analysis — in one place.

Cloud infrastructure can be difficult to secure. A misconfigured storage account, an overly permissive role, or an exposed service can create risks that are easy to overlook.

**CloudGuard AI** is a security and compliance platform built to help identify those risks in Microsoft Azure.

It scans Azure infrastructure, detects common security misconfigurations, maps findings to compliance controls, and uses AI to explain what went wrong and how to fix it.

Built with Python, FastAPI, Azure SDK, and LangChain.

---

## What can it do?

- **Scan Azure infrastructure** — Connect an Azure subscription and inspect supported resources for security misconfigurations.
- **Find security risks** — Detect issues across storage, networking, Key Vault, App Services, and access permissions.
- **Explain findings with AI** — Understand why an issue matters, its potential impact, and recommended remediation.
- **Map compliance controls** — Connect security findings with ISO 27001 and SOC 2 controls.
- **Track security over time** — Review scan history, findings, trends, and security alerts.
- **Generate PDF reports** — Export security assessment results.
- **Manage multiple organizations** — Keep company data isolated with role-based access for Owners, Admins, and Analysts.

## How it works

The workflow is straightforward:

```
Connect Azure Subscription
          |
          v
  Collect Resource Data
          |
          v
  Run Security Checks
          |
          v
  Identify Misconfigurations
          |
          v
  AI-Powered Risk Analysis
          |
          v
  Compliance Mapping
          |
          v
  Dashboard & PDF Reports
```

The goal isn't just to report that something is wrong. It's to make the finding understandable and actionable.

## Security is more than scanning

CloudGuard AI also includes security controls around the platform itself:

- JWT-based authentication.
- Password hashing.
- Company-level data isolation.
- Role-based access control.
- Encrypted Azure client credentials using Fernet.
- Protected API endpoints based on user permissions.

Azure credentials are encrypted before being stored. They are not returned in API responses.

## Built with

| Area              | Technology                   |
| ----------------- | ---------------------------- |
| Backend           | Python, FastAPI              |
| Database          | SQLite, SQLAlchemy           |
| Authentication    | JWT, Argon2                  |
| Cloud Integration | Microsoft Azure SDK          |
| AI                | LangChain, LangGraph, OpenAI |
| Compliance        | ISO 27001, SOC 2             |
| Scheduling        | APScheduler                  |
| Deployment        | Docker, Docker Compose       |
| Testing           | Pytest                       |

## Project structure

```
cloudguard-ai/
│
├── app/
│   ├── agents/       # AI security analysis
│   ├── api/          # FastAPI routes
│   ├── auth/         # Authentication and permissions
│   ├── azure/        # Azure integrations
│   ├── compliance/   # Compliance control mapping
│   ├── core/         # Configuration and encryption
│   ├── db/           # Database models
│   ├── reports/      # PDF report generation
│   ├── scheduler/    # Scan scheduling
│   ├── schemas/      # Data validation
│   ├── security/     # Security scanning rules
│   └── static/       # Login and dashboard
│
├── Dockerfile
├── compose.yaml
├── main.py
├── pyproject.toml
├── uv.lock
└── .env.example
```

## Run it locally

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- An Azure subscription
- An OpenAI API key
- Docker Desktop (for Docker deployment)

### 1. Clone the repository

```
git clone https://github.com/aveelash/cloudguard-ai.git
cd cloudguard-ai
```

### 2. Set up the environment

```
cp .env.example .env
```

Add your configuration to `.env`:

```
OPENAI_API_KEY=
AZURE_SUBSCRIPTION_ID=
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_CREDENTIAL_ENCRYPTION_KEY=
JWT_SECRET_KEY=
```

Use strong, securely generated secrets. Never commit your `.env` file.

### 3. Install dependencies

```
uv sync
```

### 4. Start the application

```
uv run fastapi dev main.py
```

Open the application:

| Service           | URL                                                          |
| ----------------- | ------------------------------------------------------------ |
| Application       | [http://localhost:8000](http://localhost:8000)               |
| API Documentation | [http://localhost:8000/docs](http://localhost:8000/docs)     |
| Health Check      | [http://localhost:8000/health](http://localhost:8000/health) |

## Run with Docker

CloudGuard AI can also run as a Docker container using Docker Compose.

```
docker compose up -d --build
```

Check the container:

```
docker compose ps
```

View application logs:

```
docker compose logs -f cloudguard-ai
```

Stop the application:

```
docker compose down
```

The Docker deployment stores its SQLite database in a persistent volume, so restarting the container does not remove its data.

## Testing

The project includes automated tests for security rules, scanning logic, AI analysis, and compliance mapping.

Run the test suite:

```
uv run python -m pytest app/agents app/compliance app/security -q --import-mode=importlib
```

Compile application modules:

```
uv run python -m compileall app
```

## Current project status

- Core application and API implemented.
- Azure integration and security scanning tested.
- Authentication, authorization, and multi-tenant isolation implemented.
- AI analysis and compliance mapping implemented.
- PDF reporting implemented.
- Docker build and persistent storage verified.
- Automated tests passing.

**Note:** Automatic scheduled scanning is currently paused. Manual scans are available when an Azure connection is configured with the required permissions.

## What's next?

CloudGuard AI is a hands-on project focused on bringing together cloud security, backend engineering, AI, and compliance.

There is still room to improve its coverage as cloud environments and security requirements evolve.

If you're interested in the implementation, feel free to explore the source code.

---

**Built by [Aveelash Hota](https://github.com/aveelash)**

[GitHub Repository](https://github.com/aveelash/cloudguard-ai)