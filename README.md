

# CloudGuard AI

AI-powered Azure Security and Compliance Platform built with FastAPI, Python, Azure SDK, and LangChain.

CloudGuard AI helps organizations assess their Azure infrastructure, identify security misconfigurations, map findings to compliance frameworks, and understand security risks through AI-powered analysis.

## Features

- **Azure Integration:** Connect Azure subscriptions using service principal credentials.

- **Security Scanning:** Scan Azure resources for common security misconfigurations.

- **AI Security Analysis:** Generate risk explanations, potential impacts, and remediation recommendations.

- **Compliance Mapping:** Map security findings to ISO 27001 and SOC 2 controls.

- **Multi-Tenant Architecture:** Isolate users, scans, alerts, and Azure connections by company.

- **Role-Based Access Control:** Owner, Admin, and Analyst permissions.

- **Security History:** Track scans, findings, trends, and alerts.

- **PDF Reports:** Generate security assessment reports.

- **Credential Encryption:** Encrypt Azure client secrets using Fernet.

- **Docker Deployment:** Run the application using Docker Compose.

## Tech Stack

| Category | Technology |

|---|---|

| Backend | Python, FastAPI |

| Database | SQLite, SQLAlchemy |

| Authentication | JWT, Argon2 |

| Cloud | Microsoft Azure SDK |

| AI | LangChain, LangGraph, OpenAI |

| Compliance | ISO 27001, SOC 2 |

| Scheduling | APScheduler |

| Containerization | Docker, Docker Compose |

| Testing | Pytest |

## Project Structure

```text

cloudguard-ai/

├── app/

│   ├── agents/

│   ├── api/

│   │   └── routes/

│   ├── auth/

│   ├── azure/

│   ├── compliance/

│   ├── core/

│   ├── db/

│   ├── reports/

│   ├── scheduler/

│   ├── schemas/

│   ├── security/

│   └── static/

├── Dockerfile

├── compose.yaml

├── .dockerignore

├── .env.example

├── .gitignore

├── [main.py](http://main.py)

├── pyproject.toml

└── uv.lock

```

## Getting Started

### Prerequisites

- Python 3.12+

- uv

- Docker Desktop (for containerized deployment)

- Azure subscription

- OpenAI API key

### Environment Configuration

Clone the repository:

```bash

git clone [https://github.com/aveelash/cloudguard-ai.git](https://github.com/aveelash/cloudguard-ai.git)

cd cloudguard-ai

```

Create your environment file:

```bash

cp .env.example .env

```

Configure the required environment variables in `.env`.

Never commit `.env` or expose credentials.

### Run Locally

Install dependencies:

```bash

uv sync

```

Start the application:

```bash

uv run fastapi dev [main.py](http://main.py)

```

Open:

- Application: [http://localhost:8000](http://localhost:8000)

- Swagger API: [http://localhost:8000/docs](http://localhost:8000/docs)

- Health Check: [http://localhost:8000/health](http://localhost:8000/health)

## Docker Deployment

Build and start the application:

```bash

docker compose up -d --build

```

Check container status:

```bash

docker compose ps

```

View logs:

```bash

docker compose logs -f cloudguard-ai

```

Stop the application:

```bash

docker compose down

```

The SQLite database is stored in a persistent Docker volume.

## Testing

Run the local automated test suite:

```bash

uv run python -m pytest app/agents app/compliance app/security -q --import-mode=importlib

```

Compile application modules:

```bash

uv run python -m compileall app

```

## Security Notes

- Azure client secrets are encrypted at rest.

- Authentication uses JWT tokens.

- Passwords are stored as hashes.

- API access is protected through role-based authorization.

- Company-level data isolation is enforced.

- Secrets and local database files are excluded from Git.

## Current Deployment Notes

- Docker Compose provides a containerized application deployment.

- SQLite uses a persistent Docker volume.

- Automatic scheduled scanning is currently paused.

- Azure scanning requires a configured Azure connection and appropriate permissions.

## Author

**Aveelash Hota**

GitHub: [https://github.com/aveelash](https://github.com/aveelash)