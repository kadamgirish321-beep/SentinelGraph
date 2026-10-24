# SentinelGraph
### AI-Driven Attack Path Discovery and Security Risk Prioritization

SentinelGraph is a cybersecurity platform designed to discover potential multi-hop attack paths, analyze security risks, and prioritize remediation using graph intelligence, automated reconnaissance, and explainable risk scoring.

The platform combines a React dashboard, a FastAPI backend, a graph analysis engine, and a reconnaissance service to transform network scan results into actionable security insights.

## Key Features

- **Attack Path Discovery:** Find potential attack paths using Dijkstra's shortest-path algorithm and Yen's K-shortest-path algorithm.
- **Interactive Security Dashboard:** Explore graph topology, attack paths, assets, and risk metrics through a React-based interface.
- **Explainable Risk Scoring:** Prioritize risks using exploitability, asset criticality, and exposure.
- **What-If Remediation:** Simulate vulnerability patching and credential revocation to estimate their impact on attack paths and overall risk.
- **Automated Reconnaissance:** Integrate Nmap scanning, XML parsing, and scan-result normalization.
- **Graph Intelligence:** Model relationships among hosts, services, vulnerabilities, credentials, and assets.
- **AI and Reinforcement Learning:** Includes an AI investigation agent and a reinforcement-learning environment for attack-path exploration.
- **Resilient Architecture:** Uses Redis for caching and asynchronous scan-result processing.

## Architecture

SentinelGraph consists of four main services:

| Component | Responsibility | Technology |
|---|---|---|
| Frontend | Interactive dashboard and graph visualization | React, Vite, Cytoscape.js |
| Backend | REST API, authentication, authorization, and reporting | Python, FastAPI, JWT |
| Analysis Service | Graph processing, pathfinding, risk scoring, and simulations | Python, NetworkX, Neo4j integration |
| Recon Service | Network scanning and scan-result normalization | Python, Nmap, defusedxml |

Supporting infrastructure includes Redis for caching and asynchronous messaging, Neo4j for graph storage, and Docker Compose for multi-service orchestration.

## Technology Stack

**Frontend**
- React
- Vite
- Cytoscape.js
- JavaScript

**Backend and Analysis**
- Python
- FastAPI
- Pydantic
- NetworkX
- Neo4j integration
- Dijkstra's algorithm
- Yen's K-shortest-path algorithm

**Infrastructure and Security**
- Docker and Docker Compose
- Redis
- Nmap
- JWT authentication
- Role-based access control
- `defusedxml` for defensive XML parsing

## Risk Scoring

The platform uses an explainable risk-scoring model:

**Risk Score**

`(Exploitability × 0.4) + (Asset Criticality × 0.4) + (Exposure × 0.2)`

The score is intended to help prioritize security findings based on exploitation potential, asset importance, and exposure.

Risk categories defined by the project:

| Score | Risk Level |
|---|---|
| 0–30 | Low |
| 31–60 | Medium |
| 61–80 | High |
| 81–100 | Critical |

## Project Structure

```text
SentinelGraph/
├── analysis-service/
│   ├── analysis_service/
│   │   ├── ai/
│   │   ├── algorithms/
│   │   ├── api/
│   │   ├── consumer/
│   │   ├── graph/
│   │   ├── models/
│   │   ├── risk/
│   │   ├── rl/
│   │   └── simulation/
│   └── tests/
├── backend/
│   ├── app/
│   │   ├── auth/
│   │   ├── routes/
│   │   ├── schemas/
│   │   └── services/
│   └── tests/
├── frontend/
│   └── src/
│       ├── api/
│       ├── auth/
│       ├── components/
│       └── pages/
├── recon-service/
│   ├── app/
│   │   ├── api/
│   │   ├── normalizer/
│   │   ├── publisher/
│   │   └── scanner/
│   ├── range/
│   └── tests/
├── docker-compose.yml
├── .env.example
├── README.md
└── .gitignore
```

## Getting Started

### Prerequisites

- Git
- Docker and Docker Compose
- Python 3.12 or later
- Node.js and npm

The full multi-service deployment requires Docker and Docker Compose.

### 1. Clone the repository

```bash
git clone https://github.com/kadamgirish321-beep/SentinelGraph.git
cd SentinelGraph
```

### 2. Configure environment variables

Review `.env.example` and the service-specific environment examples.

Create your local `.env` files as required by the configuration, and replace all placeholder values with appropriate local settings. Keep real credentials and secrets out of Git.

### 3. Start the services

From the project root, run:

```bash
docker compose up -d --build
```

Use this command after verifying that the Docker Compose configuration and required environment variables are ready.

### 4. Access the application

The project configuration defines these local service endpoints:

| Service | Local URL |
|---|---|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:8000 |
| Backend API documentation | http://localhost:8000/docs |
| Analysis Service | http://localhost:9000 |
| Recon Service | http://localhost:8001 |

Service availability depends on successful startup and configuration.

## Testing

The repository includes unit, integration, and end-to-end tests.

### Analysis Service

```bash
cd analysis-service
pip install -r requirements.txt
pytest tests/ -v
```

### Backend

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

### Recon Service

```bash
cd recon-service
pip install -r requirements.txt
pytest tests/unit/ -v
```

### Frontend Production Build

```bash
cd frontend
npm ci
npm run build
```

Some tests may require supporting services or additional environment configuration.

## Security Considerations

- Use only on systems and network ranges you own or are explicitly authorized to assess.
- Keep passwords, API keys, and JWT secrets in private environment files.
- Use strong, unique secrets for local or deployed environments.
- Review authentication and authorization settings before deployment.
- Treat scan results and generated attack paths as security-sensitive information.

## Project Goals

SentinelGraph explores how graph algorithms, security telemetry, explainable risk models, and remediation simulations can support more informed vulnerability prioritization.

The project brings together concepts from graph theory, cybersecurity, backend engineering, distributed systems, and interactive data visualization.

## License

No license has been specified yet. Check with the project contributors before adding a license or redistributing the code.
