# AttackGraphX

**AI-Driven Attack Path Discovery and Security Risk Prioritization Using Graph Intelligence**

AttackGraphX is an enterprise-grade cyber graph intelligence platform designed to discover, analyze, and mitigate multi-hop attack vectors before malicious actors can exploit them. By unifying automated network reconnaissance, graph topology modeling, Dijkstra/Yen's K-shortest pathfinding algorithms, explainable risk calculations, and what-if remediation simulations, AttackGraphX transforms raw vulnerability telemetry into actionable, prioritized mitigation strategies.

---

## Architecture Overview

```
                               ┌────────────────────────────────────────────────┐
                               │             Frontend Cyber Dashboard           │
                               │      (React 18 / Vite / Cytoscape.js / :5173)   │
                               └───────────────────────┬────────────────────────┘
                                                       │  HTTP (REST / JWT)
                                                       ▼
                               ┌────────────────────────────────────────────────┐
                               │              FastAPI Gateway (:8000)           │
                               │  - JWT Authentication & RBAC (Admin/Analyst)   │
                               │  - Redis Last-Known-Good Stale Cache Fallback  │
                               │  - Executive PDF & CSV Report Generators       │
                               └───────────┬──────────────────────┬─────────────┘
                                           │                      │
                   HTTP Proxy (:9000)      │                      │ Redis Cache / Read-Through
                                           ▼                      ▼
┌────────────────────────────────────────────────────────┐   ┌──────────────────────────┐
│             Analysis Service (:9000)                   │   │   Redis 7 Infrastructure │
│ - Graph Engine: Neo4j (Bolt :7687) + In-Memory NetworkX│   │   - Pub/Sub & Cache (:6379)│
│ - Pathfinder: Dijkstra & Yen's K-Shortest Paths        │   │   - Stream: scan_results │
│ - Explainable Risk Scoring & Severity Stratification   │   └────────────▲─────────────┘
│ - What-If Remediation Engine (Isolated Graph Snapshot) │                │
│ - Redis Stream Consumer (Idempotent Scan Ingestion)    │                │ Stream Publish
│ - AI Agent & Reinforcement Learning Simulation Env     │                │
└────────────────────────────────────────────────────────┘   ┌────────────┴─────────────┐
                                                             │  Recon Service (:8001)   │
                                                             │  - Nmap Scanner Engine   │
                                                             │  - XML Parser (defused)  │
                                                             │  - CIDR Range Validator  │
                                                             └────────────▲─────────────┘
                                                                          │ Active Probing
                                                             ┌────────────┴─────────────┐
                                                             │    Simulated Range Lab   │
                                                             │ (172.20.0.10 - 172.20.0.12)
                                                             │ Nginx, vsftpd, Custom App│
                                                             └──────────────────────────┘
```

---

## Key Capabilities

1. **Deterministic & Resilient Graph Modeling**:
   - Canonical graph schema featuring `Host`, `Service`, `Vulnerability`, `Credential`, and `Asset` nodes.
   - Relationships including `HOSTS`, `EXPOSES`, `HAS_VULNERABILITY`, `CAN_REACH`, `HAS_CREDENTIAL`, and `CAN_COMPROMISE`.
   - Dual-mode graph store: seamlessly interfaces with Neo4j via Cypher queries while maintaining high-performance in-memory fallback for 100% offline testability.

2. **Multi-Hop Attack Pathfinding**:
   - Exploitation transition cost modeling based on CVSS metrics, service exposure, and lateral movement privilege requirements.
   - Directed shortest-path discovery using Dijkstra's algorithm.
   - Alternate path discovery using Yen's K-shortest path algorithm with loop avoidance.

3. **Explainable Risk Formulation**:
   - Formula:
     $$\text{Risk Score} = (\text{Exploitability} \times 0.4) + (\text{Asset Criticality} \times 0.4) + (\text{Exposure} \times 0.2)$$
   - Stratified risk bands:
     - **0 – 30**: LOW
     - **31 – 60**: MEDIUM
     - **61 – 80**: HIGH
     - **81 – 100**: CRITICAL
   - Full factor breakdown with detectability ratings, MITRE ATT&CK technique IDs, and hop-by-hop traversal rationales.

4. **What-If Remediation Simulation**:
   - Performs non-destructive in-memory branching of the active graph snapshot.
   - Models the topological impact of patching vulnerabilities or revoking compromised credentials.
   - Quantifies exact metric deltas: paths eliminated, residual critical paths, and overall risk reduction.
   - Dynamically ranks proposed remediations by risk reduction efficiency.

5. **Asynchronous Reconnaissance Ingestion**:
   - Nmap automation scanning authorized subnets (`172.20.0.0/24`).
   - Secure XML parsing using `defusedxml` preventing XXE injection.
   - Redis Stream (`scan_results`) message publishing and idempotent consumer group processing with duplicate-event protection.

6. **Agentic AI & Reinforcement Learning**:
   - Structured AI agent for autonomous vulnerability investigation and remediation recommendations.
   - Gym-compatible Reinforcement Learning environment (`AttackGraphEnv`) simulating attacker state traversal and benchmark comparisons against classical Dijkstra pathfinding.

---

## Directory Structure

```
AttackGraph/
├── analysis-service/          # Person 2: Attack Graph & What-If Engine
│   ├── analysis_service/
│   │   ├── ai/               # AI reasoning agent & tool-calling
│   │   ├── algorithms/       # Dijkstra & Yen's K-shortest path algorithms
│   │   ├── api/              # FastAPI endpoints on port 9000
│   │   ├── consumer/         # Redis Stream consumer (scan_results)
│   │   ├── graph/            # Dual-mode GraphStore & Enterprise Seed Topology
│   │   ├── models/           # Canonical Pydantic contracts & schemas
│   │   ├── risk/             # Explainable Risk Engine
│   │   ├── rl/               # Gym RL attack path environment
│   │   └── simulation/       # What-If patch simulator & patch ranker
│   ├── tests/                # 32 unit & integration tests
│   └── Dockerfile
├── backend/                   # Person 3: API Gateway & Reporting
│   ├── app/
│   │   ├── auth/             # JWT authentication & RBAC (Admin / Analyst)
│   │   ├── routes/           # REST endpoints (/paths, /patches, /simulate, /reports, /topology, /assets)
│   │   ├── schemas/          # API request & response schemas
│   │   └── services/         # Redis last-known-good cache & analysis client
│   ├── tests/                # 39 unit, cache-fallback & full E2E workflow tests
│   └── Dockerfile
├── recon-service/             # Person 1: Nmap Scanning & Normalization
│   ├── app/
│   │   ├── api/              # Recon HTTP triggers & health check
│   │   ├── models/           # Scan data contract
│   │   ├── normalizer/       # Nmap XML normalization
│   │   ├── publisher/        # Redis Stream publisher
│   │   └── scanner/          # Subnet validation & nmap execution
│   ├── range/                # Docker targets (Nginx web, vsftpd, custom app)
│   ├── tests/unit/           # 73 unit tests
│   └── Dockerfile
├── frontend/                  # Person 3: Interactive Cyber Dashboard
│   ├── src/
│   │   ├── api/              # Gateway HTTP client & dev mock handler
│   │   ├── auth/             # Context-driven JWT auth & protected routing
│   │   ├── components/       # Cytoscape topology, hop stepper, charts, reports
│   │   └── pages/            # Dashboard & Login views
│   └── Dockerfile
├── docker-compose.yml         # Full multi-container orchestration
├── .env.example               # Reference environment configuration
├── IMPLEMENTATION_STATUS.md   # Milestone verification record
├── IMPLEMENTATION_PLAN.md     # Engineering roadmap & dependencies
├── WORKLOG.md                 # Granular work session log
└── NEXT_SESSION.md            # Maintenance and handoff protocol
```

---

## Getting Started

### Prerequisites

- **Docker & Docker Compose** (v2.20+)
- **Python 3.12+**
- **Node.js 20+** & **npm**

### Quickstart with Docker Compose

Deploy the complete multi-service stack with a single command:

```bash
# 1. Clone repository
git clone https://github.com/Shahu1906/AttackGraph.git
cd AttackGraph

# 2. Configure environment
cp .env.example .env

# 3. Build and launch all containers
docker compose up -d --build
```

### Accessing Endpoints

| Component | URL | Credentials / Notes |
|---|---|---|
| **Frontend UI** | `http://localhost:5173` | Login: `admin` / `admin123` or `analyst` / `analyst123` |
| **API Gateway** | `http://localhost:8000` | Docs: `http://localhost:8000/docs` |
| **Analysis Engine** | `http://localhost:9000` | Docs: `http://localhost:9000/docs` |
| **Recon Service** | `http://localhost:8001` | Docs: `http://localhost:8001/docs` |
| **Neo4j Browser** | `http://localhost:7474` | User: `neo4j` / Pass: `attackgraphx123` |
| **Redis** | `localhost:6379` | Message broker & cache |

---

## Automated Test Verification

All modules have extensive automated test coverage across unit, cache-resilience, and full end-to-end integration workflows.

### 1. Analysis Service Test Suite (32 Tests)

```bash
cd analysis-service
pytest tests/ -v
```
- Tests graph persistence, Dijkstra pathfinding, Yen's K-paths, explainable risk calculations, what-if remediation simulations, Redis stream consumer, and AI/RL environments.

### 2. Backend Gateway & E2E Test Suite (39 Tests)

```bash
cd backend
pytest tests/ -v
```
- Tests JWT authentication, RBAC authorization, Redis cache fallbacks, PDF & CSV report exports, and comprehensive end-to-end simulated workflow (`test_full_platform_e2e_workflow`).

### 3. Recon Service Unit Test Suite (73 Tests)

```bash
cd recon-service
pytest tests/unit/ -v
```
- Tests CIDR validation, port ranges, schema normalization, safe XML parsing, and Redis stream publisher.

### 4. Frontend Production Build

```bash
cd frontend
npm run build
```
- Bundles 2,393 React modules into production-ready static assets without errors.

---

## Core API Contract

### Gateway Endpoints (`:8000`)

- `POST /auth/login` — Authenticate and receive signed HS256 JWT token.
- `GET /paths?target={all|host}` — Retrieve ranked attack paths with explainable risk breakdown.
- `GET /patches` — Retrieve recommended remediation patches prioritized by risk reduction.
- `POST /simulate` — Execute What-If simulation (Admin only; Analyst returns 403 Forbidden).
- `POST /simulate/reset` — Reset active simulation state back to live baseline (Admin only).
- `GET /reports/pdf?target={target}` — Download executive PDF report formatted with ReportLab.
- `GET /reports/csv` — Export raw attack telemetry as CSV.
- `GET /topology` — Retrieve Cytoscape graph nodes and edges.
- `GET /assets` — Retrieve enterprise asset inventory.
- `GET /health` — Multi-tier health probe evaluating API, Redis, and upstream Analysis Service.

---

## Security & Reliability Design

- **Zero Unhandled Crashes**: Analysis client employs exponential backoff retry mechanisms with automatic failover to Redis stale cache.
- **Fail-Open Cache Fallback**: When upstream services undergo maintenance, the dashboard displays cached data with a `stale_cache` indicator rather than crashing.
- **Defensive XML Parsing**: Subnet XML scans are parsed strictly using `defusedxml` to block billion-laughs and external entity attacks.
- **Role-Based Access Control**: Sensitive actions (What-If remediation execution, scan triggering) are restricted exclusively to `admin` role tokens.