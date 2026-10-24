# AttackGraphX — Implementation Plan & Dependency Roadmap

## 1. System Vision & Architecture Principles
AttackGraphX is designed around decoupled, resilient microservices communicating asynchronously over Redis Streams and synchronously over authenticated REST APIs.

### Service Topology & Dependency Order
```
Level 0: Infrastructure
  ├── Redis 7 (Broker & Stale Cache)
  └── Neo4j 5 (Persistent Graph Database)

Level 1: Core Reconnaissance & Ingestion
  ├── Attack Range (Virtual Lab Targets)
  └── Reconnaissance Service (Nmap scanner & Stream Publisher)

Level 2: Graph Analytics & Intelligence
  └── Analysis Service (Graph Engine, Dijkstra, Risk Scoring, What-If Simulation)

Level 3: Edge Gateway & Security
  └── API Gateway (JWT Auth, RBAC, Proxy, Stale Cache Fallback, PDF/CSV Reports)

Level 4: User Experience & Visualization
  └── Frontend Cyber Dashboard (React 18, Cytoscape.js, Recharts, Responsive Stepper)
```

---

## 2. Milestone Breakdown & Progress

| Milestone | Scope & Deliverables | Status | Tests Verified |
|---|---|---|---|
| **M1: System Audit & Baseline** | Repository audit, environment setup, dependency verification, baseline tests. | **COMPLETED** | Backend: 36, Recon: 73, Frontend build |
| **M2: Analysis Engine Core** | Graph model, Enterprise seed topology, Neo4j & NetworkX dual-mode engine, Dijkstra & Yen's K-paths. | **COMPLETED** | 16 unit tests |
| **M3: Risk Engine & What-If** | Explainable formula, severity classification, isolated simulation snapshot, patch ranking. | **COMPLETED** | 8 unit tests |
| **M4: Streaming Ingestion** | Redis stream consumer group, idempotent processing, dynamic topology edge synthesis. | **COMPLETED** | 2 integration tests |
| **M5: Gateway Integration** | Upstream HTTP client, cache fallback, topology & assets routing, PDF/CSV export. | **COMPLETED** | 39 gateway tests |
| **M6: Frontend Alignment** | Live API client integration, topology & assets API hooks, build validation. | **COMPLETED** | Vite build: 2,393 modules |
| **M7: End-to-End Verification** | Recon -> Stream -> Analysis -> Gateway -> Auth -> PDF/CSV full lifecycle test. | **COMPLETED** | `test_e2e_workflow.py` PASS |
| **M8: AI & RL Extensions** | Autonomous LLM agent tool-calling, Gym RL exploration benchmark vs Dijkstra. | **COMPLETED** | 3 tests |
| **M9: Packaging & Documentation**| Docker Compose orchestration, comprehensive `README.md`, status & handoff guides. | **COMPLETED** | Full stack spec |

---

## 3. Dependency Verification Order

When validating or maintaining components, always proceed in the following order:
1. **Models & Schemas**: Verify canonical models in `recon-service/app/models/scan_models.py` and `analysis-service/analysis_service/models/`.
2. **Analysis Service Algorithms & Graph Store**: Run `pytest analysis-service/tests`.
3. **Recon Service Normalization & Publisher**: Run `pytest recon-service/tests/unit`.
4. **API Gateway Auth, Cache & Routes**: Run `pytest backend/tests`.
5. **End-to-End Lifecycle Workflow**: Run `pytest backend/tests/test_e2e_workflow.py`.
6. **Frontend Static Bundle**: Run `npm run build` in `frontend/`.
