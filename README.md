# PatchGuard.ai — Risk-Aware Software Upgrade Orchestrator

> **An agentic AI platform** that ingests live vulnerability intelligence, maps it to enterprise service dependency graphs, and generates a ranked, explainable, low-disruption upgrade plan — then autonomously executes approved patches with canary deployments and automatic rollback.

**Fictional enterprise:** Harborview Financial Services — a mid-sized financial company (~850 employees, $220M revenue, hybrid AWS + on-prem infrastructure).

---

## ⚡ Quick Start

```bash
# 1. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate          # macOS/Linux
# venv\Scripts\activate           # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Enable AI features — requires a Google Gemini API key
export GEMINI_API_KEY="your-key-here"

# 4. Run the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Then open:
- **Dashboard:** http://localhost:8000/
- **API Docs:** http://localhost:8000/docs

> AI features (ReAct agent, AI explanations, NL queries) are optional — the full scoring and planning pipeline runs without any API key.

---

## 🏗️ Architecture

### Multi-Agent Pipeline (6 Agents)

| # | Agent | Responsibility |
|---|-------|---------------|
| 1 | **Vulnerability Ingestion** | Load & normalize CVE/KEV/EPSS data from live feeds |
| 2 | **Asset & Dependency Context** | Build NetworkX service graph, match CVEs to services |
| 3 | **Risk Reasoning** | Compute business-aware composite risk scores (0–100) |
| 4 | **Upgrade Planning** | Rank upgrades, assign maintenance windows, build plans |
| 5 | **Governance** | Enforce tier-based approval policies and compliance rules |
| 6 | **Explanation** | Generate human-readable rationale and executive summaries |

### Scoring Formula

```
final_score = 0.30 × severity + 0.25 × exploitability + 0.20 × business_impact
            + 0.15 × blast_radius + 0.10 × exposure
            − 0.08 × complexity_penalty − 0.05 × maintenance_penalty
```

All sub-scores normalized to 0–100. Sub-scores and rationale are stored on every plan item for full explainability.

---

## 🎯 Key Features

- **Business-Aware Scoring** — Goes beyond CVSS. Factors in blast radius, service tier, exploit probability (EPSS), KEV catalog status, regulatory scope (PCI-DSS, SOX, GDPR), and maintenance window feasibility
- **Gemini ReAct Agent** — Uses a Reason + Act loop with 10 tools (CVE lookup, dependency graph queries, runbook retrieval, script generation) to autonomously triage vulnerabilities and execute patches step-by-step
- **Autonomous Execution Engine** — Canary-first patch deployment (10% traffic) → health verification → full rollout or automatic rollback, with a complete audit trail
- **Live Feed Integration** — Real-time CISA KEV catalog, NVD CVE API, and FIRST EPSS scores enriched into every analysis run
- **Dependency Graph** — Interactive vis-network visualization (tier-colored nodes, criticality-colored edges) with betweenness centrality hub detection and cycle detection
- **CVSS vs Business-Aware Comparison** — Side-by-side ranking delta showing exactly why business context reorders priorities
- **Human-in-the-Loop Approvals** — Tier-1 and payment/auth services always require human sign-off; auto-approve can trigger the ReAct remediation agent immediately on approval
- **Cost-of-Delay Analytics** — Daily financial risk ($) per unpatched finding, trend charts across pipeline runs, and smart maintenance-window batch scheduling
- **Full Explainability** — Every recommendation includes technical, business, operational rationale plus structured explanation objects
- **Change Planning** — Pre-checks, execution steps, rollback procedures, and post-checks generated for every upgrade
- **Report Export** — JSON, CSV, and plain-text executive summary exports with live execution status and audit trail
- **AI Assistant** — Natural language Q&A over the risk dataset, AI-generated executive summaries, and per-item deep-dive explanations (all via Gemini)

---

## 📂 Repository Structure

```text
PatchGuard.ai/
├── app/
│   ├── main.py             # FastAPI app — 35+ endpoints
│   ├── config.py           # Scoring weights, thresholds, feed URLs
│   ├── models.py           # Pydantic v2 data models
│   ├── loaders.py          # JSON data I/O layer
│   ├── core/
│   │   ├── graph_engine.py # NetworkX DiGraph — blast radius, hub detection
│   │   ├── scoring.py      # Business-aware composite risk scoring
│   │   ├── matching.py     # CVE-to-service matching with alias normalization
│   │   ├── explainer.py    # Structured explanation generation
│   │   └── policy.py       # Tier-based approval and governance rules
│   ├── agents/
│   │   ├── orchestrator.py # 6-agent sequential pipeline
│   │   ├── gemini_agent.py # Gemini ReAct agent + 10 tools
│   │   └── execution_agent.py # Autonomous patch execution orchestrator
│   ├── services/
│   │   ├── cve_provider.py          # Live NVD/KEV/EPSS feed fetchers
│   │   ├── llm_service.py           # Gemini API wrapper
│   │   ├── execution_service.py     # Canary + full rollout simulation
│   │   ├── execution_state.py       # Execution state machine & persistence
│   │   ├── verification_service.py  # Pre/post health checks
│   │   ├── rollback_service.py      # Automated rollback logic
│   │   ├── change_control_service.py # Approval routing
│   │   ├── notification_service.py  # Alert queue
│   │   ├── report_service.py        # JSON/CSV/text export
│   │   └── analytics.py             # Cost-of-delay, trends, batch windows
│   ├── demo_data/          # Synthetic Harborview fixture data (15 services, 18 CVEs)
│   ├── templates/          # Jinja2 dashboard (8-tab UI)
│   └── static/             # Dark-theme CSS + vis-network JS
├── tests/
│   └── test_smoke.py       # 12-test suite covering all core modules
├── requirements.txt
└── PROJECT_REPORT.md
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|---------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/services` | All services |
| GET | `/api/services/{name}` | Service detail + blast radius |
| GET | `/api/vulnerabilities` | Vulnerabilities (`kev_only`, `severity_min` filters) |
| POST | `/api/vulnerabilities` | Add single vulnerability |
| POST | `/api/vulnerabilities/ingest` | Batch ingest |
| POST | `/api/analysis/run` | Execute full 6-agent pipeline |
| GET | `/api/analysis/latest` | Latest analysis results |
| GET | `/api/plan` | Active ranked upgrade plan |
| GET | `/api/plan/{rank}` | Plan item detail |
| GET | `/api/graph` | Dependency graph (vis.js JSON) |
| GET | `/api/comparison` | CVSS-only vs business-aware ranking delta |
| POST | `/api/approvals/{cve}/{svc}` | Submit approval decision |
| GET | `/api/approvals` | All approval records |
| POST | `/api/approvals/{cve}/{svc}/auto-remediate` | Approve + trigger autonomous patch |
| GET | `/api/feeds/kev` | Live CISA KEV catalog |
| GET | `/api/feeds/enrich` | Enrich vulns with live KEV/EPSS |
| GET | `/api/analytics/trend` | Risk trend data across runs |
| GET | `/api/analytics/batches` | Maintenance-window batch schedule |
| POST | `/api/agents/triage/{cve}/{svc}` | Run Gemini ReAct triage agent |
| POST | `/api/agents/remediate/{cve}/{svc}` | Run Gemini ReAct remediation agent |
| POST | `/api/agents/blast-radius/{svc}` | Run blast radius analysis agent |
| POST | `/api/ai/explain/{rank}` | AI explanation for a plan item |
| POST | `/api/ai/query` | Natural language Q&A over risk data |
| POST | `/api/ai/summary` | AI-generated executive summary |
| POST | `/api/execution/start` | Start autonomous remediation |
| GET | `/api/execution/list` | All execution records |
| GET | `/api/execution/{id}` | Execution detail + full trace |
| POST | `/api/execution/{id}/approve` | Approve a pending execution |
| GET | `/api/notifications` | Agent notification queue |
| GET | `/api/reports/export.json` | Full JSON export |
| GET | `/api/reports/export.csv` | CSV plan export |
| GET | `/api/reports/executive-summary.txt` | Executive summary text |

---

## 🧪 Testing

```bash
pytest tests/ -v
```

Covers: data loading, graph construction, blast radius, CVE matching, scoring, policy evaluation, full pipeline, CVSS vs business-aware comparison.

---

## 📝 Notes

- AI features require `GEMINI_API_KEY`; all other features run fully offline on synthetic data
- All external APIs (NVD, CISA KEV, EPSS) have graceful fallback — the system never hard-fails on a network error
- JSON file persistence by design for portability; production migration path to PostgreSQL documented in `PROJECT_REPORT.md`
