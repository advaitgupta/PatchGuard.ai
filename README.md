# Risk-Aware Software Upgrade Orchestrator

> **An agentic AI platform** that ingests vulnerability intelligence, maps it to enterprise services and dependency graphs, then generates a ranked, explainable, low-disruption upgrade plan for a real firm.

**Fictional enterprise:** Harborview Financial Services — a mid-sized financial services company (~850 employees, $220M revenue, hybrid AWS + on-prem infrastructure).

---

## ⚡ Quick Start

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Then open:
- **Dashboard:** http://localhost:8000/
- **API Docs:** http://localhost:8000/docs

---

## 🏗️ Architecture

### Multi-Agent Pipeline (6 Agents)

| # | Agent | Responsibility |
|---|-------|---------------|
| 1 | **Vulnerability Ingestion** | Load & normalize CVE/KEV/EPSS data |
| 2 | **Asset & Dependency Context** | Build service graph, match vulns to services |
| 3 | **Risk Reasoning** | Compute business-aware composite risk scores |
| 4 | **Upgrade Planning** | Rank upgrades, assign windows, build plans |
| 5 | **Governance** | Enforce approval policies and compliance rules |
| 6 | **Explanation** | Generate human-readable rationale |

### Scoring Formula

```
final_score = 0.30 × severity + 0.25 × exploitability + 0.20 × business_impact
            + 0.15 × blast_radius + 0.10 × exposure
            - penalties(complexity, maintenance_window)
```

All sub-scores normalized to 0–100.  The system stores both raw sub-scores and final composite for full explainability.

---

## 📂 Repository Structure

```text
risk_upgrade_orchestrator/
├── app/
│   ├── main.py           # FastAPI app with 25+ endpoints
│   ├── config.py          # Scoring weights, thresholds, feed URLs
│   ├── models.py          # Pydantic data models
│   ├── loaders.py         # JSON data loading/saving
│   ├── core/
│   │   ├── graph_engine.py  # NetworkX dependency graph
│   │   ├── scoring.py      # Business-aware risk scoring
│   │   ├── matching.py     # Vulnerability-to-service matching
│   │   ├── explainer.py    # Explanation generation
│   │   └── policy.py       # Approval/governance policies
│   ├── agents/
│   │   └── orchestrator.py  # Multi-agent pipeline
│   ├── services/
│   │   ├── cve_provider.py  # Live NVD/KEV/EPSS feeds
│   │   └── report_service.py # JSON/CSV/text export
│   ├── demo_data/           # Synthetic Harborview data
│   ├── templates/           # Jinja2 dashboard
│   └── static/              # CSS + JS
├── tests/
│   └── test_smoke.py        # Comprehensive test suite
├── requirements.txt
└── README.md
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|---------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/services` | All services |
| GET | `/api/services/{name}` | Service detail + blast radius |
| GET | `/api/vulnerabilities` | Vulnerabilities (filter: `kev_only`, `severity_min`) |
| POST | `/api/vulnerabilities` | Add single vulnerability |
| POST | `/api/vulnerabilities/ingest` | Batch ingest |
| POST | `/api/analysis/run` | Execute full 6-agent pipeline |
| GET | `/api/analysis/latest` | Latest analysis results |
| GET | `/api/plan` | Ranked upgrade plan |
| GET | `/api/plan/{rank}` | Plan item detail |
| GET | `/api/graph` | Dependency graph (vis.js JSON) |
| GET | `/api/comparison` | CVSS-only vs business-aware ranking |
| POST | `/api/approvals/{cve}/{svc}` | Submit approval decision |
| GET | `/api/approvals` | All approval records |
| GET | `/api/feeds/kev` | Live CISA KEV feed |
| GET | `/api/feeds/enrich` | Enrich vulns with live KEV/EPSS |
| GET | `/api/reports/export.json` | Full JSON export |
| GET | `/api/reports/export.csv` | CSV plan export |
| GET | `/api/reports/executive-summary.txt` | Executive summary text |

---

## 🎯 Key Features

- **Business-Aware Scoring** — Goes beyond CVSS to include blast radius, service criticality, exploit probability, and maintenance feasibility
- **Live Feed Integration** — Real-time CISA KEV catalog and EPSS scores from public APIs
- **Dependency Graph** — Interactive vis.js visualization showing service-to-service dependencies, critical paths, and hub services
- **CVSS vs Business-Aware Comparison** — Side-by-side ranking comparison showing why business context changes priorities
- **Human-in-the-Loop Approvals** — Tier-1 and payment/auth services require human approval before execution
- **Full Explainability** — Every recommendation includes technical, business, and operational rationale
- **Change Planning** — Pre-checks, execution steps, rollback procedures, and post-checks for every upgrade
- **Report Export** — JSON, CSV, and executive summary exports

---

## 📊 Demo Script

| Minute | Show |
|--------|------|
| 1 | Service graph and enterprise landscape |
| 2 | Vulnerabilities arriving and matching to services |
| 3 | Risk scoring with business context |
| 4 | Ranked upgrade plan with explanations |
| 5 | Approval workflow and blast-radius handling |

---

## 🧪 Testing

```bash
pytest tests/ -v
```

---

## 📝 Notes

- Uses synthetic data by design for reproducibility and safety
- SQLite-compatible for hackathon; designed for PostgreSQL in production
- No API keys required for public vulnerability feeds (NVD, CISA KEV, EPSS)
