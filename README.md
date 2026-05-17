# Agentic Security Operations Platform with Real-Time ML Detection

AI-Driven Threat Detection & Simulation Engine — a full-stack SOC (Security Operations Center) platform powered by Claude AI, AI Agents, real public IDS datasets, and a live event replay engine.

## Overview

ThreatVision combines real-time threat detection, AI-driven incident analysis, adversarial simulation, and real-dataset ML benchmarking into a unified SOC platform:

- **Red Agent** — simulates attacker TTPs mapped to MITRE ATT&CK
- **Blue Agent** — analyzes incidents and generates defensive playbooks via Claude
- **Playbook Agent** — orchestrates multi-step remediation workflows
- **Simulation Engine** — runs controlled attack/defense scenarios
- **Threat Classifier** — 9-step ML + rule-based detection pipeline (IsolationForest + 12 rules)
- **Real Dataset ML** — trains and benchmarks IsolationForest on NSL-KDD and UNSW-NB15
- **Dataset Replay Engine** — streams real labeled attack records through the live ingestion pipeline
- **Real-time Dashboard** — live SOC view with WebSocket updates, data source selector, and benchmark card
- **Analyst & Ticket System** — workload management, SLA tracking, auto-assignment
- **Audit Logger** — immutable SHA-256 hash-chained audit trail

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         ThreatVision                             │
│                                                                  │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │   Frontend   │   │   Backend    │   │      AI Agents       │  │
│  │  Next.js 14  │◄──│   FastAPI    │──►│  Claude (Anthropic)  │  │
│  │  Zustand WS  │   │  WS / REST   │   │  Red · Blue · Plays  │  │
│  └──────────────┘   └──────────────┘   └──────────────────────┘  │
│                            │                                     │
│           ┌────────────────┼────────────────┐                    │
│           ▼                ▼                ▼                    │
│      ┌─────────┐    ┌──────────┐    ┌──────────┐                 │
│      │Postgres │    │  Redis   │    │ ChromaDB │                 │
│      │(events) │    │(streams) │    │(vectors) │                 │
│      └─────────┘    └──────────┘    └──────────┘                 │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │                 Dataset ML Pipeline                       │   │
│  │  NSL-KDD (22 MB) + UNSW-NB15 (183 MB parquet)             │   │
│  │  Download → Load → Feature Extract → Train → Benchmark    │   │
│  │  Replay Engine → Redis Stream → Classifier → Dashboard    │   │
│  └───────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14, React, Zustand, Recharts, Framer Motion |
| Backend | Python 3.12, FastAPI, SQLAlchemy (asyncpg), Pydantic v2 |
| AI | Anthropic Claude (claude-sonnet-4-6) |
| ML | scikit-learn IsolationForest, StandardScaler |
| Datasets | NSL-KDD, UNSW-NB15 (via HuggingFace parquet mirror) |
| Vector DB | ChromaDB (port 8001) |
| Cache/Stream | Redis Streams (XADD/XREADGROUP) |
| Database | PostgreSQL 16 (asyncpg) |

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Node.js 18+ (for local dev)
- Python 3.12+ (for local dev)

### 1. Clone and configure

```bash
git clone https://github.com/chaithanyakrishnasn/threatvision
cd threatvision
cp .env.example .env
# Add your ANTHROPIC_API_KEY to .env (optional — agents have fallbacks)
```

### 2. One-command demo start

```bash
bash start-demo.sh
```

On first run this will:
1. Start PostgreSQL, Redis, and ChromaDB via Docker
2. Auto-download NSL-KDD (~22 MB) and UNSW-NB15 (~183 MB) to `backend/app/datasets/cache/`
3. Seed 50 classified ThreatEvents + 5 analysts + 8 demo tickets
4. Start the backend API and Next.js frontend

Services after startup:
- Dashboard: http://localhost:3000/dashboard
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### 3. Full Docker stack

```bash
make docker-up    # build + start all 5 services
make docker-down
make docker-clean # also removes volumes
```

### 4. Local development

```bash
# Infrastructure only
docker compose up -d postgres redis chromadb

# Backend
cd backend && pip install -e ".[dev]"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend
cd frontend && npm install && npm run dev

# Or both in parallel
make dev
```

### 5. Seed data (manual)

```bash
cd backend
python3 -m app.data.seed_db        # 50 classified ThreatEvents + Incidents
python3 -m app.data.seed_analysts   # 5 analysts + 1 project + 8 demo tickets
```

## Real Dataset ML

ThreatVision trains and evaluates its IsolationForest anomaly detector on two public IDS benchmarks.

### Datasets

| Dataset | Size | Records | Attack Categories |
|---------|------|---------|-------------------|
| NSL-KDD | 22 MB CSV | 125,973 | DoS, Probe, R2L, U2R, Normal |
| UNSW-NB15 | 183 MB parquet | 2,059,415 | Fuzzers, Exploits, Generic, Reconnaissance, DoS, Analysis, Backdoor, Shellcode, Worms, Normal |

### Benchmark Results (auto-calibrated threshold)

| Dataset | Threshold | Accuracy | Precision | Recall | F1 |
|---------|-----------|----------|-----------|--------|----|
| NSL-KDD | 0.900 | 86.6% | 80.3% | 95.6% | **0.873** |
| UNSW-NB15 | 0.963 | 91.9% | 28.0% | 43.8% | **0.341** |

NSL-KDD: DoS detection 96%, Probe 98%, U2R 100%. UNSW-NB15 lower F1 is expected for unsupervised detection on a dataset with only ~5% attack traffic.

### CLI commands

```bash
cd backend

# Download datasets to cache/
python3 -m app.datasets download

# Train + evaluate both, print metrics
python3 -m app.datasets benchmark

# Check cache status without downloading
python3 -m app.datasets status
```

### Dataset Replay Engine

Stream real labeled records through the live ingestion pipeline:

```bash
# Via API (backend must be running)
curl -X POST "http://localhost:8000/api/v1/datasets/nsl_kdd/replay/start?events_per_second=5&sample_size=1000"

# Stop replay, return to synthetic stream
curl -X POST "http://localhost:8000/api/v1/datasets/replay/stop"

# Replay status
curl http://localhost:8000/api/v1/datasets/replay/status
```

Or use the **Data Source selector** in the dashboard (top-right panel) to switch between Synthetic / NSL-KDD / UNSW-NB15 with a single click.

## Project Structure

```
threatvision/
├── backend/
│   ├── app/
│   │   ├── agents/          # AI agents (red, blue, playbook, simulation engine)
│   │   ├── api/             # FastAPI routers (11 modules + datasets)
│   │   ├── data/            # Synthetic event generator + seed scripts
│   │   ├── datasets/        # Real dataset ML pipeline
│   │   │   ├── registry.py      # Dataset definitions (NSL-KDD, UNSW-NB15)
│   │   │   ├── downloader.py    # Async HTTP download with progress + fallbacks
│   │   │   ├── loaders.py       # CSV/parquet loaders with schema normalisation
│   │   │   ├── feature_extractor.py  # Maps dataset columns → 8 IF features
│   │   │   ├── benchmark.py     # Train + auto-calibrate threshold + evaluate
│   │   │   ├── replay.py        # Stream dataset records as live events
│   │   │   └── __main__.py      # CLI: download / train / benchmark / status
│   │   ├── detection/       # ThreatClassifier (9-step pipeline, 12 rules)
│   │   ├── ingestion/       # Event normalizer + Redis XADD/XREADGROUP consumer
│   │   ├── middleware/      # Audit middleware
│   │   ├── models/          # SQLAlchemy ORM models
│   │   ├── schemas/         # Pydantic schemas
│   │   ├── services/        # Analyst, ticket, SLA, audit services
│   │   ├── websocket/       # WebSocket connection manager
│   │   └── main.py          # FastAPI entrypoint + lifespan
│   ├── tests/
│   ├── Dockerfile
│   └── pyproject.toml
├── frontend/
│   ├── src/
│   │   ├── app/             # Next.js App Router pages (dashboard, analysts, tickets, logs)
│   │   ├── components/
│   │   │   └── dashboard/   # SOC UI components
│   │   │       ├── DatasetSelector.tsx   # Data source switcher (Synthetic/NSL-KDD/UNSW)
│   │   │       ├── MetricDetailModal.tsx # Metric drill-down with benchmark card
│   │   │       ├── SimulationPanel.tsx
│   │   │       ├── IncidentFeed.tsx
│   │   │       └── ...
│   │   ├── lib/             # API client, WebSocket, Zustand store
│   │   └── types/           # TypeScript interfaces
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml
├── start-demo.sh            # One-command demo launcher
├── .env.example
├── Makefile
└── README.md
```

## API Reference

### Core

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| WS | `/ws` | Real-time event stream |

### Threats & Incidents

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/incidents` | List incidents |
| POST | `/api/v1/incidents` | Create incident |
| GET | `/api/v1/threats` | List threat events |
| POST | `/api/v1/ingestion/ingest` | Ingest raw event |
| GET | `/api/v1/alerts` | List alerts |
| GET | `/api/v1/dashboard/metrics` | SOC metrics |

### AI & Simulation

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/simulation/run` | Start Red vs Blue simulation |
| GET | `/api/v1/playbooks` | List generated playbooks |
| POST | `/api/v1/playbooks/generate` | Generate IR playbook via Claude |

### Analyst & Ticket System

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/analysts` | List analysts + workload |
| GET | `/api/v1/analysts/leaderboard` | Performance leaderboard |
| GET | `/api/v1/tickets` | List tickets with SLA status |
| PATCH | `/api/v1/tickets/{id}/resolve` | Resolve ticket |
| GET | `/api/v1/projects` | List projects + security score |

### Dataset ML

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/datasets/` | List datasets with cache/train/benchmark status |
| GET | `/api/v1/datasets/benchmarks/summary` | Latest benchmark results (dashboard card) |
| GET | `/api/v1/datasets/replay/status` | Replay engine status + stats |
| POST | `/api/v1/datasets/replay/stop` | Stop active replay |
| POST | `/api/v1/datasets/{id}/download` | Download dataset to cache |
| POST | `/api/v1/datasets/{id}/train` | Train IsolationForest on dataset |
| POST | `/api/v1/datasets/{id}/benchmark` | Evaluate trained detector on labeled data |
| POST | `/api/v1/datasets/{id}/replay/start` | Start streaming dataset as live events |
| GET | `/api/v1/datasets/{id}/status` | Single dataset status |

### Audit

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/audit` | Query hash-chained audit log |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Anthropic API key (optional — agents have fallbacks) | — |
| `POSTGRES_URL` | Async PostgreSQL connection URL | `postgresql+asyncpg://...` |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `CHROMA_HOST` | ChromaDB hostname | `localhost` |
| `NEXT_PUBLIC_API_URL` | Frontend → Backend HTTP URL | `http://localhost:8000` |
| `NEXT_PUBLIC_WS_URL` | Frontend → Backend WebSocket URL | `ws://localhost:8000/ws` |

## Testing

```bash
# Fast (no services required)
cd backend && pytest tests/test_detection.py tests/test_agents.py -v

# All tests (requires PostgreSQL + Redis)
cd backend && pytest tests/ -v

# Skip tests requiring Anthropic API key
cd backend && pytest tests/ -v -m "not slow"
```

Current: **15 passed, 4 skipped** (API key tests skipped when `ANTHROPIC_API_KEY` is absent).
