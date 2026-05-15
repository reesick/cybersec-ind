# CyberForesight — Project Report

**Date:** May 2026  
**Repository:** `https://github.com/reesick/cybersec-ind` (branch: `main`)  
**Model:** B-MTGNN (Bayesian Multi-variate Temporal Graph Neural Network)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement & Scope](#2-problem-statement--scope)
3. [System Architecture](#3-system-architecture)
4. [ML Pipeline](#4-ml-pipeline)
   - 4.1 [Data Collection](#41-data-collection)
   - 4.2 [Preprocessing](#42-preprocessing)
   - 4.3 [Graph Construction](#43-graph-construction)
   - 4.4 [Model Architecture](#44-model-architecture)
   - 4.5 [Training & Evaluation](#45-training--evaluation)
   - 4.6 [Forecasting & Gap Analysis](#46-forecasting--gap-analysis)
5. [API Layer](#5-api-layer)
6. [Frontend Dashboard](#6-frontend-dashboard)
7. [Configuration & Secrets](#7-configuration--secrets)
8. [Dependencies](#8-dependencies)
9. [Output Artifacts](#9-output-artifacts)
10. [Performance Results](#10-performance-results)
11. [Gap Category Framework](#11-gap-category-framework)
12. [Deployment](#12-deployment)
13. [Known Issues & Past Fixes](#13-known-issues--past-fixes)
14. [Limitations & Exclusions](#14-limitations--exclusions)

---

## 1. Executive Summary

CyberForesight is an end-to-end forecasting system that predicts **academic research publication volume** for 26 cyber threat topics and 97 defense technology topics over a 12-month horizon (and up to 36 months ahead in experiments). It does **not** predict real-world attack frequencies.

The core model — B-MTGNN — combines dilated temporal convolutions with a learned graph convolution network and Bayesian (MC-dropout) uncertainty quantification. Trained on monthly publication counts sourced from Elsevier Scopus (July 2011 – December 2022), the model achieves an R² of **0.9987** on the held-out test set.

Results are served through a FastAPI backend and visualised in a React 18 + TypeScript dashboard deployed on Railway.

**At a glance:**

| Dimension | Detail |
|---|---|
| Training window | July 2011 – December 2022 (138 months) |
| Forecast horizon | Up to 36 months (production: 2025–2027) |
| Threat topics | 26 |
| Defense technologies (PATs) | 97 |
| Total graph nodes | 123 |
| Validation R² | 0.9987 |
| Validation RMSE | ~224 papers/month |
| MC dropout iterations | 30 (for 95% CI bands) |
| Backend | FastAPI + uvicorn |
| Frontend | React 18 + Vite + TailwindCSS |
| Deployment | Railway |

---

## 2. Problem Statement & Scope

### What this system forecasts

The research community's attention (measured in monthly publication counts from Scopus) toward:

- 26 **cyber threat** topics (e.g., Ransomware, Zero-day, Phishing, APT)
- 97 **Pertinent Alleviation Technologies (PATs)** — defense mechanisms (e.g., Anomaly Detection, Access Control, Adversarial Training)

### What it does NOT do

- Predict real-world attack frequency or severity
- Ingest live threat intelligence feeds (CISA KEV had only 13 months of history before the training cutoff — insufficient for modeling)
- Forecast CVE counts (NVD CVEs are used as an **input feature**, not a target)

### Research question answered

> *Which cyber threats are receiving disproportionately less defensive research investment, and how will that gap evolve?*

This is answered through the **Gap Analysis** module, which compares normalised threat and defense publication trajectories and categorises each threat-PAT pair as ONG / OWG / SNG / SWG.

---

## 3. System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          CyberForesight                              │
│                                                                      │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────────────┐   │
│  │  Data Layer │───▶│  ML Pipeline │───▶│  Output Artifacts     │   │
│  │             │    │              │    │  (CSV, PNG, JSON, .pt) │   │
│  │ Elsevier    │    │ Preprocessing│    └───────────┬───────────┘   │
│  │ Scopus API  │    │ Graph Build  │                │               │
│  │ NVD CVE API │    │ B-MTGNN      │                ▼               │
│  │ GDELT/ACLED │    │ Forecasting  │    ┌───────────────────────┐   │
│  │ Holidays    │    │ Gap Analysis │    │  FastAPI Backend      │   │
│  └─────────────┘    └──────────────┘    │  (api/)               │   │
│                                         │  /api/forecast/       │   │
│                                         │  /api/gap/            │   │
│                                         │  /api/graph/          │   │
│                                         │  /api/metrics/        │   │
│                                         │  /api/pipeline/       │   │
│                                         └───────────┬───────────┘   │
│                                                     │               │
│                                                     ▼               │
│                                         ┌───────────────────────┐   │
│                                         │  React Frontend       │   │
│                                         │  (frontend/)          │   │
│                                         │  Overview, Forecast,  │   │
│                                         │  GapAnalysis, Graph,  │   │
│                                         │  ModelMetrics, ATC,   │   │
│                                         │  TrendGallery         │   │
│                                         └───────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

### Repository layout

```
CyberForesight/
├── api/                          # FastAPI backend
│   ├── main.py                   # App factory, CORS, static SPA serving
│   ├── routers/
│   │   ├── forecast.py
│   │   ├── gap.py
│   │   ├── graph.py
│   │   ├── metrics.py
│   │   └── pipeline.py
│   └── services/
│       └── data_loader.py        # LRU-cached CSV/JSON loaders
├── frontend/                     # React 18 + TypeScript SPA
│   ├── src/
│   │   ├── App.tsx
│   │   ├── pages/                # 7 pages
│   │   ├── components/           # Layout, Hint
│   │   └── api/client.ts         # Axios + TypeScript interfaces
│   ├── package.json
│   └── vite.config.ts
├── src/                          # ML pipeline
│   ├── constants.py              # Threat list, PAT list, mappings, countries
│   ├── utils.py
│   ├── data_collection/
│   ├── preprocessing/
│   ├── graph/
│   ├── model/
│   ├── training/
│   ├── forecasting/
│   └── visualisation/
├── data/
│   ├── processed/monthly_dataset.csv   # 138 × 1160 matrix
│   ├── graph/tpt_graph.json            # Threat-PAT topology
│   └── raw/                            # Elsevier .pkl cache (150+ files)
├── outputs/                      # All model outputs
├── run_pipeline.py               # End-to-end orchestration
├── create_stub_cache.py          # Utility: zero-fill missing cache entries
├── config.yaml                   # Public config
├── config.local.yaml.example     # Secret template (gitignored)
└── requirements.txt
```

---

## 4. ML Pipeline

### 4.1 Data Collection

Implemented in `src/data_collection/`. Five feature types are collected for each of 123 nodes across 138 months:

| Feature | Symbol | Source | Fallback |
|---|---|---|---|
| Monthly publication count (threats) | NoM_A | Elsevier Scopus API | Semantic Scholar |
| Monthly publication count (PATs) | NoM_P | Elsevier Scopus API | Semantic Scholar |
| Number of incidents (CVEs) | NoI | NVD CVE API | Hackmageddon scraper → synthetic |
| Armed conflict events | ACA | GDELT v2 / ACLED | Synthetic |
| Public holidays per country | PH | `holidays` Python library | — |

**Smart caching** (`src/data_collection/cache_manager.py`): Pickle files stored in `data/raw/`. The `reuse_recent_days` parameter (default 7) suppresses re-download of recently cached data even when `cache.refresh = true`. All collectors degrade gracefully to synthetic data when live APIs are unavailable or `use_live_apis: false`.

**`create_stub_cache.py`**: Creates zero-filled pickle stubs for any PATs missing from the cache (used when extending the date cutoff to 2026-04-01 without re-querying APIs).

Coverage: 26 threats × 36 countries + 97 PATs = 1,033 series collected and merged.

### 4.2 Preprocessing

Implemented in `src/preprocessing/`.

1. **`dataset_builder.py`** merges all collected series into a single `138 × 1160` matrix (`data/processed/monthly_dataset.csv`): 138 months × (123 nodes × ~9.4 features per node on average).
2. **`smoothing.py`** applies Double Exponential Smoothing (DES/Holt's method) to dampen noise in publication series.
3. **`wfc.py`** computes Windowed Frequency Counts — a sliding-window aggregation of incident counts per attack type per country, used as an additional feature.

### 4.3 Graph Construction

Implemented in `src/graph/`.

- **`tpt_graph.py`**: Builds the Threat-Protection Topology (TPT) graph from `THREAT_PAT_MAP` (defined in `src/constants.py`). Each threat node connects to its associated PAT nodes; PATs shared by multiple threats become hubs.
- **`adjacency.py`**: Computes static adjacency matrices for initial graph convolution.
- **`egpt.py`**: Scores temporal relationship strength between node pairs using historical correlation, producing edge weights that inform the learned adjacency.

Output: `data/graph/tpt_graph.json` — 123 nodes, weighted directed edges.

### 4.4 Model Architecture

Implemented in `src/model/`.

#### B-MTGNN (Bayesian Multi-variate Temporal GNN)

```
Input  [B, Tin=10, N=123, F]
  │
  ▼
┌──────────────────────────────────────┐
│  Temporal Convolution Block          │
│  (Dilated inception convolutions)    │
│  src/model/temporal_conv.py          │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│  Graph Learning Layer                │
│  (Adaptive adjacency matrix)         │
│  src/model/graph_learning.py         │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│  Graph Convolution Block             │
│  (MixHop GCN, depth=2)               │
│  src/model/graph_conv.py             │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│  MC Dropout (p=0.4, 30 iterations)   │  ← Bayesian uncertainty
│  src/model/b_mtgnn.py                │
└──────────────────┬───────────────────┘
                   │
                   ▼
Output [B, Tout=36, N=123]  (mean + std → 95% CI)
```

**Key design choices:**

- **Dilated inception convolutions**: capture multi-scale temporal patterns at varying receptive field sizes without inflating parameter count.
- **Learned adaptive adjacency**: the graph topology is not fixed — a learnable embedding layer produces a soft adjacency that is refined during training, allowing the model to discover implicit threat-PAT relationships beyond the hard-coded `THREAT_PAT_MAP`.
- **MixHop GCN**: aggregates features from 1-hop and 2-hop neighbours simultaneously, improving information propagation on sparse graphs.
- **MC dropout for Bayesian inference**: dropout is kept active at inference time; 30 forward passes produce a distribution over predictions. Mean = point estimate; 1.96 × std = 95% CI half-width.

**Hyperparameters (production):**

| Parameter | Value |
|---|---|
| Input window (`tin`) | 10 months |
| Output horizon (`tout`) | 36 months |
| Dropout rate | 0.4 |
| Learning rate | 0.001 |
| Epochs | 80 |
| Graph K neighbours | 12 |
| GCN depth | 2 |
| Conv channels | 16 |
| Alpha (graph learning) | 1.5 |
| Beta (regularisation) | 0.2 |
| MC iterations | 30 |

### 4.5 Training & Evaluation

Implemented in `src/training/`.

**Data splits** (temporal, no shuffling):

| Split | Proportion | Purpose |
|---|---|---|
| Train | 43% (~59 months) | Model fitting |
| Validation | 30% (~41 months) | Early stopping / HP search |
| Test | 27% (~37 months) | Final evaluation |

**Windowing**: overlapping sliding windows (stride = 1 month) generate training samples from the training set.

**Hyperparameter search** (`src/training/hyperparam_search.py`): 20-iteration random search over:
- Learning rate: [0.0001, 0.01]
- Dropout: [0.2, 0.7]
- Conv channels: {8, 12, 16}
- GCN depth: {1, 2, 3}

Best checkpoint saved to `outputs/b_mtgnn_best.pt`; search checkpoints to `outputs/trial_*.pt`.

**Metrics** (`src/training/evaluation.py`):

| Metric | Formula | Interpretation |
|---|---|---|
| RSE | `‖ŷ − y‖₂ / ‖y − ȳ‖₂` | Relative Squared Error vs. naive mean |
| RAE | `‖ŷ − y‖₁ / ‖y − ȳ‖₁` | Relative Absolute Error vs. naive mean |
| RMSE | `√mean((ŷ − y)²)` | Root Mean Squared Error (papers/month) |
| R² | `1 − SSres/SStot` | Variance explained |

**Ablation study** (`src/training/ablation.py`): 10 model variants compared — temporal-only (TCN), graph-only, no adaptive adjacency, no Bayesian layer, various backbone simplifications, plus Linear Regression and naive mean baselines.

### 4.6 Forecasting & Gap Analysis

Implemented in `src/forecasting/`.

**`forecast.py`**: Rolls the trained model forward from the last training timestamp through 2027-12-01, running 30 MC dropout passes per step. Outputs mean prediction and 95% CI bounds per node per month → `outputs/forecast_2025_2027.csv`.

**`gap_analysis.py`**: For each threat-PAT pair in `THREAT_PAT_MAP`:
1. Normalise both time series (min-max, 0–1).
2. Compute `gap = threat_norm − pat_norm`.
3. Classify by current gap magnitude and trend direction → ONG / OWG / SNG / SWG.
4. Write `outputs/gap_analysis_report.csv`.

**`recommendations.py`**: Ranks threat-PAT pairs by gap magnitude and generates a Top-20 investment priorities table → `outputs/investment_recommendations.pdf`.

---

## 5. API Layer

Implemented in `api/`. FastAPI application with uvicorn, serving both the JSON API and the React SPA (production catch-all).

### Endpoints

#### `GET /api/forecast/nodes`
Returns list of all 123 node IDs (threats + PATs).

#### `GET /api/forecast/`
Query params: `node` (optional), `year` (optional, comma-separated).  
Returns: forecast rows with columns `node_id`, `date`, `predicted`, `ci_lower`, `ci_upper`.

#### `GET /api/forecast/summary`
Per-node summary: `avg_predicted`, `avg_uncertainty`, `max_predicted`.

#### `GET /api/gap/`
Query params: `category` (ONG/OWG/SNG/SWG), `sort_by`, `limit` (default 200).  
Returns: gap rows with `threat`, `pat`, `gap_score`, `category`, `year`.

#### `GET /api/gap/categories`
Returns list of distinct category codes present in the data.

#### `GET /api/gap/top`
Query param: `n` (default 10). Returns top N gaps by magnitude.

#### `GET /api/graph/`
Returns the full threat-PAT graph as `{ nodes: [...], links: [...] }` — normalised from `tpt_graph.json` (`edges` → `links`, per-month weight arrays stripped).

#### `GET /api/graph/node/{node_id}`
Returns immediate neighbours of a given node.

#### `GET /api/metrics/validation`
Returns RSE, RAE, RMSE, R² from `outputs/validation_metrics.csv`.

#### `GET /api/metrics/ablation`
Returns all ablation study rows.

#### `GET /api/metrics/atc`
Returns Alleviation Technologies Cycle phase data.

#### `POST /api/pipeline/run`
Triggers the full pipeline (data collection → training → forecasting). Returns run ID.

#### `GET /api/pipeline/status`
Returns current pipeline run status.

#### `WS /api/pipeline/logs`
WebSocket streaming of live pipeline logs.

### Data Loader (`api/services/data_loader.py`)

All loaders are decorated with `@lru_cache` so CSV/JSON files are read once per process lifetime, keeping API latency low.

---

## 6. Frontend Dashboard

**Stack:** React 18 + TypeScript · Vite 5 · TailwindCSS 3.4 · Recharts 2 · react-force-graph-2d · TanStack React Query · React Router 6 · Lucide React

### Pages

#### Overview (`pages/Overview.tsx`)
- KPI cards: threats tracked (26), PATs tracked (97), R² (0.9987), RMSE
- Top-8 threats bar chart: average predicted papers/month across forecast window
- Validation metric cards with plain-English explanations
- `Hint` component explains what "publications/month" measures

#### Forecast (`pages/Forecast.tsx`)
- Searchable node selector sidebar (threats + PATs grouped)
- Area chart: predicted line + shaded 95% CI band
- Year-filter toggle buttons (2025 / 2026 / 2027)
- Custom tooltip displaying date, prediction, CI lower/upper

#### Gap Analysis (`pages/GapAnalysis.tsx`)
- Category legend (ONG=yellow, OWG=orange, SNG=green, SWG=red/dark)
- Filter by category + sort controls
- Colour-coded table: cell background scales from red (large deficit) to green (defense ahead)
- Up to 200 rows; sortable by gap magnitude or year

#### Threat Graph (`pages/ThreatGraph.tsx`)
- `react-force-graph-2d` canvas rendering
- Red nodes = threats, blue nodes = PATs, edges = THREAT_PAT_MAP relationships
- Click node → side panel: full name, description, connected nodes list
- Labels rendered on canvas at zoom ≥ 1.5
- Legend: node counts and edge count

#### Model Metrics (`pages/ModelMetrics.tsx`)
- Validation KPI cards (RSE, RAE, RMSE, R²) with explanations
- Ablation bar chart: RSE across 10 model variants + 2 baselines
  - Green bar = full B-MTGNN; blue = partial variants; grey = baselines
- Full ablation results table

#### ATC — Alleviation Technologies Cycle (`pages/ATC.tsx`)
- Displays lifecycle phases (Growth → Maturity → Trough) for each PAT
- Classification based on slope of forecast trajectory
- Intended to guide technology investment timing

#### Trend Gallery (`pages/TrendGallery.tsx`)
- 4-column responsive grid of 26 threat PNG charts (from `outputs/trend_plots/`)
- Click to open lightbox zoom

### Shared Components

- **`Layout.tsx`** — sidebar + main content area wrapper
- **`Sidebar.tsx`** — navigation links + branding
- **`Hint.tsx`** — styled blue info box for plain-English chart explanations

### Data Fetching

TanStack React Query (`@tanstack/react-query`) with `axios` client (`src/api/client.ts`). All queries use standard staleTime / cacheTime defaults. TypeScript interfaces define shapes for every API response.

In development, Vite proxies `/api/*` → `localhost:8000` (identical path — no rewrite needed, matching production routing).

---

## 7. Configuration & Secrets

### `config.yaml` (public, committed)

```yaml
project:
  seed: 42
  start_date: "2011-07-01"
  end_date: "2026-04-01"
  forecast_start: "2025-01-01"
  forecast_end: "2027-12-01"
  data_dir: "data"
  output_dir: "outputs"

api:
  use_live_apis: true

apis:
  elsevier:   { enabled: true,  rate_limit_sleep: 0.2 }
  semantic_scholar: { enabled: true, rate_limit_sleep: 3.0 }
  acled:      { enabled: true }
  nvd:        { enabled: true,  rate_limit_sleep: 0.6 }
  hackmageddon: { enabled: true }

cache:
  enabled: true
  refresh: false
  reuse_recent_days: 7
  path: "data/raw/"

model:
  tin: 10
  tout: 36
  dropout: 0.4
  lr: 0.001
  epochs: 80
  graph_k: 12
  gcn_depth: 2
  conv_channels: 16
  alpha: 1.5
  beta: 0.2
  mc_iterations: 30

search:
  random_iterations: 20
  lr_range: [0.0001, 0.01]
  dropout_range: [0.2, 0.7]
  conv_channels: [8, 12, 16]
  gcn_depth: [1, 2, 3]
```

### `config.local.yaml` (gitignored secrets)

Contains: Elsevier API key, NVD API key, ACLED credentials, Twitter Bearer token. Template at `config.local.yaml.example`.

---

## 8. Dependencies

### Python (`requirements.txt`)

| Category | Packages |
|---|---|
| Deep learning | `torch`, `torch-geometric` |
| Data / ML | `numpy`, `pandas`, `scipy`, `scikit-learn`, `statsmodels` |
| Visualisation | `matplotlib`, `seaborn`, `plotly`, `networkx` |
| Data collection | `requests`, `tweepy`, `openai`, `semanticscholar`, `beautifulsoup4`, `thefuzz`, `holidays`, `tqdm` |
| Config / utils | `pyyaml`, `python-dotenv` |
| API server | `fastapi>=0.110.0`, `uvicorn[standard]>=0.29.0`, `aiofiles>=23.2.1` |

### Frontend (`frontend/package.json`)

| Package | Version | Notes |
|---|---|---|
| `react` + `react-dom` | ^18.2.0 | |
| `react-router-dom` | ^6.22.3 | |
| `@tanstack/react-query` | ^5.28.0 | |
| `recharts` | ^2.12.2 | |
| `react-force-graph-2d` | ^1.25.5 | |
| `axios` | ^1.6.8 | |
| `lucide-react` | ^0.363.0 | |
| `vite` | ^5.2.0 | In **dependencies** (not devDependencies) |
| `@vitejs/plugin-react` | ^4.2.1 | In **dependencies** (not devDependencies) |

> **Note:** `vite` and `@vitejs/plugin-react` are deliberately in `dependencies`, not `devDependencies`. This is required for Railway's production `npm install` to include them at build time. The build script is `"build": "vite build"` (no `tsc` step — Vite uses esbuild internally).

---

## 9. Output Artifacts

All generated by `run_pipeline.py`:

| File | Description |
|---|---|
| `outputs/b_mtgnn_best.pt` | Best model checkpoint (PyTorch state dict) |
| `outputs/trial_0.pt` – `trial_19.pt` | Hyperparameter search checkpoints |
| `outputs/forecast_2025_2027.csv` | 123 nodes × 36 months: `date`, `node_id`, `predicted`, `ci_lower`, `ci_upper` |
| `outputs/gap_analysis_report.csv` | Threat-PAT pairs: `threat`, `pat`, `gap_score`, `category`, `year` |
| `outputs/validation_metrics.csv` | Single row: RSE, RAE, RMSE, R² |
| `outputs/ablation_and_baselines.csv` | 10 variants + 2 baselines: RSE, RAE |
| `outputs/atc_phases.csv` | PAT lifecycle phases |
| `outputs/investment_recommendations.pdf` | Top-20 gaps by magnitude |
| `outputs/trend_plots/*.png` | 26 PNG trend charts (one per threat) |
| `outputs/atc_diagram.png` | Alleviation Technologies Cycle visualisation |
| `data/processed/monthly_dataset.csv` | 138 rows × 1160 columns (full feature matrix) |
| `data/graph/tpt_graph.json` | 123-node threat-PAT topology graph |
| `data/raw/elsevier_*.pkl` | Cached Scopus API responses (150+ files) |

---

## 10. Performance Results

### Validation Metrics (held-out test set)

| Metric | Value | Interpretation |
|---|---|---|
| **R²** | **0.9987** | 99.87% of variance explained — near-perfect fit |
| **RSE** | **0.035** | 96.5% lower error than naive mean predictor |
| **RAE** | **0.029** | 97.1% lower absolute error than naive mean |
| **RMSE** | **~224 papers/month** | Average absolute deviation in publication count |

### Ablation Study Summary

| Model Variant | RSE | Observation |
|---|---|---|
| **Full B-MTGNN** | **0.035** | Best overall |
| No Bayesian layer (fixed dropout) | ~0.042 | Slightly worse; CI bands less calibrated |
| No adaptive adjacency | ~0.080 | Large degradation — graph learning is critical |
| Graph-only (no temporal conv) | ~0.110 | Temporal component essential |
| Temporal-only (TCN, no GNN) | ~0.150 | GNN component essential |
| Linear Regression | ~0.38 | Baseline |
| Naive mean | 1.000 | Baseline (RSE denominator) |

The adaptive graph learning layer and temporal convolution blocks each independently contribute large performance gains; removing either causes substantial degradation.

---

## 11. Gap Category Framework

The gap analysis compares normalised threat publication volume vs. normalised PAT publication volume. The resulting `gap_score = threat_norm − pat_norm` is combined with trend direction to assign one of four categories:

| Code | Full Name | Color | Meaning | Priority |
|---|---|---|---|---|
| **ONG** | Ongoing | Yellow | Small, stable gap — persistent but not accelerating defense lag | Medium |
| **OWG** | Growing / Widening | Orange | Gap accelerating — threat research outpacing defense investment | High |
| **SNG** | Balanced / No Gap | Green | Defense research keeping pace with threat attention | Low |
| **SWG** | Critical / Significant Widening | Dark Red | Large, rapidly accelerating gap — highest urgency | Critical |

### Threat-PAT Coverage

**26 Cyber Threats:**
Account Hijacking, Adversarial Attack, APT, Backdoor, Botnet, Brute Force Attack, Cryptojacking, DDoS, Data Poisoning, Deepfake, Disinformation, DNS Spoofing, Dropper, Insider Threat, IoT Device Attack, Malware, MITM, Password Attack, Phishing, Ransomware, Session Hijacking, Supply Chain Attack, Targeted Attack, Trojan, Vulnerability, Zero-day

**97 PAT codes** (examples): AC (Access Control), AD (Anomaly Detection), AdT (Adversarial Training), 3DFR (3D Face Recognition), ... each mapped to 5–15 threats via `THREAT_PAT_MAP` in `src/constants.py`.

---

## 12. Deployment

### Platform: Railway

Railway was chosen over Render after Render's `NODE_ENV=production` flag during builds caused `npm install` to skip `devDependencies`, breaking the Vite/TypeScript compilation repeatedly despite multiple workarounds.

### Build command (Railway dashboard)

```bash
pip install -r requirements.txt && npm --prefix frontend install && npm --prefix frontend run build
```

### Start command (Railway dashboard)

```bash
uvicorn api.main:app --host 0.0.0.0 --port $PORT
```

`$PORT` is injected by Railway at runtime. FastAPI serves the compiled React SPA (`frontend/dist/`) via a static file mount + catch-all route for client-side navigation.

### Local development

```bash
# Terminal 1 — backend
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8000

# Terminal 2 — frontend
cd frontend
npm install
npm run dev          # http://localhost:5173
```

Vite's dev server proxies `/api/*` → `http://localhost:8000` with the same path (no rewrite), so the frontend code is identical between dev and production.

### Running the full pipeline

```bash
python run_pipeline.py
```

This executes: data collection → preprocessing → graph construction → model training → hyperparameter search → forecasting → gap analysis → visualisation. Outputs are written to `outputs/`.

---

## 13. Known Issues & Past Fixes

| Issue | Root Cause | Fix Applied |
|---|---|---|
| **Threat graph renders blank** | `tpt_graph.json` uses `"edges"` key; `react-force-graph-2d` requires `"links"` | `api/routers/graph.py` renames the key at serve time |
| **Graph API response ~2 MB** | Per-month weight arrays embedded in every edge | Stripped weight arrays in `graph.py` before serialising |
| **Tooltip text black on dark background** | Recharts default tooltip text colour | Added `itemStyle={{ color: "#94a3b8" }}` to all `<Tooltip>` components |
| **Frontend build fails on Render** | `NODE_ENV=production` skips devDependencies; Vite was in devDependencies | Moved `vite` and `@vitejs/plugin-react` to `dependencies`; switched to Railway |
| **`tsc` fails at build time** | Missing `@types/react` in production install | Removed `tsc` from build script; Vite/esbuild handles compilation without type-checking at build time |
| **Gap category codes unclear** | Raw codes ONG/OWG/SNG/SWG not self-explanatory | Frontend maps codes to full labels with colour coding |

---

## 14. Limitations & Exclusions

1. **No real-world attack prediction.** The model forecasts *research attention*, not attack frequency, severity, or likelihood. CVE counts are input features, not outputs.

2. **Static graph topology.** `THREAT_PAT_MAP` is hand-curated. New threats or PATs require a code update and re-run of the pipeline.

3. **Training cutoff: December 2022.** The model has no knowledge of post-2022 events (e.g., emergence of AI-assisted phishing at scale in 2023-2024). Predictions beyond 12–18 months should be treated with caution.

4. **Scopus-only publication source.** Non-Scopus-indexed venues (grey literature, preprints, government reports) are not captured.

5. **English-language bias.** Scopus queries are in English; research published in other languages is largely excluded.

6. **36-country ACA scope.** Armed conflict activity is tracked for 36 specific countries. Conflicts elsewhere are not represented.

7. **No online learning.** Retraining requires re-running the full pipeline. There is no mechanism for incremental model updates as new data arrives.

---

*Report generated May 2026. For questions, see CLAUDE.md or open an issue at `https://github.com/reesick/cybersec-ind`.*
