# CyberForesight — Session Context

## What this project is

B-MTGNN (Bayesian Multi-variate Temporal Graph Neural Network) that forecasts **research publication volume** (papers/month from Elsevier Scopus) for 26 cyber threat and defense technology topics. It does NOT predict real-world attacks — NVD CVEs are used as an input feature, not the output.

Training data: July 2011 – December 2022. Forecast horizon: up to 12 months ahead.

## Repo

GitHub: `https://github.com/reesick/cybersec-ind` (branch: `main`)

## Stack

- **ML pipeline**: Python — `torch`, `torch-geometric`, `statsmodels`, `scikit-learn`
- **API**: FastAPI + uvicorn (`api/`)
- **Frontend**: React 18 + TypeScript + Vite + TailwindCSS + Recharts + react-force-graph-2d (`frontend/`)
- **Data fetching**: TanStack React Query

## Project layout

```
api/
  main.py              # FastAPI app — serves API + React SPA (catch-all)
  routers/
    forecast.py        # GET /api/forecast/nodes, /api/forecast/, /api/forecast/summary
    gap.py             # GET /api/gap/, /api/gap/categories, /api/gap/top
    graph.py           # GET /api/graph/  (normalises edges→links for react-force-graph-2d)
    metrics.py         # GET /api/metrics/validation, /ablation, /atc
    pipeline.py        # POST /api/pipeline/run, WS /api/pipeline/logs
  services/
    data_loader.py     # lru_cache loaders for all CSVs/JSONs in outputs/ and data/

frontend/src/
  App.tsx              # React Router routes
  pages/
    Overview.tsx       # KPI cards + top-threats bar chart + model metric cards
    Forecast.tsx       # Node selector + line chart with CI band
    GapAnalysis.tsx    # Colour-coded gap table (ONG/OWG/SNG/SWG)
    ThreatGraph.tsx    # Force-directed graph (red=threats, blue=defense)
    ModelMetrics.tsx   # Validation, ablation, ATC metric cards
    ATC.tsx            # Technology Lifecycle page
    TrendGallery.tsx   # Grid of 26 trend PNGs with lightbox
  components/
    Hint.tsx           # Blue info box for plain-English chart explanations
    layout/
      Layout.tsx
      Sidebar.tsx

data/
  graph/tpt_graph.json      # Threat-protection topology graph
  processed/monthly_dataset.csv
  raw/                      # Elsevier .pkl cache files (one per topic)

outputs/
  forecast_results.csv
  gap_analysis.csv
  model_metrics.csv
  ablation_results.csv
  atc_scores.csv
  trend_plots/              # 26 PNG trend charts
```

## Dev / local run

```bash
# Backend
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev          # http://localhost:5173
```

Vite proxies `/api/*` → `localhost:8000` (no rewrite — same paths as production).

## Deployment

**Platform**: Railway (moved away from Render — see history below)

**Build command** (set in Railway dashboard):
```
pip install -r requirements.txt && npm --prefix frontend install && npm --prefix frontend run build
```

**Start command**:
```
uvicorn api.main:app --host 0.0.0.0 --port $PORT
```

FastAPI serves the React `frontend/dist/` as a SPA (catch-all route in `api/main.py`).

### Why Railway instead of Render

Render sets `NODE_ENV=production` during builds, which causes `npm install` to skip `devDependencies`. This broke the TypeScript/Vite build repeatedly. Railway does not have this issue.

### Key package.json decisions

- `vite` and `@vitejs/plugin-react` are in **`dependencies`** (not devDependencies) so they survive a production `npm install`
- Build script is `"build": "vite build"` (no `tsc` step) — Vite uses esbuild internally and doesn't need `@types/react` to compile

## Known quirks / past fixes

| Issue | Fix |
|---|---|
| Threat graph blank | `tpt_graph.json` uses `"edges"` key; `react-force-graph-2d` needs `"links"`. `graph.py` normalises this. Also stripped per-month `weights` arrays (were ~2 MB per edge). |
| Tooltip text black in Overview/ModelMetrics | Added `itemStyle={{ color: "#94a3b8" }}` to Recharts `<Tooltip>` |
| Gap category codes confusing | Mapped: ONG=Ongoing, OWG=Growing/Widening, SNG=Balanced/No Gap, SWG=Critical/Significant Widening |

## Gap category codes

| Code | Meaning | Color |
|---|---|---|
| ONG | Ongoing — small stable gap | yellow |
| OWG | Growing/Widening — threat outpacing defense | red |
| SNG | Balanced — no significant gap | green |
| SWG | Critical/Significant Widening — large accelerating gap | dark red |

## What the model does NOT do (decided against)

- Real-world attack frequency prediction — would need CISA KEV (only 13 months of history before training cutoff, insufficient)
- Live threat feed integration — same reason

## Config

`config.yaml` — public config (API keys placeholders, data paths)
`config.local.yaml` — secrets (gitignored). Template at `config.local.yaml.example`
