# 🛡️ Phase 1 — CVE Forecasting: Short Technical Documentation

---

## Problem Statement

Cybersecurity today is fundamentally **reactive** — organizations detect and respond to attacks only after they happen. There is no systematic, data-driven way to predict *how many* vulnerabilities will emerge, *which attack types* will surge, or *which vendors* will be most affected in the coming weeks or months.

This project addresses that gap by building a **proactive forecasting framework** using the official CVE database. The goal of Phase 1 is to establish a baseline: train and compare multiple machine learning models to forecast daily CVE publication volumes, and identify which approach best captures real-world vulnerability trends.

---

## Dataset

| Property | Detail |
|---|---|
| **Source** | [`cvelistV5`](https://github.com/CVEProject/cvelistV5) — Official CVE Program GitHub repository |
| **Total Records** | 335,550+ CVE JSON files |
| **Phase 1 Subset** | 84,936 published CVEs (2024–2026) |
| **Format** | JSON → parsed → flat CSV → daily time-series |
| **Update Frequency** | Every ~7 minutes (live database) |

**Fields extracted per record:** `cve_id`, `date_published`, `cwe_id`, `base_score`, `base_severity`, `attack_vector`, `attack_complexity`, `vendor`, `product`

A custom **CWE → Attack Category** mapping is applied during parsing to convert 90+ raw CWE IDs into 20+ human-readable categories (e.g., XSS, SQL Injection, Buffer Overflow, DoS, Path Traversal, etc.).

---

## Approach & Pipeline

The script runs **14 sequential steps**:

**Step 1 — Parse:** All CVE JSON files are read one by one. Only records with `state = PUBLISHED` are kept. Each record is mapped to an attack category via the CWE dictionary and key CVSS fields are extracted.

**Step 2 — EDA:** Exploratory visualizations — top 10 attack categories, CVSS severity breakdown (Low / Medium / High / Critical), and top 10 most affected vendors.

**Step 3 — Time-Series Conversion:** CVEs are grouped by `date_published` to create a daily count series. Ten features are then engineered:

| Feature | Description |
|---|---|
| `day_of_week` | 0 = Monday, 6 = Sunday |
| `month` | 1–12 |
| `day_of_year` | 1–365 |
| `week_of_year` | ISO week number |
| `is_weekend` | Binary flag |
| `quarter` | Q1–Q4 |
| `rolling_7d_mean` | 7-day moving average |
| `rolling_14d_mean` | 14-day moving average |
| `lag_1` | Yesterday's CVE count |
| `lag_7` | CVE count from 7 days ago |

**Step 4 — Stationarity Test:** ADF test + ACF/PACF plots on the most recent 3 years of data to check if differencing is needed for ARIMA.

**Step 5 — Train/Test Split:** 80/20 chronological split — no shuffling, temporal order preserved.

**Steps 6–10 — Model Training (5 models):**

| # | Model | Config | MAE | RMSE |
|---|---|---|---|---|
| 1 | ARIMA(5,1,0) | AR=5, d=1, MA=0 | 76.18 | 96.84 |
| 2 | **Random Forest** | 200 trees, depth=10 | **49.69** | **69.51** ✅ |
| 3 | XGBoost | 300 trees, lr=0.05 | 54.69 | 74.64 |
| 4 | SVR (RBF) | C=100, ε=0.5 | 47.98 | 73.51 |
| 5 | LSTM | 2-layer (64→32), 14-day lookback | 58.90 | 80.80 |

**Step 11 — Comparison Dashboard:** 5-panel visual — all model forecasts vs actual, MAE/RMSE bar charts, residual distribution, and actual vs predicted scatter.

**Step 12 — 30-Day Forecast:** Random Forest is used to predict the next 30 days of CVE publications, with a ±15% confidence band.

**Step 13 — Attack Category Trends:** Monthly CVE breakdown by top 6 attack categories, shown as stacked area + line plots.

**Step 14 — Save Outputs:** All results written to `model_results.csv` and `daily_cve_timeseries.csv`.

---

## Key Findings

- **Random Forest is the best model** (RMSE = 69.51) — ensemble methods handle the high variance in real daily CVE counts better than statistical or deep learning models at this stage.
- **Lag features dominate importance** — `rolling_7d_mean` and `lag_1` are the top predictors across both RF and XGBoost.
- **Weekend effect is real** — noticeably fewer CVEs are published on Saturdays and Sundays.
- **ARIMA performs worst** — real CVE data has non-stationary trends and sharp spikes that a pure statistical model cannot capture.
- **LSTM underperforms here** — Phase 1 LSTM is univariate (uses only CVE count). Adding all 10 features in Phase 2 is expected to improve it significantly.

---

## Outputs Generated

| File | Description |
|---|---|
| `01_eda_overview.png` | Attack categories, severity, vendors |
| `02_timeseries.png` | Daily CVE series + rolling averages |
| `03_acf_pacf.png` | Autocorrelation plots |
| `04_train_test_split.png` | Train/test split visualization |
| `05_arima.png` | ARIMA forecast vs actual |
| `06_random_forest.png` | RF forecast + feature importance |
| `07_xgboost.png` | XGBoost forecast + feature importance |
| `08_svr.png` | SVR forecast vs actual |
| `09_lstm.png` | LSTM training loss + forecast |
| `10_dashboard.png` | Full model comparison dashboard |
| `11_30day_forecast.png` | 30-day future forecast |
| `12_category_trends.png` | Attack category trend analysis |
| `model_results.csv` | MAE / RMSE / MAPE for all models |
| `daily_cve_timeseries.csv` | Processed daily CVE time-series |

---

## How to Run (VS Code)

### Prerequisites

Make sure you have **Python 3.9+** installed. Then install dependencies:

```bash
pip install numpy pandas matplotlib seaborn scikit-learn xgboost statsmodels tensorflow
```

### Step 1 — Get the CVE Data

Clone the official CVE repository (large download, ~2–3 GB):

```bash
git clone https://github.com/CVEProject/cvelistV5.git
```

Or download a snapshot ZIP from the repository's releases page.

### Step 2 — Update Paths in the Script

Open `phase1_real_baseline.py` and update these two lines at the top:

```python
CVE_BASE_DIR = Path(r'D:\CyberSec\cvelistV5\cves')   # ← path to your cloned cves/ folder
OUTPUT_DIR   = Path(r'D:\CyberSec\baseline_outputs')  # ← where plots and CSVs will be saved
```

Change both to match where you placed the cloned data on your machine.

### Step 3 — Run the Script

Open the folder in VS Code, open a terminal, and run:

```bash
python phase1_real_baseline.py
```

**First run** will parse all ~335K JSON files and cache the result to `cve_parsed.csv` (takes ~5–15 minutes depending on your machine). Every subsequent run loads from cache instantly and skips parsing.

### Step 4 — View Outputs

All plots and CSVs will be saved to your `OUTPUT_DIR` folder automatically.

---

## Will This Run on Google Colab?

**Partially — with workarounds.**

| Part | Colab Status | Notes |
|---|---|---|
| Step 1 — JSON Parsing | ⚠️ Not directly | Script reads from a local Windows path; Colab has no access to your drive |
| Steps 2–14 — Everything else | ✅ Works well | Once the CSV cache is available |
| LSTM training | ✅ Faster on Colab | Enable GPU runtime for speedup |

**Recommended Colab workflow:**

1. Run Step 1 **locally** (or on VS Code) once to generate `cve_parsed.csv`
2. Upload `cve_parsed.csv` to your Google Drive
3. In Colab, mount Drive and update `csv_cache` to point to the uploaded file — the script will skip parsing and load from cache directly
4. Run Steps 2–14 normally in Colab

This is a realistic and practical approach. Trying to clone and parse the full 335K-file repository inside Colab will likely hit memory limits or session timeouts.

---

## What's Next

| Phase | Focus |
|---|---|
| ✅ Phase 1 | Baseline — 5 models on real CVE data |
| 🔜 Phase 2 | Deep Learning — Full-feature LSTM, BiLSTM, Transformer |
| 🔜 Phase 3 | Graph Neural Network — B-MTGNN with Bayesian uncertainty |
| 🔜 Phase 4 | Threat-Defense Gap Forecasting + Power BI Dashboard |