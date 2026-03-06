# 🛡️ Phase 1 — CVE Forecasting: Technical Documentation

---

## Problem Statement

Cybersecurity today is fundamentally **reactive** — organizations detect and respond to attacks only after they happen. There is no systematic, data-driven way to predict how many vulnerabilities will emerge, which attack types will surge, or which vendors will be most affected in the coming weeks or months.

This project builds a **proactive forecasting framework** using the official CVE database. Phase 1 establishes the baseline: train and compare five machine learning models to forecast daily CVE publication volumes, and identify which approach best captures real-world vulnerability trends.

---

## Data Structure

**Source:** `cvelistV5` — Official CVE Program GitHub repository
335,550+ JSON files, one per CVE record, organized as:

```
cvelistV5/
└── cves/
    ├── 1999/
    │   └── 0001xx/
    │       ├── CVE-1999-0001.json
    │       └── ...
    ├── 2024/
    └── 2025/
```

Each JSON file follows **CVE Record Format v5** and contains:

```json
{
  "cveMetadata": {
    "cveId": "CVE-2024-12345",
    "state": "PUBLISHED",
    "datePublished": "2024-03-15T10:00:00Z"
  },
  "containers": {
    "cna": {
      "problemTypes": [{ "descriptions": [{ "cweId": "CWE-79" }] }],
      "metrics": [{ "cvssV3_1": { "baseScore": 7.5, "baseSeverity": "HIGH", "attackVector": "NETWORK" } }],
      "affected": [{ "vendor": "example_corp", "product": "example_product" }]
    }
  }
}
```

**Fields extracted per record:**

| Field | Description |
|---|---|
| `cve_id` | Unique identifier (e.g., CVE-2024-12345) |
| `date_published` | Publication timestamp → primary time axis |
| `cwe_id` | Weakness type (e.g., CWE-79) |
| `attack_category` | Human-readable category mapped from CWE |
| `base_score` | CVSS numerical score (0–10) |
| `base_severity` | LOW / MEDIUM / HIGH / CRITICAL |
| `attack_vector` | NETWORK / LOCAL / ADJACENT / PHYSICAL |
| `vendor` | Affected technology vendor |
| `product` | Affected product name |

**CWE → Attack Category Mapping:** 90+ raw CWE IDs are mapped to 20+ readable categories during parsing:

| CWE IDs | Attack Category |
|---|---|
| CWE-79, CWE-80 | XSS |
| CWE-89, CWE-564 | SQL Injection |
| CWE-78, CWE-77 | OS / Command Injection |
| CWE-787, CWE-125 | Out-of-Bounds Write / Read |
| CWE-416 | Use After Free |
| CWE-287, CWE-306 | Authentication Bypass |
| CWE-22, CWE-23 | Path Traversal |
| CWE-352 | CSRF |
| CWE-918 | SSRF |
| CWE-400, CWE-770 | DoS |

After parsing, records are aggregated into a **daily time-series** (CVE count per day), which is the primary input for all models.

---

## Methodology

### Overall Flow

```
Raw CVE JSONs → Parse & Map CWEs → Daily Time-Series → Feature Engineering
      → Stationarity Check → Train/Test Split → 5 Models → Compare → Forecast
```

### Feature Engineering

10 features are derived from the date index of the daily series:

| Feature | Type | Description |
|---|---|---|
| `day_of_week` | Temporal | 0 = Monday, 6 = Sunday |
| `month` | Temporal | 1–12 |
| `day_of_year` | Temporal | 1–365 |
| `week_of_year` | Temporal | ISO week number |
| `is_weekend` | Binary | 1 if Saturday/Sunday |
| `quarter` | Temporal | Q1–Q4 |
| `rolling_7d_mean` | Lag | 7-day moving average of CVE count |
| `rolling_14d_mean` | Lag | 14-day moving average of CVE count |
| `lag_1` | Lag | Yesterday's CVE count |
| `lag_7` | Lag | CVE count from 7 days ago |

### Train / Test Split

- Data window: most recent **3 years** of daily CVE counts
- Split: **80% train / 20% test**, chronological (no shuffling)
- Stationarity: ADF test run before ARIMA to verify if differencing is required

### Models

| Model | Category | Key Config |
|---|---|---|
| ARIMA(5,1,0) | Statistical | Univariate — uses only the raw CVE count series |
| Random Forest | Ensemble ML | 200 trees, max depth=10, all 10 features |
| XGBoost | Gradient Boosting | 300 trees, lr=0.05, all 10 features |
| SVR (RBF) | Kernel ML | C=100, ε=0.5, features MinMax scaled |
| LSTM | Deep Learning | 2-layer (64→32 units), 14-day lookback, univariate |

> ARIMA and LSTM are **univariate** in Phase 1 — they see only raw CVE counts. RF, XGBoost, and SVR use all 10 engineered features. Phase 2 will make LSTM multivariate.

### Evaluation Metrics

- **MAE** — Mean Absolute Error (average error in CVE count units)
- **RMSE** — Root Mean Squared Error (primary ranking metric; penalizes large errors)
- **MAPE** — Mean Absolute Percentage Error (scale-independent)

### Results

| Rank | Model | MAE | RMSE |
|---|---|---|---|
| 1 | **Random Forest** | 49.69 | **69.51** |
| 2 | SVR (RBF) | 47.98 | 73.51 |
| 3 | XGBoost | 54.69 | 74.64 |
| 4 | LSTM | 58.90 | 80.80 |
| 5 | ARIMA(5,1,0) | 76.18 | 96.84 |

**Random Forest wins.** Lag features (`rolling_7d_mean`, `lag_1`) are the top predictors across RF and XGBoost. A consistent weekend dip in CVE publications is a significant pattern. ARIMA performs worst due to the non-stationary, spiky nature of real CVE data.

---

## How to Run (VS Code)

### 1. Install Dependencies

```bash
pip install numpy pandas matplotlib seaborn scikit-learn xgboost statsmodels tensorflow
```

### 2. Clone the CVE Data

```bash
git clone https://github.com/CVEProject/cvelistV5.git
```

> Large download (~2–3 GB). Alternatively download a snapshot ZIP from the repo's releases page.

### 3. Update Paths

Open `phase1_real_baseline.py` and update these two lines at the top:

```python
CVE_BASE_DIR = Path(r'D:\CyberSec\cvelistV5\cves')   # ← path to your cloned cves/ folder
OUTPUT_DIR   = Path(r'D:\CyberSec\baseline_outputs')  # ← where plots and CSVs will be saved
```

### 4. Run

```bash
python phase1_real_baseline.py
```

> **First run** parses all ~335K JSON files and caches the result to `cve_parsed.csv` (takes ~5–15 min). Every subsequent run loads from cache instantly and skips parsing.

All 12 plots and 2 CSV files are saved to `OUTPUT_DIR` automatically.

---

## What's Next

| Phase | Focus |
|---|---|
| ✅ Phase 1 | Baseline — 5 models on real CVE data |
| 🔜 Phase 2 | Deep Learning — Full-feature LSTM, BiLSTM, Transformer |
| 🔜 Phase 3 | Graph Neural Network — B-MTGNN with Bayesian uncertainty |
| 🔜 Phase 4 | Threat-Defense Gap Forecasting + Power BI Dashboard |