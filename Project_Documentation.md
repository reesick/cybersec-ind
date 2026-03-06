# 🛡️ Project Documentation: Forecasting Cyber-Attacks & Control Measures

**Project Code:** CSAI-D1  
**Institution:** DYP-ATU, Talsande — Dept. of Computer Science & Engineering  
**Student:** Mr. Shridhar S. Kharade | **Guide:** Mr. Rajwardhan S. Todkar  
**Duration:** July 2025 – July 2026

---

## Table of Contents

1. [Introduction & Motivation](#1-introduction--motivation)
2. [Market Research — What Exists Today](#2-market-research--what-exists-today)
3. [Gap Analysis — What We're Filling](#3-gap-analysis--what-were-filling)
4. [Our Approach — Core Innovation](#4-our-approach--core-innovation)
5. [Methodology — Complete Phase 1→4 Pipeline](#5-methodology--complete-phase-14-pipeline)
6. [Phase 1: Baseline Forecasting (COMPLETED)](#6-phase-1-baseline-forecasting-completed)
7. [Phase 2: Advanced Deep Learning](#7-phase-2-advanced-deep-learning)
8. [Phase 3: Graph Neural Networks](#8-phase-3-graph-neural-networks)
9. [Phase 4: Threat-Technology Gap Forecasting & Dashboard](#9-phase-4-threat-technology-gap-forecasting--dashboard)
10. [System Architecture](#10-system-architecture)
11. [Dataset Description](#11-dataset-description)
12. [Expected Outcomes](#12-expected-outcomes)
13. [References](#13-references)

---

## 1. Introduction & Motivation

### The Problem

Cybersecurity is fundamentally **reactive** — organizations detect and respond to attacks after they occur. This creates a dangerous gap:

- **82%** of data breaches involve a human element (Verizon DBIR 2023)
- Global cybercrime costs projected to reach **$10.5 trillion/year by 2025** (Cybersecurity Ventures)
- Average time to identify a breach: **204 days** (IBM Cost of Data Breach 2023)
- CVE publications have grown **27x** from 1,579 (1999) to 43,319 (2025)

### The Vision

What if we could **predict** the trajectory of cyber threats before they materialize — forecasting not just *whether* attacks will increase, but *which types* will surge, *which technologies* will be targeted, and *what defenses* will be needed?

This project builds a **proactive forecasting framework** that shifts cybersecurity from reactive detection to predictive intelligence.

---

## 2. Market Research — What Exists Today

### 2.1 Current Forecasting Approaches in the Market

| Approach | Who Uses It | How It Works | Limitations |
|----------|-------------|-------------|-------------|
| **Threat Intelligence Platforms** (Recorded Future, Mandiant) | Enterprise SOCs | Aggregate IOCs from dark web, social media, malware repos | **Reactive** — reports on existing threats, doesn't forecast new ones |
| **SIEM/SOAR** (Splunk, IBM QRadar) | Security operations | Rule-based + anomaly detection on logs | Only detects known patterns; no long-term forecasting |
| **Vulnerability Scanners** (Nessus, Qualys) | IT teams | Scan for known CVEs in deployed software | **Backward-looking** — finds what's already known, can't predict future CVEs |
| **Risk Scoring** (CVSS, EPSS) | Industry-wide | Score individual vulnerabilities by severity/exploitability | Per-vulnerability, no aggregate trend forecasting |
| **Gartner Hype Cycle** | Strategic planners | Expert-driven technology lifecycle analysis | Subjective, updated annually, non-quantitative |
| **Academic ML Models** | Research | ARIMA, LSTM, Random Forest on limited datasets | Single-model, single-dataset, no uncertainty quantification |

### 2.2 Academic Literature Landscape

| Category | Key Works | What They Do | Gap |
|----------|-----------|-------------|-----|
| **Short-term forecasting** (hours→days) | Husák & Kašpar (2019), Werner et al. (2017) | Predict imminent attacks using honeypot/IDS data | Limited to operational planning; no strategic insight |
| **Mid-term forecasting** (weeks→months) | Okutan et al. (2019), Liu et al. (2015) | Use external signals (social media, dark web) | Data-intensive, not scalable |
| **Long-term forecasting** (years) | Almahmoud et al. (2023) | Propose frameworks for proactive forecasting | Mostly theoretical; no working implementation |
| **DL-based approaches** | Ahn et al. (2019), Fang et al. (2021) | LSTM/CNN for malware/attack prediction | Single attack type, no multi-variate analysis |
| **GNN-based** | Wu et al. (2020) — MTGNN | Multi-variate time-series with graph structure | Applied to traffic/weather, **not cybersecurity** |

### 2.3 Existing Tools & Frameworks

| Tool | Type | Use Case |
|------|------|----------|
| **MITRE ATT&CK** | Knowledge base | Catalogs adversary tactics & techniques |
| **CVE/NVD** | Database | Tracks known vulnerabilities |
| **EPSS** | Prediction score | Predicts 30-day exploit probability for individual CVEs |
| **CISA KEV** | Catalog | Lists actively exploited vulnerabilities |

**Key insight:** These tools track and score *individual* vulnerabilities. **None of them forecast aggregate trends** — how many CVEs will be published next month, which attack categories will surge, or which vendors will face the most vulnerabilities.

---

## 3. Gap Analysis — What We're Filling

### 3.1 Identified Research Gaps

| Gap | Current State | What We Address |
|-----|--------------|-----------------|
| **No aggregate trend forecasting** | Tools score individual CVEs; no one forecasts monthly/yearly CVE volume trends | We forecast daily/monthly CVE publication volumes using 5+ models |
| **No CWE category forecasting** | CWE classification exists but no one predicts which categories will grow | We forecast attack category trends (XSS, injection, memory safety, etc.) |
| **No uncertainty quantification** | Existing ML models give point predictions with no confidence intervals | Phase 3 introduces **Bayesian uncertainty** via B-MTGNN |
| **No threat-technology graph** | Attack types and defense technologies are studied separately | Phase 3 builds a **GNN** connecting CVEs → CWEs → Vendors → Products |
| **No gap analysis** | No one forecasts the gap between emerging threats and available defenses | Phase 4 predicts whether defense technology will keep pace with threats |
| **Single-model studies** | Most papers use 1-2 models without systematic comparison | We compare **5 model families** across the same dataset |
| **Synthetic/limited data** | Many papers use small/synthetic datasets | We use the **official CVE database** (335K+ real records, 28 years) |

### 3.2 Our Unique Contribution

```
┌──────────────────────────────────────────────────────────────────┐
│  EXISTING WORK                    │  OUR CONTRIBUTION            │
├──────────────────────────────────────────────────────────────────┤
│  Detect known attacks (reactive)  │  Forecast future attacks     │
│  Score individual CVEs            │  Forecast aggregate trends   │
│  Single model, single dataset     │  5+ models, real CVE data    │
│  No uncertainty in predictions    │  Bayesian uncertainty (B-MTGNN)│
│  Attacks & defenses studied alone │  GNN links threats↔defenses  │
│  "Will this CVE be exploited?"    │  "Will we have the tech to   │
│                                   │   stop future threats?"      │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. Our Approach — Core Innovation

### 4.1 Theoretical Foundation

**Protection Motivation Theory (PMT)** — Originally a psychology framework (Rogers, 1975) explaining how humans respond to threats via:
- **Threat Appraisal**: How severe + how vulnerable?
- **Coping Appraisal**: How effective are defenses + can I implement them?

**Our twist:** We operationalize PMT computationally. Instead of surveying humans, we quantify threat appraisal (CVE volume forecasts) and coping appraisal (defense technology trends) using data-driven models, then predict the **gap** between them.

### 4.2 Core Innovation: B-MTGNN

The **Bayesian Multivariate Time-Series Graph Neural Network** extends the MTGNN architecture (Wu et al., 2020) with:

1. **Graph structure** — Models relationships between attack types, vendors, and technologies as a graph
2. **Multi-variate time-series** — Jointly forecasts multiple correlated time-series (CVE counts per category)
3. **Bayesian inference** — Quantifies epistemic uncertainty ("how confident is this prediction?")
4. **Temporal convolutions** — Captures long-range temporal dependencies

---

## 5. Methodology — Complete Phase 1→4 Pipeline

### High-Level Flow

```
Phase 1 (DONE)        Phase 2              Phase 3              Phase 4
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  Baseline    │   │  Advanced    │   │  Graph       │   │  Gap         │
│  Forecasting │──→│  Deep        │──→│  Neural      │──→│  Forecasting │
│  (5 models)  │   │  Learning    │   │  Networks    │   │  & Dashboard │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
   ARIMA, RF,         BiLSTM,           B-MTGNN,           Threat vs.
   XGBoost,           Transformer,      Threat-Tech        Defense gap,
   SVR, LSTM          Attention         Graph               Power BI
```

---

## 6. Phase 1: Baseline Forecasting (COMPLETED ✅)

### 6.1 Objective
Establish baseline forecasting performance using 5 standard model families on real CVE data.

### 6.2 Data Source
- **Database:** cvelistV5 (Official CVE Program repository)
- **Records used:** 84,936 published CVEs (2024–2026)
- **Format:** JSON → parsed to flat CSV → aggregated to daily time-series

### 6.3 Feature Engineering

| Feature | Type | Description |
|---------|------|-------------|
| `cve_count` | **Target** | Daily CVE publications |
| `day_of_week` | Temporal | 0=Mon, 6=Sun |
| `month` | Temporal | 1–12 |
| `day_of_year` | Temporal | 1–365 |
| `week_of_year` | Temporal | ISO week |
| `is_weekend` | Binary | Weekend flag |
| `quarter` | Temporal | Q1–Q4 |
| `rolling_7d_mean` | Lag | 7-day moving average |
| `rolling_14d_mean` | Lag | 14-day moving average |
| `lag_1` | Lag | Yesterday's count |
| `lag_7` | Lag | Last week's count |

### 6.4 Models Implemented

| Model | Category | Config | MAE | RMSE |
|-------|----------|--------|-----|------|
| **Random Forest** | Ensemble ML | 200 trees, depth=10 | **49.69** | **69.51** |
| SVR (RBF) | Kernel ML | C=100, ε=0.5 | 47.98 | 73.51 |
| XGBoost | Gradient Boosting | 300 trees, lr=0.05 | 54.69 | 74.64 |
| LSTM | Deep Learning | 2-layer (64→32), 14-day lookback | 58.90 | 80.80 |
| ARIMA(5,1,0) | Statistical | AR=5, d=1, MA=0 | 76.18 | 96.84 |

### 6.5 Key Findings
- **Random Forest wins** by RMSE (69.51), same result as the synthetic baseline
- Real data is **much harder** to predict — daily CVE counts range from ~20 to 400+
- Lag features (`rolling_7d_mean`, `lag_1`) are the most important predictors
- Weekend patterns are significant — fewer CVEs published on weekends
- ARIMA struggles most — real CVE data has strong non-stationary trends

### 6.6 Deliverables
- `Phase1_CVE_Baseline.ipynb` — Complete notebook
- `baseline_outputs/` — 12 plots, model results CSV, processed time-series CSV

---

## 7. Phase 2: Advanced Deep Learning

### 7.1 Objective
Improve prediction accuracy using more sophisticated deep learning architectures.

### 7.2 Models to Implement

| Model | Architecture | Why |
|-------|-------------|-----|
| **Full LSTM** | Multi-feature LSTM with 10 input features | Phase 1 LSTM only used univariate data; adding all features should improve accuracy |
| **BiLSTM** | Bidirectional LSTM | Captures both forward and backward temporal dependencies |
| **Temporal CNN** | 1D Convolutions + dilated causal convolutions | Faster training, captures local patterns efficiently |
| **Transformer** | Multi-head self-attention + positional encoding | State-of-the-art sequence modeling; captures long-range dependencies |
| **CNN-LSTM Hybrid** | CNN for feature extraction → LSTM for temporal | Combines spatial and temporal pattern recognition |

### 7.3 Methodology Changes from Phase 1
- Use **all 10 engineered features** as LSTM inputs (not just univariate)
- Implement **TimeSeriesSplit** cross-validation (5-fold)
- Add **hyperparameter tuning** via Optuna or RandomizedSearchCV
- Use **proper prediction intervals** (quantile regression or conformal prediction)

### 7.4 Expected Improvements
- 15-30% RMSE reduction vs. Phase 1 best (target: RMSE < 55)
- Confidence intervals for all predictions
- Attention maps showing which time lags matter most

---

## 8. Phase 3: Graph Neural Networks

### 8.1 Objective
Model the relationships between attack types, vendors, products, and technologies using graph-based deep learning — the **core research contribution** of the project.

### 8.2 Graph Construction

The CVE database naturally encodes a graph structure:

```
            CVE-2025-1001
           /      |       \
      CWE-295  Medixant  RadiAnt DICOM
     (Cert Val) (vendor)   (product)
         |         |
     Authentication  Healthcare
     (category)     (sector)
```

**Node types:**
- CVEs (vulnerability instances)
- CWE categories (attack types)
- Vendors (technology providers)
- Products (software/hardware)

**Edge types:**
- CVE → CWE (vulnerability has type)
- CVE → Vendor (vulnerability affects vendor)
- CVE → Product (vulnerability affects product)
- CWE → CWE (parent-child in CWE hierarchy)

### 8.3 B-MTGNN Architecture

**Bayesian Multivariate Time-Series Graph Neural Network:**

```
Input: Daily time-series per node (CVE counts per CWE category, per vendor, etc.)
     ↓
[Graph Learning Layer] — Learns adaptive adjacency matrix from data
     ↓
[Temporal Convolution] — Dilated causal convolutions for temporal patterns
     ↓
[Graph Convolution] — Message passing across threat-technology graph
     ↓
[Mix-Hop Propagation] — Multi-scale graph diffusion
     ↓
[Bayesian Output Layer] — Mean + variance predictions (uncertainty)
     ↓
Output: Forecasted time-series per node WITH confidence intervals
```

### 8.4 Bayesian Uncertainty
Instead of point predictions, B-MTGNN outputs:
- **μ (mean)**: Expected CVE count for each category/vendor
- **σ² (variance)**: Epistemic uncertainty — how confident the model is
- This allows stakeholders to make **risk-adjusted decisions**

---

## 9. Phase 4: Threat-Technology Gap Forecasting & Dashboard

### 9.1 Objective
Predict the **gap** between future cyber threats and available defense technologies, presented via an interactive dashboard.

### 9.2 Gap Forecasting Framework

```
THREAT TRAJECTORY              GAP              DEFENSE TRAJECTORY
(CVE volume by CWE)            ↕              (Technology maturity)
     ↗ Rising Fast        → WIDENING GAP →      ↗ Slow growth
     → Stable             → STABLE GAP →        → Stable
     ↘ Declining          → CLOSING GAP →       ↗ Growing
```

**For each attack category, compute:**
- Threat score: Forecasted CVE count + severity trend + exploitation likelihood
- Defense score: Available tools, vendor patches, detection capabilities
- **Gap = Threat score - Defense score**

### 9.3 Power BI Dashboard

Interactive dashboard with:
- Global CVE trend forecasts (30, 60, 90 day horizons)
- Per-category threat trajectory (top 10 CWE categories)
- Vendor-specific vulnerability forecasts
- Threat-defense gap visualization with uncertainty bands
- Historical accuracy tracking (predicted vs. actual)

### 9.4 Automation
- On-premises data gateway for real-time CVE sync
- Automated model retraining on new data
- Alert system for widening threat-defense gaps

---

## 10. System Architecture

### End-to-End Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                    DATA LAYER                                   │
├─────────────────────────────────────────────────────────────────┤
│  CVE Database (cvelistV5)  →  JSON Parser  →  Feature Engine   │
│  335K+ records, 28 years      CWE mapping     10 temporal      │
│  Updated every 7 minutes      CVSS extraction  + lag features  │
└──────────────────────┬──────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────┐
│                    MODEL LAYER                                  │
├─────────────────────────────────────────────────────────────────┤
│  Phase 1: ARIMA, RF, XGBoost, SVR, LSTM (baseline)             │
│  Phase 2: BiLSTM, Transformer, CNN-LSTM (deep learning)        │
│  Phase 3: B-MTGNN (graph + Bayesian uncertainty)               │
└──────────────────────┬──────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────┐
│                  FORECASTING & INSIGHT LAYER                    │
├─────────────────────────────────────────────────────────────────┤
│  30/60/90-day CVE forecasts with confidence intervals           │
│  Per-category trend predictions                                 │
│  Threat-defense gap analysis                                    │
│  Technology lifecycle curves                                    │
└──────────────────────┬──────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                           │
├─────────────────────────────────────────────────────────────────┤
│  Power BI Interactive Dashboard                                 │
│  Automated reports & alerts                                     │
│  Real-time sync via on-premises gateway                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 11. Dataset Description

### Primary Dataset: cvelistV5

| Property | Value |
|----------|-------|
| **Source** | [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) |
| **Total records** | 335,550+ |
| **Time span** | 1999 – 2026 (28 years) |
| **Format** | JSON (CVE Record Format v5.x) |
| **Update frequency** | Every ~7 minutes |
| **Phase 1 subset** | 84,936 records (2024–2026) |

### Fields Extracted

| Field | Description | Used For |
|-------|-------------|----------|
| `cve_id` | Unique identifier | Record tracking |
| `date_published` | Publication timestamp | **Primary time-series axis** |
| `cwe_id` | Vulnerability type (CWE) | **Attack category classification** |
| `base_severity` | CVSS severity (L/M/H/C) | **Severity trend analysis** |
| `base_score` | CVSS numerical score (0-10) | Weighted severity |
| `attack_vector` | Network/Local/Adjacent/Physical | Attack delivery method |
| `vendor` | Affected technology vendor | **Vendor-specific forecasting** |
| `product` | Affected product name | **Product-level analysis** |

---

## 12. Expected Outcomes

| Phase | Deliverable | Expected Result |
|-------|-------------|-----------------|
| Phase 1 ✅ | Baseline model comparison | Best model identified (Random Forest, RMSE=69.5) |
| Phase 2 | Deep learning models | 15-30% improvement in RMSE |
| Phase 3 | B-MTGNN with uncertainty | First-ever Bayesian GNN for cyber threat forecasting |
| Phase 4 | Interactive dashboard | Actionable threat-defense gap predictions |
| **Overall** | **Published research paper** | **Novel contribution to proactive cybersecurity** |

---

## 13. References

| # | Author(s) | Year | Title / Topic |
|---|-----------|------|---------------|
| 1 | Rogers, R.W. | 1975 | Protection Motivation Theory |
| 2 | Wu, Z. et al. | 2020 | Connecting the Dots: Multivariate Time Series Forecasting with GNNs (MTGNN) |
| 3 | Almahmoud, Z. et al. | 2023 | A holistic and proactive approach to forecasting cyber threats |
| 4 | Husák, M. & Kašpar, J. | 2019 | Towards predicting cyber attacks using information exchange and data mining |
| 5 | Okutan, A. et al. | 2019 | Forecasting cyber attacks with incomplete, imbalanced, and insignificant data |
| 6 | Liu, Y. et al. | 2015 | Cloudy with a chance of breach: Forecasting cyber security incidents |
| 7 | Ahn, S. et al. | 2019 | A study on CNN-based malicious network traffic detection |
| 8 | Fang, Y. et al. | 2021 | Cybersecurity entity alignment and threat prediction |
| 9 | Chandra, Y. & Collis, S. | 2021 | Gartner Hype Cycle analysis for cybersecurity technologies |
| 10 | Bergstra, J. & Bengio, Y. | 2012 | Random search for hyper-parameter optimization |
| 11 | CVE Program | 2024 | CVE Record Format v5.1 Specification |
| 12 | MITRE Corporation | 2024 | CWE — Common Weakness Enumeration |
| 13 | Verizon | 2023 | Data Breach Investigations Report (DBIR) |
| 14 | IBM Security | 2023 | Cost of a Data Breach Report |

---

*Document generated: March 2026 | Phase 1 status: COMPLETED*
