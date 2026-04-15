# Cyber Threat & PAT Forecasting (B-MTGNN)

End-to-end implementation of the pipeline described in Almahmoud et al. (2025), including:

1. Data collection/preparation (with mock fallbacks for unavailable APIs)
2. Threats and Pertinent Technologies (TPT) graph construction
3. Bayesian MTGNN model training with MC dropout
4. 2023-2025 forecasting, gap analysis, and recommendation generation
5. Alleviation Technologies Cycle (ATC) plotting

## Quickstart

```bash
pip install -r requirements.txt
python run_pipeline.py
```

## Outputs

Generated under `outputs/`:

- `b_mtgnn_best.pt`
- `forecast_2023_2025.csv`
- `gap_analysis_report.csv`
- `investment_recommendations.pdf`
- `atc_diagram.png`
- `trend_plots/*.png`

Generated under `data/`:

- `data/processed/monthly_dataset.csv`
- `data/graph/tpt_graph.json`

## Notes

- Set `api.use_live_apis: true` in `config.yaml` only after implementing live credentials and endpoint details.
- Current implementation deliberately supports mock mode for reproducible execution without external API keys.
