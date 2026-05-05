import json
from functools import lru_cache
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).parent.parent.parent
OUTPUTS_DIR = BASE_DIR / "outputs"
DATA_DIR = BASE_DIR / "data"


@lru_cache(maxsize=None)
def load_forecast() -> pd.DataFrame:
    df = pd.read_csv(OUTPUTS_DIR / "forecast_2025_2027.csv")
    df["month"] = pd.to_datetime(df["month"]).dt.strftime("%Y-%m-%d")
    return df


@lru_cache(maxsize=None)
def load_gap() -> pd.DataFrame:
    return pd.read_csv(OUTPUTS_DIR / "gap_analysis_report.csv")


@lru_cache(maxsize=None)
def load_graph() -> dict:
    with open(DATA_DIR / "graph" / "tpt_graph.json") as f:
        return json.load(f)


@lru_cache(maxsize=None)
def load_validation_metrics() -> pd.DataFrame:
    return pd.read_csv(OUTPUTS_DIR / "validation_metrics.csv")


@lru_cache(maxsize=None)
def load_ablation() -> pd.DataFrame:
    return pd.read_csv(OUTPUTS_DIR / "ablation_and_baselines.csv")


@lru_cache(maxsize=None)
def load_atc() -> pd.DataFrame:
    return pd.read_csv(OUTPUTS_DIR / "atc_phases.csv")
