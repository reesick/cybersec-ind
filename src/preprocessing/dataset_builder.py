from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.constants import COUNTRIES_36, PAT_CODES, THREATS
from src.data_collection.elsevier_api import ElsevierCollector
from src.data_collection.hackmageddon import HackmageddonCollector
from src.data_collection.holidays import monthly_holiday_counts
from src.data_collection.twitter_api import TwitterConflictCollector
from src.preprocessing.smoothing import apply_des
from src.preprocessing.wfc import monthly_attack_country_counts, monthly_attack_counts


def build_monthly_dataset(config: dict) -> pd.DataFrame:
    p = config["project"]
    use_live = config["api"]["use_live_apis"]
    start, end = p["start_date"], p["end_date"]

    hm = HackmageddonCollector(use_live_api=use_live)
    incidents = hm.impute_missing_country(hm.collect(start, end))
    noi_c = monthly_attack_country_counts(incidents)
    noi = monthly_attack_counts(incidents)

    elsevier = ElsevierCollector(config["api"]["elsevier_key"], use_live)
    nom_a = elsevier.monthly_mentions(THREATS, start, end, seed=42).rename(columns={t: f"NoM_A_{t}" for t in THREATS})
    nom_p = elsevier.monthly_mentions(PAT_CODES, start, end, seed=84).rename(columns={p: f"NoM_P_{p}" for p in PAT_CODES})

    tw = TwitterConflictCollector(config["api"]["twitter_bearer"], use_live)
    aca = tw.monthly_conflict_counts(COUNTRIES_36, start, end)
    ph = monthly_holiday_counts(COUNTRIES_36, start, end)

    months = pd.DataFrame({"month": pd.date_range(start, end, freq="MS")})
    data = months.merge(noi_c, on="month", how="left").merge(noi, on="month", how="left")
    data = data.merge(nom_a, on="month", how="left").merge(nom_p, on="month", how="left")
    data = data.merge(aca, on="month", how="left").merge(ph, on="month", how="left")
    data = data.fillna(0).sort_values("month").reset_index(drop=True)

    value_cols = [c for c in data.columns if c != "month"]
    smoothed = apply_des(data, value_cols)
    return smoothed


def save_dataset(df: pd.DataFrame, root_dir: str):
    out = Path(root_dir) / "data" / "processed"
    out.mkdir(parents=True, exist_ok=True)
    df.to_csv(out / "monthly_dataset.csv", index=False)
