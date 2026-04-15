from __future__ import annotations

import warnings

import numpy as np
import pandas as pd


class TwitterConflictCollector:
    def __init__(self, bearer_token: str = "", use_live_api: bool = False):
        self.bearer_token = bearer_token
        self.use_live_api = use_live_api

    def monthly_conflict_counts(self, countries: list[str], start_date: str, end_date: str, seed: int = 42) -> pd.DataFrame:
        if self.use_live_api:
            warnings.warn(
                "Twitter/X live API connector is not implemented yet; using synthetic ACA counts.",
                UserWarning,
                stacklevel=2,
            )
        rng = np.random.default_rng(seed + 7)
        months = pd.date_range(start_date, end_date, freq="MS")
        n = len(months)
        data = {"month": months}
        base = np.linspace(200, 450, n) + 35 * np.sin(np.linspace(0, 6 * np.pi, n))
        for c in countries:
            counts = np.maximum(0, base + rng.normal(0, 25, n) + rng.integers(-70, 70)).round().astype(int)
            data[f"ACA_C_{c}"] = counts
        df = pd.DataFrame(data)
        df["ACA"] = df[[col for col in df.columns if col.startswith("ACA_C_")]].sum(axis=1)
        return df
