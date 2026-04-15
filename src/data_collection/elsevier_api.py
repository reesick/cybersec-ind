from __future__ import annotations

import warnings

import numpy as np
import pandas as pd


class ElsevierCollector:
    def __init__(self, api_key: str = "", use_live_api: bool = False):
        self.api_key = api_key
        self.use_live_api = use_live_api

    def monthly_mentions(self, terms: list[str], start_date: str, end_date: str, seed: int = 42) -> pd.DataFrame:
        if self.use_live_api:
            warnings.warn(
                "Elsevier live API connector is not implemented yet; using synthetic monthly mention counts.",
                UserWarning,
                stacklevel=2,
            )
        rng = np.random.default_rng(seed)
        months = pd.date_range(start_date, end_date, freq="MS")
        n = len(months)
        data = {"month": months}
        trend = np.linspace(20, 120, n)
        season = 8 * np.sin(np.linspace(0, 8 * np.pi, n))
        for term in terms:
            noise = rng.normal(0, 7, n)
            shift = rng.integers(-10, 20)
            vals = np.maximum(0, trend + season + noise + shift).round().astype(int)
            data[term] = vals
        return pd.DataFrame(data)
