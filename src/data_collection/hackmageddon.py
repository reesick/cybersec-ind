from __future__ import annotations

import warnings
from dataclasses import dataclass
from typing import Optional

import numpy as np
import pandas as pd

from src.constants import COUNTRIES_36, THREATS


@dataclass
class HackmageddonCollector:
    use_live_api: bool = False

    def collect(self, start_date: str, end_date: str, approx_records: int = 18000) -> pd.DataFrame:
        if self.use_live_api:
            warnings.warn(
                "Hackmageddon live ingest is not implemented yet; using synthetic incidents. "
                "Set api.use_live_apis: false to expect mock data, or add a CSV path when supported.",
                UserWarning,
                stacklevel=2,
            )
        return self._mock_incidents(start_date, end_date, approx_records)

    def _mock_incidents(self, start_date: str, end_date: str, n: int) -> pd.DataFrame:
        rng = np.random.default_rng(42)
        months = pd.date_range(start_date, end_date, freq="MS")
        dates = rng.choice(months, size=n, replace=True)
        threats = rng.choice(THREATS, size=n, replace=True)
        countries = rng.choice(COUNTRIES_36 + [None], size=n, replace=True, p=[*(np.repeat(0.97 / 36, 36)), 0.03])
        descriptions = [f"{t} incident reported in {c or 'unknown region'}." for t, c in zip(threats, countries)]
        df = pd.DataFrame({"date": pd.to_datetime(dates), "attack_type": threats, "country": countries, "description": descriptions})
        return df.sort_values("date").reset_index(drop=True)

    @staticmethod
    def impute_missing_country(df: pd.DataFrame) -> pd.DataFrame:
        def infer_country(row) -> Optional[str]:
            if pd.notna(row["country"]):
                return row["country"]
            desc = str(row["description"])
            for code in COUNTRIES_36:
                if f" {code} " in f" {desc} ":
                    return code
            return "US"

        out = df.copy()
        out["country"] = out.apply(infer_country, axis=1)
        return out
