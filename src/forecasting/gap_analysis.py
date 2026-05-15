from __future__ import annotations

import pandas as pd

from src.constants import THREAT_PAT_MAP


def _category(gap_values: list[float]) -> str:
    if len(gap_values) < 2:
        return "ONG"
    if len(gap_values) >= 3:
        g1, g2, g3 = gap_values[-3], gap_values[-2], gap_values[-1]
        if g1 < g2 < g3:
            return "SWG"
        if g1 > g2 > g3:
            return "SNG"
        if g3 > g1:
            return "OWG"
        return "ONG"
    # 2-year path
    g1, g2 = gap_values
    delta = g2 - g1
    magnitude = abs(g2)
    if delta > 0.05 and magnitude > 0.2:
        return "SWG"
    if delta > 0.02:
        return "OWG"
    if magnitude < 0.05:
        return "SNG"
    return "ONG"


def compute_gap_report(df_forecast: pd.DataFrame) -> pd.DataFrame:
    df_forecast = df_forecast.copy()
    df_forecast["month"] = pd.to_datetime(df_forecast["month"])
    pivot = df_forecast.pivot_table(index="month", columns="node", values="pred", aggfunc="mean")
    years = sorted(pivot.index.year.unique())

    out = []
    for t, pats in THREAT_PAT_MAP.items():
        if t not in pivot.columns:
            continue
        t_norm = pivot[t] / max(pivot[t].max(), 1e-6)
        for p in pats:
            if p not in pivot.columns:
                continue
            p_norm = pivot[p] / max(pivot[p].max(), 1e-6)
            gap = t_norm - p_norm
            y = gap.groupby(gap.index.year).mean()

            row: dict = {"threat": t, "pat": p}
            gap_values = []
            for yr in years:
                val = float(y.get(yr, 0.0))
                row[f"gap_{yr}"] = val
                gap_values.append(val)

            last_year = years[-1]
            row["category"] = _category(gap_values)
            row[f"gap_magnitude_{last_year}"] = abs(gap_values[-1])
            out.append(row)

    last_year = years[-1]
    return pd.DataFrame(out).sort_values(
        ["category", f"gap_magnitude_{last_year}"], ascending=[True, False]
    )
