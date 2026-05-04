from __future__ import annotations

import pandas as pd

from src.constants import THREAT_PAT_MAP


def _category(g25: float, g26: float, g27: float) -> str:
    if g25 < g26 < g27:
        return "SWG"
    if g25 > g26 > g27:
        return "SNG"
    if g27 > g25:
        return "OWG"
    return "ONG"


def compute_gap_report(df_forecast: pd.DataFrame) -> pd.DataFrame:
    pivot = df_forecast.pivot_table(index="month", columns="node", values="pred", aggfunc="mean")
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
            g25, g26, g27 = float(y.get(2025, 0.0)), float(y.get(2026, 0.0)), float(y.get(2027, 0.0))
            out.append({
                "threat": t,
                "pat": p,
                "gap_2025": g25,
                "gap_2026": g26,
                "gap_2027": g27,
                "category": _category(g25, g26, g27),
                "gap_magnitude_2027": abs(g27),
            })
    return pd.DataFrame(out).sort_values(["category", "gap_magnitude_2027"], ascending=[True, False])
