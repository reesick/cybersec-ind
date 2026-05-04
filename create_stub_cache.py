"""Create zero-filled stub cache files for PATs missing from the 2026-04-01 cache.

Run once: python create_stub_cache.py
"""
import pickle
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from src.utils import load_config
from src.constants import PAT_CODES

cfg = load_config(str(ROOT / "config.yaml"))
start_date = cfg["project"]["start_date"]
end_date = cfg["project"]["end_date"]
cache_dir = Path(cfg["cache"]["path"])

months = pd.date_range(start_date, end_date, freq="MS")
zero_series = pd.Series([0] * len(months), index=months, dtype=int)


def cache_path(term: str) -> Path:
    safe = f"elsevier/{term}_{start_date}_{end_date}"
    for ch in "/\\:*?":
        safe = safe.replace(ch, "_")
    safe = safe.replace(" ", "_")
    return cache_dir / f"{safe}.pkl"


created = 0
for pat in PAT_CODES:
    p = cache_path(pat)
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as f:
            pickle.dump(zero_series, f, protocol=pickle.HIGHEST_PROTOCOL)
        print(f"  created stub: {p.name}")
        created += 1

print(f"\nDone — {created} stub file(s) created, {len(PAT_CODES) - created} already cached.")
