from typing import Optional

from fastapi import APIRouter, Query

from api.services.data_loader import load_gap

router = APIRouter()


def _latest_gap_magnitude_column(columns) -> Optional[str]:
    magnitude_cols = [
        c for c in columns
        if c.startswith("gap_magnitude_") and c.removeprefix("gap_magnitude_").isdigit()
    ]
    if not magnitude_cols:
        return None
    return max(magnitude_cols, key=lambda c: int(c.rsplit("_", 1)[1]))


@router.get("/")
def get_gap(
    category: Optional[str] = Query(None),
    sort_by: str = Query("gap_magnitude_latest"),
    limit: int = Query(100),
):
    df = load_gap()
    if category:
        df = df[df["category"] == category]
    if sort_by == "gap_magnitude_latest" or sort_by not in df.columns:
        sort_by = _latest_gap_magnitude_column(df.columns) or sort_by
    if sort_by in df.columns:
        df = df.sort_values(sort_by, ascending=False)
    return df.head(limit).to_dict(orient="records")


@router.get("/categories")
def get_categories():
    df = load_gap()
    return sorted(df["category"].dropna().unique().tolist())


@router.get("/top")
def get_top_gaps(n: int = Query(10)):
    df = load_gap()
    sort_by = _latest_gap_magnitude_column(df.columns)
    if not sort_by:
        return df.head(n).to_dict(orient="records")
    return (
        df.sort_values(sort_by, ascending=False)
        .head(n)
        .to_dict(orient="records")
    )
