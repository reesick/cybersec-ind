from typing import Optional

from fastapi import APIRouter, Query

from api.services.data_loader import load_gap

router = APIRouter()


@router.get("/")
def get_gap(
    category: Optional[str] = Query(None),
    sort_by: str = Query("gap_magnitude_2025"),
    limit: int = Query(100),
):
    df = load_gap()
    if category:
        df = df[df["category"] == category]
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
    return (
        df.sort_values("gap_magnitude_2025", ascending=False)
        .head(n)
        .to_dict(orient="records")
    )
