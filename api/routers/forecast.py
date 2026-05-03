from typing import Optional

from fastapi import APIRouter, Query

from api.services.data_loader import load_forecast, load_graph

router = APIRouter()


@router.get("/nodes")
def get_nodes():
    graph = load_graph()
    threats = sorted(n["id"] for n in graph["nodes"] if n["type"] == "threat")
    pats = sorted(n["id"] for n in graph["nodes"] if n["type"] == "pat")
    return {"threats": threats, "pats": pats}


@router.get("/")
def get_forecast(
    node: Optional[str] = Query(None),
    year: Optional[int] = Query(None),
):
    df = load_forecast()
    if node:
        df = df[df["node"] == node]
    if year:
        df = df[df["month"].str.startswith(str(year))]
    return df.to_dict(orient="records")


@router.get("/summary")
def get_forecast_summary():
    df = load_forecast()
    df["ci_width"] = df["ci_upper"] - df["ci_lower"]
    summary = (
        df.groupby("node")
        .agg(
            avg_pred=("pred", "mean"),
            avg_ci_width=("ci_width", "mean"),
            max_pred=("pred", "max"),
        )
        .reset_index()
    )
    graph = load_graph()
    type_map = {n["id"]: n["type"] for n in graph["nodes"]}
    summary["type"] = summary["node"].map(type_map).fillna("unknown")
    return summary.to_dict(orient="records")
