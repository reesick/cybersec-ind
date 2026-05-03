from fastapi import APIRouter

from api.services.data_loader import load_graph

router = APIRouter()


@router.get("/")
def get_graph():
    raw = load_graph()
    edges = raw.get("links", raw.get("edges", []))
    # Strip per-month weights — not needed for visualisation and makes payload huge
    links = [{"source": e["source"], "target": e["target"]} for e in edges]
    return {"nodes": raw["nodes"], "links": links}


@router.get("/node/{node_id}")
def get_node_neighbours(node_id: str):
    raw = load_graph()
    edges = raw.get("links", raw.get("edges", []))
    neighbours = []
    for e in edges:
        if e["source"] == node_id:
            neighbours.append({"direction": "out", "neighbour": e["target"]})
        elif e["target"] == node_id:
            neighbours.append({"direction": "in", "neighbour": e["source"]})
    return {"node": node_id, "neighbours": neighbours}
