from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from api.routers import forecast, gap, graph, metrics, pipeline

app = FastAPI(title="CyberForesight API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

OUTPUTS_DIR = Path(__file__).parent.parent / "outputs"
app.mount("/outputs", StaticFiles(directory=str(OUTPUTS_DIR)), name="outputs")

app.include_router(forecast.router, prefix="/forecast", tags=["forecast"])
app.include_router(gap.router, prefix="/gap", tags=["gap"])
app.include_router(graph.router, prefix="/graph", tags=["graph"])
app.include_router(metrics.router, prefix="/metrics", tags=["metrics"])
app.include_router(pipeline.router, prefix="/pipeline", tags=["pipeline"])


@app.get("/")
def root():
    return {"status": "ok", "docs": "/docs"}
