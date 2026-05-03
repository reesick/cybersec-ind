import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api.routers import forecast, gap, graph, metrics, pipeline

app = FastAPI(title="CyberForesight API", version="1.0.0")

# In production (Render) the frontend is same-origin so CORS isn't needed,
# but keep it open so Swagger UI and local dev both work.
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- API routes (all under /api so they never clash with the React SPA) ---
OUTPUTS_DIR = Path(__file__).parent.parent / "outputs"
app.mount("/api/outputs", StaticFiles(directory=str(OUTPUTS_DIR)), name="outputs")

app.include_router(forecast.router, prefix="/api/forecast", tags=["forecast"])
app.include_router(gap.router,      prefix="/api/gap",      tags=["gap"])
app.include_router(graph.router,    prefix="/api/graph",    tags=["graph"])
app.include_router(metrics.router,  prefix="/api/metrics",  tags=["metrics"])
app.include_router(pipeline.router, prefix="/api/pipeline", tags=["pipeline"])

# --- Serve the React production build (frontend/dist) if it exists ---
DIST = Path(__file__).parent.parent / "frontend" / "dist"

if DIST.exists():
    # Static assets (JS/CSS bundles) live in dist/assets
    app.mount("/assets", StaticFiles(directory=str(DIST / "assets")), name="spa-assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        """Catch-all: return index.html so React Router handles all routes."""
        return FileResponse(str(DIST / "index.html"))
else:
    @app.get("/")
    def root():
        return {"status": "API running — no frontend build found", "docs": "/docs"}
