import asyncio
from pathlib import Path

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

REPO_ROOT = Path(__file__).parent.parent.parent

_state: dict = {"running": False, "logs": [], "exit_code": None}


@router.post("/run")
async def run_pipeline(refresh_cache: bool = False):
    if _state["running"]:
        return {"status": "already_running"}
    _state["running"] = True
    _state["logs"] = []
    _state["exit_code"] = None
    asyncio.create_task(_exec(refresh_cache))
    return {"status": "started"}


@router.get("/status")
def get_status():
    return {
        "running": _state["running"],
        "exit_code": _state["exit_code"],
        "log_lines": len(_state["logs"]),
    }


@router.websocket("/logs")
async def stream_logs(websocket: WebSocket):
    await websocket.accept()
    sent = 0
    try:
        while True:
            while sent < len(_state["logs"]):
                await websocket.send_text(_state["logs"][sent])
                sent += 1
            if not _state["running"] and sent >= len(_state["logs"]):
                break
            await asyncio.sleep(0.15)
    except WebSocketDisconnect:
        pass
    finally:
        await websocket.close()


async def _exec(refresh_cache: bool):
    cmd = ["python", "run_pipeline.py"]
    if refresh_cache:
        cmd.append("--refresh-cache")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(REPO_ROOT),
    )
    async for raw in proc.stdout:
        _state["logs"].append(raw.decode(errors="replace").rstrip())
    _state["exit_code"] = await proc.wait()
    _state["running"] = False
