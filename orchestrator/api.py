from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .core import AgentOrchestrator
from .models import SIEMRequest

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("orchestrator.log", encoding="utf-8")],
)

app = FastAPI(title="Lab 13 SIEM MAS")
templates = Jinja2Templates(directory="web/templates")
orchestrator = AgentOrchestrator(os.getenv("NATS_URL", "nats://localhost:4222"))


@app.on_event("startup")
async def startup() -> None:
    await orchestrator.connect()


@app.on_event("shutdown")
async def shutdown() -> None:
    await orchestrator.close()


@app.post("/tasks/siem")
async def run_siem_task(payload: SIEMRequest) -> dict:
    result = await orchestrator.run_pipeline(payload)
    return result.model_dump(mode="json")


@app.get("/status")
async def status() -> dict:
    return orchestrator.status()


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("dashboard.html", {"request": request, "status": orchestrator.status()})

