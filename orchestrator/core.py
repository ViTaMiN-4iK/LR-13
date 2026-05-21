from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import nats
from opentelemetry import trace
from nats.aio.client import Client as NATS

from .models import Bid, Result, SIEMRequest, Task

LOGGER = logging.getLogger("siem.orchestrator")
TRACER = trace.get_tracer("python-siem-orchestrator")


class AgentOrchestrator:
    def __init__(self, nats_url: str = "nats://localhost:4222") -> None:
        self.nats_url = nats_url
        self.nc: NATS | None = None
        self.results: dict[str, asyncio.Future[Result]] = {}
        self.audit_events: list[dict[str, Any]] = []

    async def connect(self) -> None:
        self.nc = await nats.connect(self.nats_url, name="python-siem-orchestrator")
        await self.nc.subscribe("siem.tasks.completed", cb=self._on_completed)
        await self.nc.subscribe("siem.audit.events", cb=self._on_audit)
        LOGGER.info("connected to NATS at %s", self.nats_url)

    async def close(self) -> None:
        if self.nc:
            await self.nc.drain()

    async def _on_completed(self, msg) -> None:
        result = Result.model_validate_json(msg.data.decode())
        future = self.results.pop(result.task_id, None)
        if future and not future.done():
            future.set_result(result)

    async def _on_audit(self, msg) -> None:
        try:
            self.audit_events.append(json.loads(msg.data.decode()))
            self.audit_events = self.audit_events[-100:]
        except json.JSONDecodeError:
            LOGGER.exception("bad audit event")

    async def run_pipeline(self, request: SIEMRequest, timeout: float = 20, retries: int = 3) -> Result:
        with TRACER.start_as_current_span("run_siem_pipeline"):
            await self._ensure_connected()
            task = Task(type="collect_logs", payload=request.model_dump())
            await self.run_auction(task)
            last_error: Exception | None = None
            for attempt in range(1, retries + 1):
                LOGGER.info("send task=%s attempt=%s", task.id, attempt)
                future: asyncio.Future[Result] = asyncio.get_running_loop().create_future()
                self.results[task.id] = future
                await self.nc.publish("siem.logs.collect", task.model_dump_json().encode())  # type: ignore[union-attr]
                try:
                    return await asyncio.wait_for(future, timeout=timeout)
                except asyncio.TimeoutError as exc:
                    self.results.pop(task.id, None)
                    last_error = exc
                    LOGGER.error("task=%s timeout on attempt=%s", task.id, attempt)
            raise TimeoutError(f"task {task.id} failed after {retries} attempts") from last_error

    async def run_auction(self, task: Task, timeout: float = 0.8) -> Bid | None:
        await self._ensure_connected()
        payload = {
            "task_id": task.id,
            "type": "detect_attack",
            "payload": task.payload,
        }
        try:
            responses = await self.nc.request(  # type: ignore[union-attr]
                "siem.auction.bid_request",
                json.dumps(payload).encode(),
                timeout=timeout,
            )
        except Exception:
            LOGGER.info("auction finished without bids")
            return None
        bid = Bid.model_validate_json(responses.data.decode())
        task.payload["selected_detector"] = bid.agent
        LOGGER.info("auction selected %s cost=%s skill=%s", bid.agent, bid.cost, bid.skill)
        return bid

    def status(self) -> dict[str, Any]:
        return {
            "connected": bool(self.nc and self.nc.is_connected),
            "pending_tasks": list(self.results.keys()),
            "audit_events": self.audit_events[-20:],
        }

    async def _ensure_connected(self) -> None:
        if not self.nc or not self.nc.is_connected:
            await self.connect()
