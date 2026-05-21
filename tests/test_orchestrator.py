from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import pytest

from orchestrator.core import AgentOrchestrator
from orchestrator.models import SIEMRequest


class FakeMsg:
    def __init__(self, data: bytes) -> None:
        self.data = data


class FakeNATS:
    def __init__(self, auto_complete: bool = True) -> None:
        self.is_connected = True
        self.subscriptions = {}
        self.published = []
        self.auto_complete = auto_complete

    async def subscribe(self, subject, cb):
        self.subscriptions[subject] = cb

    async def publish(self, subject, data):
        self.published.append((subject, json.loads(data.decode())))
        if subject == "siem.logs.collect" and self.auto_complete:
            task = json.loads(data.decode())
            result = {
                "task_id": task["id"],
                "trace_id": task["trace_id"],
                "agent": "traffic-blocker",
                "success": True,
                "output": {"blocked": True, "source_ip": task["payload"]["source_ip"]},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            await self.subscriptions["siem.tasks.completed"](FakeMsg(json.dumps(result).encode()))

    async def request(self, subject, data, timeout):
        request = json.loads(data.decode())
        bid = {
            "task_id": request["task_id"],
            "agent": "attack-detector",
            "cost": 10.0,
            "skill": 0.92,
            "available": True,
            "subject": "siem.attacks.detect",
            "reason": "test",
            "received_at": "2026-05-21T00:00:00Z",
        }
        return FakeMsg(json.dumps(bid).encode())

    async def drain(self):
        self.is_connected = False


@pytest.mark.asyncio
async def test_run_pipeline_returns_completed_result(monkeypatch):
    fake = FakeNATS()
    orchestrator = AgentOrchestrator()

    async def fake_connect(*args, **kwargs):
        return fake

    monkeypatch.setattr("orchestrator.core.nats.connect", fake_connect)
    result = await orchestrator.run_pipeline(
        SIEMRequest(
            source_ip="203.0.113.17",
            host="vpn",
            raw_logs=["failed login", "failed login", "failed login", "malware signature"],
        ),
        timeout=1,
    )

    assert result.success is True
    assert result.output["blocked"] is True
    assert fake.published[0][0] == "siem.logs.collect"
    assert fake.published[0][1]["payload"]["selected_detector"] == "attack-detector"


@pytest.mark.asyncio
async def test_run_pipeline_retries_and_times_out(monkeypatch):
    fake = FakeNATS(auto_complete=False)
    orchestrator = AgentOrchestrator()

    async def fake_connect(*args, **kwargs):
        return fake

    monkeypatch.setattr("orchestrator.core.nats.connect", fake_connect)

    with pytest.raises(TimeoutError):
        await orchestrator.run_pipeline(SIEMRequest(raw_logs=["failed login"]), timeout=0.01, retries=2)

    await asyncio.sleep(0)
    assert len([item for item in fake.published if item[0] == "siem.logs.collect"]) == 2

