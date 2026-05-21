from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class SIEMRequest(BaseModel):
    source_ip: str = Field(default="10.10.10.17")
    host: str = Field(default="web-17")
    raw_logs: list[str] = Field(default_factory=list)


class Task(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    type: str
    trace_id: str = Field(default_factory=lambda: str(uuid4()))
    payload: dict[str, Any]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Result(BaseModel):
    task_id: str
    trace_id: str
    agent: str
    success: bool
    output: dict[str, Any]
    error: str | None = None
    timestamp: datetime


class Bid(BaseModel):
    task_id: str
    agent: str
    cost: float
    skill: float
    available: bool
    subject: str
    reason: str
    received_at: str

