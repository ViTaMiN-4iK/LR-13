from __future__ import annotations

import json
import os

import httpx
import nats


async def explain_incident(detection: dict) -> str:
    prompt = (
        "Кратко объясни инцидент SIEM для аналитика SOC и предложи 3 действия. "
        f"Данные: {json.dumps(detection, ensure_ascii=False)}"
    )
    ollama_url = os.getenv("OLLAMA_URL")
    if not ollama_url:
        return "LLM disabled: set OLLAMA_URL to enable incident explanation."
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            f"{ollama_url.rstrip('/')}/api/generate",
            json={"model": os.getenv("OLLAMA_MODEL", "llama3.1"), "prompt": prompt, "stream": False},
        )
        response.raise_for_status()
        return response.json().get("response", "")


async def main() -> None:
    nc = await nats.connect(os.getenv("NATS_URL", "nats://localhost:4222"), name="python-llm-agent")

    async def handler(msg) -> None:
        event = json.loads(msg.data.decode())
        output = event.get("output", {})
        if "detection" not in output:
            return
        explanation = await explain_incident(output["detection"])
        await nc.publish(
            "siem.llm.explanations",
            json.dumps({"task_id": event["task_id"], "explanation": explanation}, ensure_ascii=False).encode(),
        )

    await nc.subscribe("siem.audit.events", cb=handler)
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())

