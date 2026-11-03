from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import httpx

app = FastAPI(title="PAP Service - Policy Administration Point & Conflict Detector (R3)")
AUDIT_URL = "http://audit-service:8005/events"


class PolicySchema(BaseModel):
    role: str
    allowed_paths: List[str]
    action: str
    effect: str


# Реестр действующих прикладных политик P2
POLICIES_DB = {
    "analyst": {
        "role": "analyst",
        "allowed_paths": ["//home/analytics/reports", "//home/analytics/clients_pii"],
        "action": "read",
        "effect": "Permit"
    }
}


async def emit_audit(payload: dict) -> None:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(AUDIT_URL, json=payload)
    except httpx.RequestError:
        pass


# 1. Эндпоинт для PDP: запрос действующих политик (Шаги 3-4 на UML-диаграмме)
@app.get("/policies/{role}")
async def get_policy(role: str):
    policy = POLICIES_DB.get(role)
    if not policy:
        raise HTTPException(status_code=404, detail="Политика для роли не найдена")
    return policy


# 2. Эндпоинт для Администратора: предпубликационная проверка (R3)
@app.post("/policies/publish")
async def publish_policy(new_policy: PolicySchema):
    # Предикатная проверка: запрет публикации заведомо конфликтных правил
    if new_policy.effect == "Deny" and "//home/analytics/reports" in new_policy.allowed_paths:
        await emit_audit({"service": "pap-service", "type": "UBI.097",
                          "subject": "security_admin",
                          "resource": ", ".join(new_policy.allowed_paths),
                          "verdict": "Deny", "reason": "publish_conflict_R3"})
        raise HTTPException(
            status_code=409,
            detail="Детектор конфликтов (R3): Отклонено! Правило создает коллизию УБИ.097 (Сценарий 2)"
        )
    POLICIES_DB[new_policy.role] = new_policy.dict()
    return {"status": "published", "message": "Политика успешно верифицирована и сохранена в PAP"}
