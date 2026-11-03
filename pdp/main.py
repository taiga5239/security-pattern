from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any
import httpx
from prometheus_client import Counter, make_asgi_app

app = FastAPI(title="PDP Engine - Real-time Conflict Verifier")
BLOCKED_CONFLICTS = Counter('authz_policy_conflicts_total', 'Коллизии правил УБИ.097', ['scenario'])
SUCCESSFUL_PERMITS = Counter('authz_permitted_requests_total', 'Успешные авторизации')
PAP_URL = "http://pap-service:8004/policies"
YTSAURUS_ACL_URL = "http://ytsaurus-cluster:8003/api/v3/get_acl"
AUDIT_URL = "http://audit-service:8005/events"


class AuthzSchema(BaseModel):
    subject: Dict[str, Any]
    resource: Dict[str, Any]
    action: str


async def emit_audit(payload: dict) -> None:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(AUDIT_URL, json=payload)
    except httpx.RequestError:
        pass


@app.post("/evaluate")
async def evaluate(req: AuthzSchema):
    sub = req.subject
    path = req.resource.get("table_path")
    role = sub.get("role")

    # 1. Проверка R5: цепочка делегирования
    if sub.get("delegated_by") and sub.get("delegation_depth", 0) > 2:
        BLOCKED_CONFLICTS.labels(scenario="delegation_depth_exceeded").inc()
        await emit_audit({"service": "pdp-service", "subject": sub.get("user_id"),
                          "resource": path, "verdict": "Deny",
                          "reason": "delegation_depth_exceeded"})
        return {"verdict": "Deny", "reason": "Превышена глубина делегирования (> 2)"}

    # 2. Сетевой запрос прикладной политики P2 в микросервис PAP (Шаг 3-4 на UML)
    p2_effect = "Deny"
    async with httpx.AsyncClient() as client:
        try:
            pap_resp = await client.get(f"{PAP_URL}/{role}", timeout=2.0)
            if pap_resp.status_code == 200:
                policy = pap_resp.json()
                if path in policy.get("allowed_paths", []) and req.action == policy.get("action"):
                    p2_effect = policy.get("effect", "Deny")
        except httpx.RequestError:
            p2_effect = "Deny"

    # 3. Сетевой запрос локальных прав P1 в YTsaurus Cypress Master (Шаг 5-6 на UML)
    p1_effect = "Deny"
    async with httpx.AsyncClient() as client:
        try:
            yt_resp = await client.get(YTSAURUS_ACL_URL, params={"path": path}, timeout=2.0)
            if yt_resp.status_code == 200:
                acl_data = yt_resp.json().get("acl", {})
                if role in acl_data.get("denied_roles", []):
                    p1_effect = "Deny"
                elif role in acl_data.get("allowed_roles", []):
                    p1_effect = "Permit"
        except httpx.RequestError:
            return {"verdict": "Deny", "reason": "Ошибка связи с YTsaurus Master"}

    # 4. Предикатная сверка правил и стратегия Deny-Overrides (R4)
    # Сценарий 1: Шлюз разрешает (P2=Permit), но база запрещает (P1=Deny)
    if p2_effect == "Permit" and p1_effect == "Deny":
        BLOCKED_CONFLICTS.labels(scenario="ubi097_shadowing").inc()
        await emit_audit({"service": "pdp-service", "type": "UBI.097",
                          "subject": sub.get("user_id"), "resource": path,
                          "verdict": "Deny", "reason": "ubi097_shadowing"})
        return {
            "verdict": "Deny",
            "reason": "Зафиксирована коллизия УБИ.097: прикладное Permit перекрыто локальным запретом YTsaurus Cypress ACL (Deny)"
        }
    if p2_effect == "Deny" or p1_effect == "Deny":
        BLOCKED_CONFLICTS.labels(scenario="explicit_deny").inc()
        await emit_audit({"service": "pdp-service", "subject": sub.get("user_id"),
                          "resource": path, "verdict": "Deny",
                          "reason": "explicit_deny"})
        return {"verdict": "Deny", "reason": "Доступ запрещен политикой безопасности"}

    SUCCESSFUL_PERMITS.inc()
    return {"verdict": "Permit", "reason": "Политики согласованы"}


app.mount("/metrics", make_asgi_app())
