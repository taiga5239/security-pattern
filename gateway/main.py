from fastapi import FastAPI, HTTPException, Header, Depends
import httpx
import jwt
from pydantic import BaseModel
from typing import Optional
from prometheus_client import Counter, make_asgi_app

app = FastAPI(title="API Gateway (PEP) - UBI.097 Interceptor")
JWT_SECRET = "k8s-cluster-super-secret-jwt-signing-key"
JWT_ALGO = "HS256"
PDP_URL = "http://pdp-service:8001/evaluate"
YTSAURUS_URL = "http://ytsaurus-cluster:8003/api/v3/read_table"
AUDIT_URL = "http://audit-service:8005/events"

DECISIONS = Counter("pep_decisions_total", "Решения PEP по вердиктам", ["verdict"])


class QuerySchema(BaseModel):
    table_path: str
    operation: str = "read"


def auth_context(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Отсутствует заголовок Authorization: Bearer <JWT>")
    token = authorization.split(" ")[1]
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Срок действия токена истек")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Неверная криптографическая подпись токена")


async def emit_audit(payload: dict) -> None:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(AUDIT_URL, json=payload)
    except httpx.RequestError:
        pass  # недоступность аудита не должна приводить к отказу в обслуживании


@app.post("/api/v1/query")
async def handle_request(query: QuerySchema, user: dict = Depends(auth_context)):
    authz_request = {
        "subject": {
            "user_id": user.get("sub"),
            "role": user.get("role"),
            "clearance": user.get("clearance", "internal"),
            "delegated_by": user.get("delegated_by"),
            "delegation_depth": user.get("delegation_depth", 0)
        },
        "resource": {"table_path": query.table_path},
        "action": query.operation
    }
    # 1. Запрос вердикта в PDP
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(PDP_URL, json=authz_request, timeout=3.0)
            decision = resp.json()
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Служба безопасности PDP недоступна")

    # 2. Метрика и регистрация решения в подсистеме аудита (R6)
    verdict = decision.get("verdict", "Deny")
    DECISIONS.labels(verdict=verdict).inc()
    await emit_audit({
        "service": "api-gateway",
        "subject": user.get("sub"),
        "resource": query.table_path,
        "verdict": verdict,
        "reason": decision.get("reason")
    })

    # 3. Исполнение вердикта (Enforcement): блокировка УБИ.097
    if verdict != "Permit":
        raise HTTPException(
            status_code=403,
            detail=f"Доступ заблокирован паттерном безопасности: {decision.get('reason')}"
        )

    # 4. Легитимное чтение данных из YTsaurus HTTP Proxy
    async with httpx.AsyncClient() as client:
        yt_resp = await client.get(YTSAURUS_URL, params={"path": query.table_path})
    return {
        "status": "success",
        "verdict": "Permit",
        "target": query.table_path,
        "ytsaurus_response": yt_resp.json()
    }


app.mount("/metrics", make_asgi_app())
