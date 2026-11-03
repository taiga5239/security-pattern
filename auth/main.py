from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import jwt
import time

app = FastAPI(title="Auth Service - Token Issuer")
JWT_SECRET = "k8s-cluster-super-secret-jwt-signing-key"
JWT_ALGO = "HS256"


class LoginRequest(BaseModel):
    username: str


# База учетных записей для демонстрации двух сценариев
USERS_DB = {
    "analyst_ivanov": {
        "sub": "user_ivanov",
        "role": "analyst",
        "department": "analytics",
        "clearance": "internal",
        "delegated_by": None,
        "delegation_depth": 0
    },
    "hacker_petrov": {
        "sub": "user_petrov",
        "role": "analyst",  # Роль присвоена ошибочно через делегирование
        "department": "marketing",
        "clearance": "public",
        "delegated_by": "lead_analyst",
        "delegation_depth": 1  # Делегированные права с превышением
    }
}


@app.post("/login")
async def login(req: LoginRequest):
    user = USERS_DB.get(req.username)
    if not user:
        raise HTTPException(status_code=401, detail="Неверное имя пользователя (доступны: analyst_ivanov, hacker_petrov)")
    payload = {
        **user,
        "exp": int(time.time()) + 3600  # Срок жизни 1 час
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    return {
        "access_token": token,
        "token_type": "Bearer",
        "user_claims": user
    }
