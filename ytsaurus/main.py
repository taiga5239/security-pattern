from fastapi import FastAPI, HTTPException, Query

app = FastAPI(title="YTsaurus Cluster - HTTP Proxy & Cypress Master")

# Метаданные дерева Cypress и списки ACL (СЗИ-1)
CYPRESS_ACL_DATABASE = {
    "//home/analytics/reports": {
        "allowed_roles": ["analyst", "auditor"],
        "denied_roles": []
    },
    "//home/analytics/clients_pii": {
        "allowed_roles": ["admin"],
        "denied_roles": ["analyst"]  # Жесткий локальный запрет на персональные данные!
    }
}

# Данные динамических таблиц YTsaurus
YTSAURUS_TABLES_DATA = {
    "//home/analytics/reports": [
        {"report_id": 101, "metric": "q1_revenue", "value": "15.4M"},
        {"report_id": 102, "metric": "q2_forecast", "value": "18.2M"}
    ],
    "//home/analytics/clients_pii": [
        {"client_id": 1, "name": "Иванов А.А.", "passport": "4510 123456", "salary": 250000},
        {"client_id": 2, "name": "Смирнов Б.В.", "passport": "4511 654321", "salary": 480000}
    ]
}


# Эндпоинт мастера Cypress: отдает ACL права для сверки в PDP
@app.get("/api/v3/get_acl")
async def get_cypress_acl(path: str = Query(...)):
    acl = CYPRESS_ACL_DATABASE.get(path)
    if not acl:
        raise HTTPException(status_code=404, detail="Таблица не найдена в дереве Cypress")
    return {"path": path, "acl": acl}


# Эндпоинт YTsaurus HTTP Proxy: выдает реальные данные таблицы
@app.get("/api/v3/read_table")
async def read_table(path: str = Query(...)):
    data = YTSAURUS_TABLES_DATA.get(path)
    if not data:
        raise HTTPException(status_code=404, detail="Объект Cypress не существует")
    return {"status": "ok", "format": "yson/json", "rows": data}
