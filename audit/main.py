from fastapi import FastAPI, Request
from prometheus_client import Counter, make_asgi_app
import sqlite3
import datetime
import json
import os

app = FastAPI(title="Audit Service - журнал инцидентов УБИ.097 (R6)")
DB_PATH = os.environ.get("AUDIT_DB", "/data/audit.db")
db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.execute("""CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, service TEXT,
    subject TEXT, resource TEXT, verdict TEXT, reason TEXT, raw TEXT)""")

EVENTS = Counter("audit_events_total", "Зарегистрированные события аудита", ["service", "verdict"])


@app.post("/events", status_code=201)
async def ingest(request: Request):
    e = await request.json()
    db.execute("INSERT INTO events(ts, service, subject, resource, verdict, reason, raw)"
               " VALUES (?,?,?,?,?,?,?)",
               (datetime.datetime.now(datetime.timezone.utc).isoformat(),
                e.get("service"), e.get("subject"), e.get("resource"),
                e.get("verdict"), e.get("reason"), json.dumps(e, ensure_ascii=False)))
    db.commit()
    EVENTS.labels(service=e.get("service", "?"), verdict=e.get("verdict", "?")).inc()
    return {"status": "stored"}


@app.get("/events")
async def search(limit: int = 50, subject: str | None = None):
    q, args = "SELECT ts, service, subject, resource, verdict, reason FROM events WHERE 1=1", []
    if subject:
        q += " AND subject = ?"
        args.append(subject)
    q += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    cols = ("ts", "service", "subject", "resource", "verdict", "reason")
    return [dict(zip(cols, row)) for row in db.execute(q, args).fetchall()]


app.mount("/metrics", make_asgi_app())
