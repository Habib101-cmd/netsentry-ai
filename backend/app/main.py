from fastapi import FastAPI, HTTPException
from sqlalchemy import create_engine, text

from app.config import settings

app = FastAPI(title="NetSentry AI", version="0.1.0")
engine = create_engine(settings.database_url, pool_pre_ping=True)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/health/db")
def health_db():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "ok", "database": "up"}
