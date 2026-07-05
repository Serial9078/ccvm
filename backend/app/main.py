from fastapi import FastAPI
from app.database.session import Base, engine
from app import models
from app.routers import customers, assets

Base.metadata.create_all(bind=engine)

app = FastAPI(title="CCVM API", version="0.2.0")

app.include_router(customers.router)
app.include_router(assets.router)

@app.get("/health")
def health():
    return {
        "status": "ok",
        "app": "CCVM",
        "version": "0.2.0"
    }
