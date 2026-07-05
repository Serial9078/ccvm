from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database.session import Base, engine
from app import models
from app.api.v1 import customers
from app.routers import assets

Base.metadata.create_all(bind=engine)

app = FastAPI(title="CCVM API", version="0.5.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://192.168.65.199:8090",
        "http://localhost:8090",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(customers.router, prefix="/api/v1")
app.include_router(assets.router, prefix="/api/v1")

@app.get("/health")
def health():
    return {
        "status": "ok",
        "app": "CCVM",
        "version": "0.5.0"
    }
