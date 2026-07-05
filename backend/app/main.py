from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1 import assets, customers, dashboard
from app.core.config import settings
from app.database.session import Base, engine
from app import models

Base.metadata.create_all(bind=engine)

app = FastAPI(title="CCVM API", version=settings.app_version)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard.router)
app.include_router(customers.router)
app.include_router(assets.router)


@app.get("/health")
def health():
    return {"status": "ok", "app": settings.app_name, "version": settings.app_version}
