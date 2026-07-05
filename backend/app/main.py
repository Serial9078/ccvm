from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.database.session import Base, engine
from app import models
from app.routers import customers, assets

Base.metadata.create_all(bind=engine)

app = FastAPI(title="CCVM API", version=settings.app_version)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(customers.router, prefix="/api/v1")
app.include_router(assets.router, prefix="/api/v1")

@app.get("/health")
def health():
    return {"status": "ok", "app": settings.app_name, "version": settings.app_version}
