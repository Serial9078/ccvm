from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import (
    customers,
    dashboard,
    discovery,
    findings,
    hosts,
    jobs,
    ports,
    subdomains,
    technologies,
)
from app.routers import assets, domains

app = FastAPI(title="CCVM API", version="3.5.0")

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
app.include_router(domains.router, prefix="/api/v1")
app.include_router(discovery.router, prefix="/api/v1")
app.include_router(subdomains.router, prefix="/api/v1")
app.include_router(hosts.router, prefix="/api/v1")
app.include_router(ports.router, prefix="/api/v1")
app.include_router(technologies.router, prefix="/api/v1")
app.include_router(jobs.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "app": "CCVM",
        "version": "3.5.0",
    }
