from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import (
    customers,
    dashboard,
    discovery,
    findings,
    host_assessments,
    host_audits,
    host_discovery,
    host_overview,
    hosts,
    jobs,
    network_scans,
    pipelines,
    ports,
    software_assessments,
    subdomains,
    technologies,
    url_details,
    url_screenshots,
    url_security,
    urls,
)
from app.routers import (
    assets,
    domains,
)

app = FastAPI(
    title="CCVM API",
    version="4.4.0",
)

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

app.include_router(
    customers.router,
    prefix="/api/v1",
)
app.include_router(
    assets.router,
    prefix="/api/v1",
)
app.include_router(
    domains.router,
    prefix="/api/v1",
)
app.include_router(
    discovery.router,
    prefix="/api/v1",
)
app.include_router(
    pipelines.router,
    prefix="/api/v1",
)
app.include_router(
    subdomains.router,
    prefix="/api/v1",
)
app.include_router(
    hosts.router,
    prefix="/api/v1",
)
app.include_router(
    ports.router,
    prefix="/api/v1",
)
app.include_router(
    technologies.router,
    prefix="/api/v1",
)
app.include_router(
    urls.router,
    prefix="/api/v1",
)
app.include_router(
    url_details.router,
    prefix="/api/v1",
)
app.include_router(
    url_security.router,
    prefix="/api/v1",
)
app.include_router(
    url_screenshots.router,
    prefix="/api/v1",
)
app.include_router(
    jobs.router,
    prefix="/api/v1",
)
app.include_router(network_scans.router, prefix="/api/v1")
app.include_router(host_assessments.router, prefix="/api/v1")
app.include_router(software_assessments.router, prefix="/api/v1")
app.include_router(host_overview.router, prefix="/api/v1")
app.include_router(host_discovery.router, prefix="/api/v1")
app.include_router(host_audits.router, prefix="/api/v1")
app.include_router(
    findings.router,
    prefix="/api/v1",
)
app.include_router(
    dashboard.router,
    prefix="/api/v1",
)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, error: RequestValidationError):
    if request.url.path.startswith("/api/v1/host-audits"):
        # FastAPI normally echoes invalid input, including nested plaintext
        # secret fields. Do not include input/context/body on this boundary.
        return JSONResponse(
            status_code=422,
            content={
                "detail": [
                    {key: item[key] for key in ("loc", "msg", "type")} for item in error.errors()
                ]
            },
        )
    return await request_validation_exception_handler(request, error)


@app.middleware("http")
async def private_host_audit_responses(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/v1/host-audits"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


@app.get("/health")
def health():
    return {
        "status": "ok",
        "app": "CCVM",
        "version": "4.4.0",
    }
