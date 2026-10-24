"""
AttackGraphX Analysis Service — FastAPI Application Entry Point
Runs on port 9000.
Connects graph intelligence, Redis consumer, and What-If simulation engine.
"""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from analysis_service.config import settings
from analysis_service.api.endpoints import router as api_router, scan_consumer

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events: start Redis stream consumer, stop on shutdown."""
    log.info("AttackGraphX Analysis Service starting", host=settings.service_host, port=settings.service_port)
    await scan_consumer.start()
    yield
    log.info("AttackGraphX Analysis Service shutting down")
    await scan_consumer.stop()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Person 2 — AttackGraphX Analysis Service. "
        "Performs attack path discovery, Dijkstra shortest-path finding, "
        "explainable risk scoring, and What-If remediation simulation."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error("Unhandled Analysis Service exception", path=request.url.path, error=str(exc))
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "ANALYSIS_SERVICE_ERROR",
                "message": "An internal error occurred in the analysis service.",
                "details": str(exc),
            }
        },
    )


@app.get("/", tags=["root"], include_in_schema=False)
async def root():
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "docs": "/docs",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("analysis_service.main:app", host=settings.service_host, port=settings.service_port, reload=True)
