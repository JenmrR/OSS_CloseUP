from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .db import connect

app = FastAPI(title="OSS Close-UP API", version="0.1.0")


@app.get("/health/live")
def live():
    """프로세스가 살아 있는지만 확인 (DB와 무관)."""
    return {"status": "ok"}


@app.get("/health")
def health():
    """API + DB 연결까지 확인. DB가 안 되면 503."""
    try:
        with connect() as conn:
            version = conn.execute("SELECT version()").fetchone()[0]
        return {"status": "ok", "db": "ok", "db_version": version.split(",")[0]}
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "db": "error", "detail": type(e).__name__},
        )


from .uploads import router, UploadBodyLimit
from .sbom import router as sbom_router
from .ai_analysis import router as ai_router
app.add_middleware(UploadBodyLimit)
app.include_router(router)
app.include_router(sbom_router)
app.include_router(ai_router)
