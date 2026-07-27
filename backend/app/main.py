from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel

from backend.app.config import settings
from backend.app.routers import cameras, evidence


@asynccontextmanager
async def lifespan(app: FastAPI):
    for d in (
        settings.evidence_dir,
        settings.cameras_dir,
        settings.evidence_meta_dir,
        settings.results_dir,
        settings.keys_dir,
    ):
        d.mkdir(parents=True, exist_ok=True)
    yield


class HealthResponse(BaseModel):
    ok: bool
    service: str


app = FastAPI(title="VidProof API", version="0.1.0", lifespan=lifespan)

app.include_router(cameras.router)
app.include_router(evidence.router)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(ok=True, service="vidproof-api")
