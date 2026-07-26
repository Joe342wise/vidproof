from fastapi import FastAPI
from pydantic import BaseModel


class HealthResponse(BaseModel):
    ok: bool
    service: str


app = FastAPI(title="VidProof API", version="0.1.0")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(ok=True, service="vidproof-api")


@app.post("/evidence/register", status_code=501)
def register_evidence() -> dict[str, object]:
    return {
        "ok": False,
        "error": "Local evidence registration is not implemented yet",
    }
