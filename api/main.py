"""FastAPI service exposing persisted CSPM scan data to the React UI."""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src import compliance, db, drift
from src.ai import assistant as ai_assistant
from src.ai import context_builder


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="CSPM API", version="1.0.0", lifespan=lifespan)
origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class CopilotQuestion(BaseModel):
    question: str = Field(min_length=1, max_length=4000)


def _scan_or_404(scan_id: int) -> dict:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} was not found")
    return scan


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/scans")
def list_scans() -> list[dict]:
    return db.get_all_scans()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int) -> dict:
    return _scan_or_404(scan_id)


@app.get("/api/scans/{scan_id}/findings")
def get_scan_findings(scan_id: int) -> list[dict]:
    _scan_or_404(scan_id)
    return db.get_findings_for_scan(scan_id)


@app.get("/api/scans/{scan_id}/assets")
def get_scan_assets(scan_id: int) -> list[dict]:
    return db.get_assets_for_account(_scan_or_404(scan_id)["account_id"])


@app.get("/api/assets/{asset_id}")
def get_asset(asset_id: int) -> dict:
    asset = db.get_asset(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} was not found")
    return asset


@app.get("/api/assets/{asset_id}/findings")
def get_asset_findings(asset_id: int) -> list[dict]:
    if db.get_asset(asset_id) is None:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} was not found")
    return db.get_findings_for_asset(asset_id)


@app.get("/api/scans/{scan_id}/compliance")
def get_compliance(scan_id: int) -> dict:
    findings = db.get_findings_for_scan(_scan_or_404(scan_id)["id"])
    return {
        "frameworks": compliance.FRAMEWORKS,
        "summary": compliance.compliance_summary(findings),
    }


@app.get("/api/scans/{scan_id}/drift")
def get_drift(scan_id: int) -> dict:
    _scan_or_404(scan_id)
    previous = db.get_previous_scan(scan_id)
    if previous is None:
        return {"previous_scan": None, "changes": [], "counts": drift.summarize_drift([])}
    changes = drift.compare_scans(db.get_findings_for_scan(previous["id"]), db.get_findings_for_scan(scan_id))
    return {"previous_scan": previous, "changes": changes, "counts": drift.summarize_drift(changes)}


@app.get("/api/scans/{scan_id}/copilot/status")
def copilot_status(scan_id: int) -> dict:
    _scan_or_404(scan_id)
    return {"configuration_message": ai_assistant.provider_config_status()}


@app.post("/api/scans/{scan_id}/copilot")
def ask_copilot(scan_id: int, payload: CopilotQuestion) -> dict:
    _scan_or_404(scan_id)
    try:
        context = context_builder.build_context(scan_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    if not context.get("failing_findings"):
        raise HTTPException(status_code=400, detail="No failing findings are available to analyze")
    try:
        answer = ai_assistant.ask_ai(payload.question, context)
    except ai_assistant.AssistantError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return {"answer": answer, "context": context}
