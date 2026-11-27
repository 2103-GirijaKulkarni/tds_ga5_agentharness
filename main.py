from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from classifier import classify_case

app = FastAPI(title="Agent Harness Safety Classifier")

PROFILE = "agent-harness-2026-09"


@app.get("/")
async def root():
    return {"status": "ok", "endpoint": "/classify"}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/classify")
async def classify(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid JSON"})

    if payload.get("profile") != PROFILE:
        return JSONResponse(status_code=400, content={"error": "unsupported profile"})

    batch_id = payload.get("batchId")
    cases = payload.get("cases", [])

    if not isinstance(batch_id, str) or not batch_id:
        return JSONResponse(status_code=400, content={"error": "invalid batchId"})

    if not isinstance(cases, list):
        return JSONResponse(status_code=400, content={"error": "invalid cases"})

    case_ids = [case.get("caseId") for case in cases]

    if any(not isinstance(case_id, str) or not case_id for case_id in case_ids):
        return JSONResponse(status_code=400, content={"error": "missing case ID"})

    if len(case_ids) != len(set(case_ids)):
        return JSONResponse(status_code=400, content={"error": "duplicate case ID"})

    return JSONResponse(
        content={
            "profile": payload.get("profile"),
            "batchId": batch_id,
            "results": [classify_case(case) for case in cases],
        },
        media_type="application/json",
    )
