from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from classifier import classify_case

app = FastAPI(title="Agent Harness Safety Classifier")


@app.get("/")
async def root():
    return {
        "status": "ok",
        "endpoint": "/classify"
    }


@app.post("/classify")
async def classify(request: Request):
    payload = await request.json()

    results = []

    for case in payload.get("cases", []):
        result = classify_case(case)
        results.append(result)

    return JSONResponse(
        content={
            "profile": payload.get("profile"),
            "batchId": payload.get("batchId"),
            "results": results,
        },
        media_type="application/json",
    )