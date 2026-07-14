import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from analyzer import AISecurityAnalyzer

app = FastAPI(
    title="KAGE AI Engine",
    description="AI-powered security analysis for KAGE scanner",
    version="0.1.0",
)

analyzer: Optional[AISecurityAnalyzer] = None


class FindingInput(BaseModel):
    title: str
    description: str = ""
    severity: str = "info"
    file_path: str = ""
    line_start: int = 0
    code_snippet: str = ""
    category: str = ""
    message: str = ""


class AnalyzeRequest(BaseModel):
    findings: list[FindingInput]
    mode: str = "analyze"


class FindingOutput(BaseModel):
    finding_id: str
    risk_explanation: str = ""
    severity_adjustment: str = ""
    suggested_fix: str = ""


class AnalyzeResponse(BaseModel):
    analysis: list[FindingOutput]


def get_analyzer() -> AISecurityAnalyzer:
    global analyzer
    if analyzer is None:
        provider = os.environ.get("KAGE_AI_PROVIDER", "gemini")
        api_key = os.environ.get("KAGE_AI_API_KEY", "")
        model = os.environ.get("KAGE_AI_MODEL", "")
        endpoint = os.environ.get("KAGE_AI_ENDPOINT", "")
        analyzer = AISecurityAnalyzer(
            provider=provider,
            api_key=api_key,
            model=model,
            endpoint=endpoint,
        )
    return analyzer


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    try:
        eng = get_analyzer()
        results = await eng.analyze_findings(
            findings=[f.model_dump() for f in request.findings],
        )
        return AnalyzeResponse(analysis=results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("KAGE_AI_PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
