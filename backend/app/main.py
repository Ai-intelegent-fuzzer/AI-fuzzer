from fastapi import FastAPI

app = FastAPI(
    title="AI-Fuzzer",
    description="Intelligent Black-Box Fuzzer for AI-Powered Applications",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "project": "AI-Fuzzer",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}
from app.api.adapter import router as adapter_router
app.include_router(adapter_router)


