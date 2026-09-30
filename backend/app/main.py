from fastapi import FastAPI

from app.api.execution import router as execution_router
from app.api.fuzzing import router as fuzzing_router
from app.api.scan import router as scan_router
from app.api.targets import router as targets_router


app = FastAPI(
    title="AI-Fuzzer",
    description="Intelligent Black-Box Fuzzer for AI-Powered Applications",
    version="0.1.0",
)


app.include_router(targets_router)
app.include_router(fuzzing_router)
app.include_router(execution_router)
app.include_router(scan_router)


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
