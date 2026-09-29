from fastapi import FastAPI

from app.api.targets import router as targets_router
from app.api.connectivity import router as connectivity_router
from app.api.fuzzing import router as fuzzing_router
from app.api.execution import router as execution_router

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

app.include_router(targets_router)
app.include_router(connectivity_router)
app.include_router(fuzzing_router)
app.include_router(execution_router)


