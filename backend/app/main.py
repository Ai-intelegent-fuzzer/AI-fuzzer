from pathlib import Path
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from fastapi import FastAPI

from app.api.adapter import router as adapter_router
from app.api.attacks import router as attacks_router
from app.api.authorization import router as authorization_router
from app.api.connectivity import router as connectivity_router
from app.api.execution import router as execution_router
from app.api.integrations import router as integrations_router
from app.api.fuzzing import router as fuzzing_router
from app.api.scan import router as scan_router
from app.api.scan import scan_lifecycle_router
from app.api.reports import router as reports_router
from app.api.rag import router as rag_router
from app.api.targets import router as targets_router
from app.api.tools import router as tools_router
from app.api.vector_store import router as vector_store_router
from app.api.agent_memory import router as agent_memory_router
from app.api.web_security import router as web_security_router
from app.database.store import database


@asynccontextmanager
async def lifespan(_app: FastAPI):
    database.initialize()
    database.recover_incomplete_scans()
    yield


app = FastAPI(
    title="AI-Fuzzer",
    description="Intelligent Black-Box Fuzzer for AI-Powered Applications",
    version="0.1.0",
    lifespan=lifespan,
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
app.include_router(attacks_router)
app.include_router(authorization_router)
app.include_router(rag_router)
app.include_router(tools_router)
app.include_router(vector_store_router)
app.include_router(agent_memory_router)
app.include_router(web_security_router)
app.include_router(integrations_router)
app.include_router(adapter_router)
app.include_router(connectivity_router)
app.include_router(fuzzing_router)
app.include_router(execution_router)
app.include_router(scan_router)
app.include_router(scan_lifecycle_router)
app.include_router(reports_router)
