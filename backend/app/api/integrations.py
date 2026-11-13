from fastapi import APIRouter, HTTPException, Query, status

from app.database.store import database
from app.integrations.models import (
    IntegrationExecutionAudit,
    IntegrationExecutionRequest,
    IntegrationExecutionResult,
    IntegrationMetadata,
    IntegrationSecurityTestRequest,
    IntegrationSecurityTestResult,
    SyntheticIntegration,
    SyntheticIntegrationCreate,
)
from app.integrations.service import IntegrationService

router = APIRouter(prefix="/integrations", tags=["Synthetic Integrations"])
integration_service = IntegrationService(database)


@router.get("", response_model=list[IntegrationMetadata])
def list_integrations() -> list[IntegrationMetadata]:
    return [
        IntegrationMetadata.from_integration(item)
        for item in integration_service.list_integrations()
    ]


@router.post(
    "",
    response_model=IntegrationMetadata,
    status_code=status.HTTP_201_CREATED,
)
def create_integration(data: SyntheticIntegrationCreate) -> IntegrationMetadata:
    try:
        integration = integration_service.register(data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return IntegrationMetadata.from_integration(integration)


@router.post(
    "/security-tests",
    response_model=IntegrationSecurityTestResult,
    status_code=status.HTTP_201_CREATED,
)
def run_integration_security_test(
    request: IntegrationSecurityTestRequest,
) -> IntegrationSecurityTestResult:
    try:
        return integration_service.run_security_test(request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/security-tests", response_model=list[IntegrationSecurityTestResult])
def list_integration_security_results(
    limit: int = Query(default=100, ge=1, le=500),
) -> list[IntegrationSecurityTestResult]:
    return integration_service.list_security_results(limit)


@router.get("/audits", response_model=list[IntegrationExecutionAudit])
def list_integration_audits(
    limit: int = Query(default=100, ge=1, le=500),
) -> list[IntegrationExecutionAudit]:
    return integration_service.list_audits(limit)


@router.post(
    "/{integration_id}/execute",
    response_model=IntegrationExecutionResult,
    status_code=status.HTTP_201_CREATED,
)
def execute_integration(
    integration_id: str,
    request: IntegrationExecutionRequest,
) -> IntegrationExecutionResult:
    try:
        return integration_service.execute(integration_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{integration_id}", response_model=IntegrationMetadata)
def get_integration(integration_id: str) -> IntegrationMetadata:
    integration = integration_service.get_integration(integration_id)
    if integration is None:
        raise HTTPException(status_code=404, detail="Synthetic integration not found.")
    return IntegrationMetadata.from_integration(integration)
