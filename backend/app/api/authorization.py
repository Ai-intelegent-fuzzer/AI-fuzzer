from fastapi import APIRouter, HTTPException, Query, status

from app.authorization.models import (
    AuthorizationCheckRequest,
    AuthorizationScenarioRequest,
    AuthorizationTestResult,
    SyntheticIdentity,
    SyntheticIdentityCreate,
    SyntheticIdentityUpdate,
    SyntheticResource,
)
from app.authorization.service import AuthorizationService
from app.database.store import database

router = APIRouter(tags=["Synthetic Authorization"])
authorization_service = AuthorizationService(database)


@router.get("/identities", response_model=list[SyntheticIdentity])
def list_identities() -> list[SyntheticIdentity]:
    return database.list_identities()


@router.post(
    "/identities",
    response_model=SyntheticIdentity,
    status_code=status.HTTP_201_CREATED,
)
def create_identity(identity_data: SyntheticIdentityCreate) -> SyntheticIdentity:
    identity = identity_data.to_identity()
    database.create_identity(identity)
    return identity


@router.get("/identities/{identity_id}", response_model=SyntheticIdentity)
def get_identity(identity_id: str) -> SyntheticIdentity:
    identity = database.get_identity(identity_id)
    if identity is None:
        raise HTTPException(status_code=404, detail="Synthetic identity not found")
    return identity


@router.patch("/identities/{identity_id}", response_model=SyntheticIdentity)
def update_identity(
    identity_id: str,
    assignments: SyntheticIdentityUpdate,
) -> SyntheticIdentity:
    identity = database.update_identity_assignments(
        identity_id,
        assignments.roles,
        assignments.permissions,
    )
    if identity is None:
        raise HTTPException(status_code=404, detail="Synthetic identity not found")
    return identity


@router.get("/authorization/resources", response_model=list[SyntheticResource])
def list_synthetic_resources() -> list[SyntheticResource]:
    return database.list_synthetic_resources()


@router.post(
    "/authorization/check",
    response_model=AuthorizationTestResult,
    status_code=status.HTTP_201_CREATED,
)
def check_synthetic_authorization(
    request: AuthorizationCheckRequest,
) -> AuthorizationTestResult:
    return authorization_service.check(request)


@router.post(
    "/authorization/tests",
    response_model=AuthorizationTestResult,
    status_code=status.HTTP_201_CREATED,
)
def run_authorization_scenario(
    request: AuthorizationScenarioRequest,
) -> AuthorizationTestResult:
    return authorization_service.run_scenario(request.scenario)


@router.get("/authorization/tests", response_model=list[AuthorizationTestResult])
def list_authorization_tests(
    limit: int = Query(default=100, ge=1, le=500),
) -> list[AuthorizationTestResult]:
    return authorization_service.list_tests(limit)


@router.get(
    "/authorization/tests/{test_id}",
    response_model=AuthorizationTestResult,
)
def get_authorization_test(test_id: str) -> AuthorizationTestResult:
    result = authorization_service.get_test(test_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Authorization test not found")
    return result
