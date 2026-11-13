from fastapi import APIRouter, HTTPException

from app.web_security.models import (
    WebFixture,
    WebTestCase,
    WebTestRunRequest,
    WebTestRunResponse,
)
from app.web_security.service import LocalWebSecurityFixture

router = APIRouter(prefix="/web-security", tags=["Synthetic Web Security Fixture"])
web_fixture = LocalWebSecurityFixture()


@router.get("/fixtures", response_model=list[WebFixture])
def list_web_fixtures() -> list[WebFixture]:
    return web_fixture.fixtures()


@router.get("/tests", response_model=list[WebTestCase])
def list_web_tests() -> list[WebTestCase]:
    return web_fixture.tests()


@router.post("/runs", response_model=WebTestRunResponse)
def run_web_tests(request: WebTestRunRequest) -> WebTestRunResponse:
    try:
        return web_fixture.run(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
