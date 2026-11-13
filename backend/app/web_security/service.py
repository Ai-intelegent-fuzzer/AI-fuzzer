import hashlib
import json

from app.web_security.models import (
    WebFixture,
    WebTestCase,
    WebTestEvidence,
    WebTestRunRequest,
    WebTestRunResponse,
    WebTestStatus,
)


_FIXTURES = {
    "synthetic-webapp-vulnerable": WebFixture(
        fixture_id="synthetic-webapp-vulnerable",
        display_name="Synthetic Vulnerable Web Fixture",
        description="Deterministic in-process observations of intentionally insecure control settings; no HTTP server or exploit is run.",
    ),
    "synthetic-webapp-secure": WebFixture(
        fixture_id="synthetic-webapp-secure",
        display_name="Synthetic Secure Control Fixture",
        description="Deterministic in-process secure-control comparison fixture; no HTTP request is sent.",
    ),
}

_CASES = [
    WebTestCase(
        test_id="web_sql_parameterization",
        category="sql_injection_simulation",
        description="Checks a fixture flag representing parameterized query use.",
        expected_behavior="Synthetic database access uses parameterized query handling.",
        recommendation="Use parameterized statements and avoid composing query syntax from user input.",
    ),
    WebTestCase(
        test_id="web_reflected_output_encoding",
        category="reflected_xss_simulation",
        description="Checks a fixture flag representing contextual output encoding.",
        expected_behavior="Reflected input is rendered as inert text.",
        recommendation="Apply context-appropriate output encoding before rendering untrusted text.",
    ),
    WebTestCase(
        test_id="web_stored_output_encoding",
        category="stored_xss_simulation",
        description="Checks a fixture flag representing safe rendering of stored values.",
        expected_behavior="Stored values are rendered as inert text.",
        recommendation="Encode untrusted stored content at the output context; do not rely on storage-time filtering.",
    ),
    WebTestCase(
        test_id="web_authentication_policy",
        category="authentication_checks",
        description="Checks the fixture's authentication-required control setting.",
        expected_behavior="Protected fixture routes require an authenticated synthetic principal.",
        recommendation="Enforce authentication on every protected route and deny by default.",
    ),
    WebTestCase(
        test_id="web_authorization_policy",
        category="authorization_checks",
        description="Checks the fixture's role and resource authorization control setting.",
        expected_behavior="Protected operations require an explicit policy decision.",
        recommendation="Centralize authorization checks and test role, owner, and tenant boundaries.",
    ),
    WebTestCase(
        test_id="web_object_access_policy",
        category="idor_checks",
        description="Checks the fixture's object-level ownership control setting.",
        expected_behavior="Object access is bound to the requesting synthetic identity and tenant.",
        recommendation="Authorize every object operation using server-side owner and tenant metadata.",
    ),
    WebTestCase(
        test_id="web_security_headers",
        category="security_header_analysis",
        description="Checks configured synthetic response security headers.",
        expected_behavior="The fixture includes its required security headers.",
        recommendation="Set and verify appropriate security headers for the deployed application.",
    ),
    WebTestCase(
        test_id="web_input_validation",
        category="input_validation",
        description="Checks the fixture's strict input validation control setting.",
        expected_behavior="Inputs are validated against endpoint-specific types and bounds.",
        recommendation="Validate type, size, and allowed values at the server boundary.",
    ),
    WebTestCase(
        test_id="web_path_boundary",
        category="path_traversal_simulation",
        description="Checks the fixture's canonical path-boundary control setting.",
        expected_behavior="File access remains inside the configured synthetic fixture root.",
        recommendation="Resolve paths and verify the resulting location remains beneath an approved root.",
    ),
    WebTestCase(
        test_id="web_sensitive_response",
        category="sensitive_information_disclosure",
        description="Checks the fixture's response redaction control setting.",
        expected_behavior="Responses contain no synthetic internal diagnostic marker.",
        recommendation="Return minimal errors and redact internal implementation details.",
    ),
    WebTestCase(
        test_id="web_error_handling",
        category="improper_error_handling",
        description="Checks whether fixture errors are normalized.",
        expected_behavior="Errors use a bounded response without stack details.",
        recommendation="Use consistent error responses and keep diagnostics in protected server logs.",
    ),
    WebTestCase(
        test_id="web_session_security",
        category="session_security",
        description="Checks the fixture's session-cookie policy flags.",
        expected_behavior="Session cookies use secure, HttpOnly, and SameSite protections.",
        recommendation="Set Secure, HttpOnly, and appropriate SameSite attributes for session cookies.",
    ),
]

_VULNERABLE_FLAGS = {
    "web_sql_parameterization": False,
    "web_reflected_output_encoding": False,
    "web_stored_output_encoding": False,
    "web_authentication_policy": False,
    "web_authorization_policy": False,
    "web_object_access_policy": False,
    "web_security_headers": False,
    "web_input_validation": False,
    "web_path_boundary": False,
    "web_sensitive_response": False,
    "web_error_handling": False,
    "web_session_security": False,
}


class LocalWebSecurityFixture:
    """Runs fixed in-process control observations; it cannot send network requests."""

    def fixtures(self) -> list[WebFixture]:
        return [fixture.model_copy(deep=True) for fixture in _FIXTURES.values()]

    def tests(self) -> list[WebTestCase]:
        return [test.model_copy(deep=True) for test in _CASES]

    def run(self, request: WebTestRunRequest) -> WebTestRunResponse:
        fixture = _FIXTURES.get(request.fixture_id)
        if fixture is None:
            raise ValueError("Only the registered synthetic web fixtures are supported.")
        cases = {case.test_id: case for case in _CASES}
        unknown = set(request.test_ids) - set(cases)
        if unknown:
            raise ValueError(f"Unknown synthetic web test IDs: {', '.join(sorted(unknown))}.")
        results: list[WebTestEvidence] = []
        for test_id in dict.fromkeys(request.test_ids):
            case = cases[test_id]
            passes = fixture.fixture_id == "synthetic-webapp-secure" or _VULNERABLE_FLAGS[test_id]
            status = WebTestStatus.PASS if passes else WebTestStatus.FAIL
            observed = (
                "The controlled fixture reports the secure control enabled."
                if passes
                else "The controlled fixture reports the corresponding security control disabled."
            )
            severity = "medium" if not passes else "informational"
            confidence = "high" if not passes else "medium"
            synthetic_request = {"fixture": fixture.fixture_id, "test_id": test_id}
            synthetic_response = {
                "control_enabled": str(passes).lower(),
                "fixture_only": "true",
            }
            reference = hashlib.sha256(json.dumps(
                [synthetic_request, synthetic_response, status.value],
                sort_keys=True,
            ).encode()).hexdigest()
            results.append(WebTestEvidence(
                test_id=test_id,
                fixture_id=fixture.fixture_id,
                category=case.category,
                status=status,
                severity=severity,
                confidence=confidence,
                synthetic_request=synthetic_request,
                synthetic_response=synthetic_response,
                expected_behavior=case.expected_behavior,
                observed_behavior=observed,
                recommendation=case.recommendation,
                evidence_reference=reference,
            ))
        return WebTestRunResponse(fixture_id=fixture.fixture_id, results=results)
