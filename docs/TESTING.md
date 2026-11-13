# Testing and isolated validation

All commands below are for local test fixtures. Backend endpoint tests require local fixture targets; set explicit test-only endpoint policy allowances and redirect the application database to SQLite memory before running the suite.

## Backend suite

From PowerShell:

```powershell
Set-Location D:\AI-fuzzer-1\backend
$env:AI_FUZZER_DATABASE_URL = "sqlite://"
$env:AI_FUZZER_ALLOWED_PROVIDER_HOSTS = "controlled.test,synthetic.test,custom.example.test,127.0.0.1,localhost"
$env:AI_FUZZER_ALLOW_PRIVATE_TARGETS = "1"
python -m unittest discover -s tests
```

These environment settings are for test execution only. Do not copy the private-target allowance into a deployed service. Tests mock provider HTTP calls and use loopback/local synthetic fixtures; no live provider call was made in the validation recorded in [FINAL_VALIDATION_REPORT](./FINAL_VALIDATION_REPORT.md).

Focused authorization/tool checks:

```powershell
python -m unittest discover -s tests -p test_tools.py -v
python -m unittest discover -s tests -p test_authorization.py -v
python -m unittest discover -s tests -p test_gap_closure.py -v
```

The tool tests cover consistent and inconsistent operation flags, unknown operations, built-in definitions, malformed persisted definitions, authorization, client-claim resistance, state preservation, and audit records. Migration tests use temporary SQLite databases and verify historical record preservation.
The gap-closure tests cover vector authorization/auditing, agent-memory ownership/session/expiry, the fixed local web fixture, API validation, and schema version 10 with historical target/scan/finding preservation.

## Frontend suite

```powershell
Set-Location D:\AI-fuzzer-1\AI-Fuzzer\frontend
npm test
npm run lint
npm run build
```

The frontend test command uses Vitest; the build runs TypeScript project checks and Vite production bundling.

Latest local validation: 240 backend tests passed; the frontend suite passed 10 tests across 3 files; lint and the TypeScript/Vite production build passed. The build emits a non-failing large-chunk advisory. Run the commands above to repeat validation in an isolated environment.

## Validation boundaries

- Do not set `AI_FUZZER_DATABASE_URL` to the normal working database for tests.
- Do not run scans against public or third-party hosts.
- Do not use the configured Groq target for tests.
- A `TestClient` scan test uses the local controlled test server and mocked adapters; it does not establish that real-provider inference works.
- Migration tests create isolated databases; never reset or delete a user database to validate migrations.
- A successful test suite cannot prove that every attack category is effective against arbitrary applications.
- Vector ranking uses deterministic hashed-token vectors; fixture web-control results do not represent scans of real hosts.
