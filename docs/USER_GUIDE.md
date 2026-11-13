# User guide

## Start locally on Windows

Start the backend in one PowerShell window:

```powershell
Set-Location D:\AI-fuzzer-1\backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Start the frontend in another:

```powershell
Set-Location D:\AI-fuzzer-1\AI-Fuzzer\frontend
npm run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:5173`. Backend health and OpenAPI are at `http://127.0.0.1:8000/health` and `http://127.0.0.1:8000/docs`.

If dependencies are missing, install them from the repository root with `.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt`; in the frontend directory use `npm install`. Do not share or paste API keys.

## Synthetic application security lab

1. Open **Application Security Lab** from the navigation.
2. Review the synthetic identity, resource, RAG document, vector collection, tool/MCP, and connector metadata.
3. Select a target to see category applicability based on its configured scope and capabilities.
4. Select a synthetic identity for tool or connector scenarios.
5. Run one of the clearly labeled synthetic scenarios and review the expected/actual decision, outcome, and audit reference.
6. Use **Refresh fixtures** to reload persisted local fixture data.
7. Search a local vector collection with the selected synthetic identity or inspect that identity's authorized memory metadata.
8. Run a fixed web-control simulation against one of the local fixtures. It does not contact or scan a host.

Scenario execution through this lab uses local synthetic services and does not submit prompts to configured model providers. Vector similarity uses deterministic token hashing rather than semantic embeddings. Avoid adding non-synthetic content: fixture models validate synthetic namespaces and markers.

## Target and scan workflow

Target management and scans can invoke configured endpoints. Use only a target you own or have explicit permission to assess. To keep a workflow entirely local, use a controlled loopback mock endpoint and an isolated database. Do not select the configured Groq target or any public provider for a synthetic verification.

1. Add a target with a controlled endpoint.
2. Review its scope and capability profile; enable only capabilities that are actually in scope.
3. Open **New Scan**, select supported categories, set a bounded case count and timeout, and confirm authorization.
4. Review the scan's status, requested/applicable/not-applicable coverage, executed cases, and findings.
5. Open findings and reports to inspect evidence and provenance. Do not treat a zero-finding report as proof of security.

## Credentials and storage

Provider credentials are not synthetic identity credentials. The app does not return target keys in normal target responses. Configure a credential-encryption key before storing provider keys, restrict access to the backend database and environment, and never commit `.env` files.

The default database resides at `%LOCALAPPDATA%\AI-Fuzzer\ai_fuzzer.sqlite3`. For tests, prefer `AI_FUZZER_DATABASE_URL=sqlite://` or a dedicated temporary file.

## Exports and reports

Reports can be viewed/exported from **Reports**. The report data comes from stored scan results. Browser printing can be used to save a PDF; the backend does not create a server-side PDF. Report coverage and evidence are limited to what was actually recorded.
