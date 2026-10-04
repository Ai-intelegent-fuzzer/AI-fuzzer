# Fuzzing Subsystem

## Scope and data flow

The backend fuzzing subsystem generates controlled test cases, applies named deterministic transformations, sends requests to configured targets, and passes responses to the existing heuristic analyzer.

```text
Scan API -> in-process scheduler -> case generator -> mutation strategies
         -> target executor -> response analyzer -> metrics and coverage
```

`FuzzCase` retains the original required fields (`case_id`, `prompt`, and `category`). Optional fields identify its direct parent, strategy, mutation depth, sequence, and metadata. Mutated cases also retain `origin_case_id`, `origin_prompt`, and ancestor IDs in metadata. A test category describes what is being exercised; it is not a confirmed vulnerability classification.

## Mutation strategies

The registry in `app/fuzzing/mutator.py` provides ten deterministic transformations: instruction restructuring, role variation, context variation, direct request wording, polite wording, paraphrase-style framing, Base64 encoding, delimiter framing, instruction placement, and prefix/suffix framing. Each result records its strategy, parent, and incremented depth.

The generator defaults to one mutation level, preserving existing endpoint behavior. Callers may request up to five levels. The mutator limits each case to ten mutations; generation and scan requests are capped at 100 cases. Unknown categories and strategy names are ignored. Generated categories include prompt injection, instruction override, jailbreak, data extraction, role confusion, context manipulation/poisoning, RAG and indirect prompt injection, tool misuse, and unauthorized agent action.

Mutation prompts are for authorized security assessments only. Use synthetic/mock targets and synthetic canary data; the fuzzer does not perform tool actions or destructive operations.

## Multi-turn tests

`FuzzConversation` contains ordered `FuzzTurn` records with a conversation ID, turn number, case ID, parent, and strategy. Single-turn generation remains the default. A scan can enable `multi_turn`; each turn is sent in order, with prior user prompts and target responses included as context in the next request's `prompt` field. This preserves compatibility with adapters that accept the existing `{ "prompt": "..." }` payload. It does not claim provider-native conversation support.

## Execution and scan lifecycle

`POST /scans` creates a queued scan and runs it on a bounded in-process worker pool. Use `GET /scans/{scan_id}` for lifecycle and metrics, `GET /scans/{scan_id}/results` for case results, and `POST /scans/{scan_id}/cancel` to request cancellation. Scan records are held in memory and are lost when the application restarts; this implementation does not use a database or distributed workers.

Existing routes remain available:

- `POST /targets/{target_id}/fuzz-cases`
- `POST /targets/{target_id}/fuzz`
- `POST /targets/{target_id}/execute`

Example scan request:

```json
{
  "target_id": "registered-target-id",
  "count": 20,
  "categories": ["prompt_injection", "context_manipulation"],
  "max_mutation_depth": 2,
  "timeout_seconds": 15,
  "max_retries": 1,
  "concurrency": 2,
  "delay_seconds": 0.1,
  "multi_turn": false
}
```

The request bounds case count to 100, depth to 5, retries to 5, timeout to 120 seconds, concurrency to 8, and optional inter-case delay to 10 seconds. With multi-turn enabled, `count` is the number of conversations; otherwise it is the number of cases. Execution retries only timeouts, network errors, and HTTP 5xx responses; HTTP 4xx and unexpected exceptions are not retried. Response bodies are streamed and capped at 10,000 bytes by default. Cancellation prevents work that has not started; an in-flight HTTP request finishes or reaches its timeout before the scan becomes cancelled.

## Metrics and test-space coverage

Scan metrics include generated/executed/successful/failed counts, timeouts, retries, mutations, strategies, categories, heuristic vulnerable cases/findings, execution durations, and per-category generated/executed/vulnerable/finding counts. `FuzzingCoverage` reports categories and strategies exercised, mutation depths, unique prompts/cases, and received target responses. This is test-space coverage, not source-code coverage.

The response analyzer uses heuristic indicators. A result marked `vulnerable` or a generated finding is a **potential vulnerability** requiring review and validation; it is not mathematical proof or an automatic confirmed-vulnerability judgment. The current analyzer does not fully detect every generated category.

## Tests

Run the deterministic backend suite from the repository root:

```powershell
python -c "import sys, unittest; sys.path.insert(0, 'backend'); suite=unittest.defaultTestLoader.discover('backend/tests', pattern='test_*.py'); result=unittest.TextTestRunner(verbosity=2).run(suite); sys.exit(not result.wasSuccessful())"
```

The suite uses HTTPX mock transports and the repository's synthetic mock-target logic. It does not call external AI services.