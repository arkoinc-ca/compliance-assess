# compliance-assess — Dev Instructions

For general Python stack standards (uv, ruff, mypy strict, pytest patterns, async patterns, error handling), see the project root: [`.claude/CLAUDE.md`](../../.claude/CLAUDE.md).

---

## Runtime and tooling

| Component | Requirement |
|-----------|-------------|
| Python | 3.11+ |
| Package manager | `uv` (preferred) |
| Type checker | `mypy --strict` |
| Linter / formatter | `ruff check` + `ruff format` |
| Test runner | `pytest` |

---

## Repo-specific requirements

### Testing — real fixtures, not mocked tools

Semgrep and tree-sitter must be exercised against real source fixtures in tests. Do not mock semgrep invocations:

- Place test source corpora in `tests/fixtures/corpus/` — small, purpose-built files that trigger specific rules.
- Integration tests must invoke `semgrep` as a subprocess against the corpus and assert on real findings.
- Unit tests for the finding model, deduplication logic, and output adapters may use frozen fixture data.

Rationale: mocking semgrep means you test your mock, not your rule. If semgrep's behavior changes or a rule is malformed, a mocked test will never catch it.

### SARIF output validation

Every SARIF-emitting code path must be exercised by a test that validates the output against the [SARIF 2.1.0 JSON schema](https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecificationDrafts/SARIF2.1.0/sarif-schema-2.1.0.json). Use `jsonschema` for validation in tests.

### Logging

Use `structlog` for all audit-grade log output. Log at the finding and scan-summary level; do not log raw scanned-code content under any circumstances. PII may appear in scanned source; never emit it to logs.

### Error handling

Follow the `Result[Ok, Err]` pattern from `.claude/CLAUDE.md`. Scanner errors (semgrep failure, schema error, missing catalog) must surface as typed errors, not uncaught exceptions reaching the CLI.

---

## Commands

```bash
uv sync                          # Install dependencies
uv run pytest                    # Run tests
uv run pytest -v -k integration  # Run integration tests only
uv run ruff check .              # Lint
uv run ruff format .             # Format
uv run mypy .                    # Type check
```

<!-- written-by: builder-sonnet | model: sonnet -->
