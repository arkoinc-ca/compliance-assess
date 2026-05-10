# Supported Languages

compliance-assess detects compliance gaps in multiple languages. This page describes coverage, confidence levels, and roadmap.

## Overview

| Language | Confidence | Rules | Framework Coverage | Notes |
|----------|-----------|-------|-------------------|-------|
| Python | production | all 5 | FastAPI, SQLAlchemy, structlog, logging | Well-tested against PIPEDA, GDPR |
| JavaScript / TypeScript | production | all 5 | Express, console, Mongoose, Sequelize | ES6+ and CommonJS dialects |
| Java | baseline (v0.2) | all 5 | SLF4J, JPA, Spring Framework | Idiomatic patterns only; FP rate not measured |
| C# | baseline (v0.2) | all 5 | Microsoft.Extensions.Logging, EF Core | Async/await patterns; FP rate not measured |

The five core rules: `pii-in-logs`, `missing-consent`, `missing-dsr`, `missing-audit`, `missing-retention`.

## What "Production" Means

Rules are corpus-tested against positive and negative samples. Precision is measured and verified to meet Phase 2 Acceptance Gate P2-G04 (false-positive rate ≤ 15%). Use findings with confidence; they reflect compliance gaps in your code.

See `rule-precision.md` for methodology and baseline.

## What "Baseline" Means

Rules fire on common, idiomatic framework patterns but have not been corpus-tested. False-positive rate is unknown. Treat findings as a technical starting point; verify the finding manually before taking action or making code changes.

Baseline coverage will expand to full production in v1.0 after corpus measurement and tuning.

## Why These Four Languages

These languages cover the typical enterprise tech stack for the target audience:

- **Python**: dominant in Canadian fintech and SaaS backends
- **JavaScript/TypeScript**: standard for web and Node.js services
- **Java**: required for integration with legacy enterprise systems (banking, insurance)
- **C#**: prevalent in Microsoft-centric enterprises and .NET shops

## Languages NOT Covered in v0.2

The following are in the roadmap for v1.0+ ; open an issue to request prioritization:

- Go
- Ruby
- PHP
- Rust
- Kotlin
- Swift

## Adding a New Language

To add a new language (e.g., Go) to an existing rule:

1. Edit `compliance-catalog/detection-rules/semgrep/<rule-id>.yaml`
2. Add a new `rules` entry with `languages: [go]`
3. Write semgrep patterns targeting Go idioms (goroutines, loggers, ORM patterns)
4. Add positive and negative samples to `tests/fixtures/corpus/`
5. Run the corpus test: `uv run pytest tests/integration/test_corpus.py`
6. Verify precision ≥ 85% before submitting a pull request

Example (pii-in-logs for Go):

```yaml
- id: pii-in-logs-go
  languages: [go]
  severity: WARNING
  message: |
    Potential PII in log statement. Redact sensitive fields before logging.
  pattern-either:
    - pattern: log.Printf(..., user.Email, ...)
    - pattern: log.Println(..., user.Email, ...)
```

Semgrep supports most common languages via tree-sitter. Check [semgrep docs](https://semgrep.dev/docs/supported-languages/) for syntax and limitations.

<!-- written-by: writer-haiku | model: haiku -->
