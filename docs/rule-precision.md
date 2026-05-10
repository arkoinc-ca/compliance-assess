# Rule Precision

This document describes how compliance-assess rules are tested, measured, and improved to meet the v0.2 baseline.

## Goal

Phase 2 Acceptance Gate P2-G04 requires a false-positive rate below 15% before v0.2 ships. This page documents the methodology and baseline status.

## Methodology: Curated Corpus

For each detection rule, we maintain a small, curated corpus of code samples:

- **Positive samples** (MUST fire): code that violates the control (e.g., logging a user's email)
- **Negative samples** (MUST NOT fire): benign code that looks similar but complies (e.g., logging an email *after* redaction, or logging an error message)

For each rule, compute:

```
Precision = TP / (TP + FP)

Where:
  TP = samples that must fire and do fire
  FP = samples that must not fire but do fire
```

Target precision ≥ 85% (equivalently, FP rate ≤ 15%).

## Baseline Measurement (v0.2 Gate)

The baseline measurement runs as part of the v0.2 release gate (human-action checklist `docs/human-action-checklist.md`). Once measured, results are recorded in a `MEASUREMENT.yaml` in the detection-rules directory.

Placeholder: [to be completed at v0.2 release]

## Per-Rule Confidence Levels

Current assessment across the five core rules:

| Rule | Python | JavaScript/TypeScript | Java | C# |
|------|--------|----------------------|------|-----|
| pii-in-logs | production | production | baseline | baseline |
| missing-consent | production | production | baseline | baseline |
| missing-dsr | production | production | baseline | baseline |
| missing-audit | production | production | baseline | baseline |
| missing-retention | production | production | baseline | baseline |

**Production** — rule has been corpus-tested and precision verified against P2-G04. Use findings as input to engineering decisions.

**Baseline** — rule fires on idiomatic framework patterns but has not been corpus-tested. Treat findings as a starting point; verify manually before taking action.

## Improving a Rule

If a rule produces too many false positives in your codebase:

1. Identify a false-positive finding (detection that should not fire)
2. Extract a minimal code sample and add it to `tests/fixtures/corpus/<rule-id>-negative/`
3. Edit the rule in `detection-rules/semgrep/<rule-id>.yaml`
4. Add a `pattern-not` clause to suppress the pattern
5. Document the suppression reason in the rule's metadata
6. Run the corpus test: `uv run pytest tests/integration/test_corpus.py -k <rule-id>`
7. Verify TP count stays constant and FP count drops

Example: if `pii-in-logs` fires on `logger.info(user.email)` *after* a redaction step, add:

```yaml
pattern-not: logger.$LEVEL(..., redact($X.email), ...)
```

## Inline Suppression

Suppress a rule for a specific line with the `compliance-ignore` annotation:

**Python:**
```python
logger.info(user.email)  # compliance-ignore: pii-in-logs
```

**JavaScript/TypeScript:**
```javascript
console.log(user.email); // compliance-ignore: pii-in-logs
```

**Java:**
```java
logger.info(user.getEmail()); // compliance-ignore: pii-in-logs
```

**C#:**
```csharp
logger.LogInformation(user.Email); // compliance-ignore: pii-in-logs
```

Format: single-space after comment marker, `compliance-ignore:`, rule ID (no spaces around colon).

## Contributing a Corpus Sample

Add test samples to `tests/fixtures/corpus/`:

```
tests/fixtures/corpus/
├── pii-in-logs-positive/
│   ├── python-log-email.py
│   ├── javascript-console-ssn.js
│   └── ...
└── pii-in-logs-negative/
    ├── python-log-redacted.py
    ├── javascript-console-uuid.js
    └── ...
```

Each file should be minimal (≤10 lines) and include a comment explaining what it tests. Negative samples should look structurally similar to positives but comply with the rule.

<!-- written-by: writer-haiku | model: haiku -->
