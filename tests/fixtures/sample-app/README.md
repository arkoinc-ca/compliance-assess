# Sample App: Vulnerable Compliance Demo

A deliberately-non-compliant FastAPI backend + minimal JS frontend used by the
`compliance-assess` quickstart tutorial. Every file in this app violates at
least one compliance rule from the catalog.

## What this app is

A toy "user dashboard" that:
- Lets users sign up (no consent capture)
- Sends marketing email to all users (no consent check)
- Stores user PII (no retention policy)
- Logs raw user data (PII in logs)
- Allows admin user deletion (no audit trail)
- Has no data-subject-request endpoint

## Quick scan

From the repository root:

```bash
compliance-assess scan tests/fixtures/sample-app \
  --profile ../compliance-catalog/profiles/use-case/saas-canada-b2c.yaml \
  --catalog ../compliance-catalog \
  --format markdown
```

You should see at least 1 finding for each of the 5 rules.

## Expected findings (production-confidence rules)

| Rule | File:line (approx) | Why it fires |
|---|---|---|
| pii-in-logs | backend/logging_config.py:9 | logger.info(user.email) |
| missing-consent | backend/auth.py:11 | send_email(user, ...) no consent gate |
| missing-dsr | backend/main.py | FastAPI app has no /dsr or /users/me/delete |
| missing-audit | backend/users.py:4 | user.delete() with no audit_log.write() |
| missing-retention | backend/models.py:8 | SQLAlchemy User model with no retention_policy |

## Remediation

See [REMEDIATION.md](./REMEDIATION.md) for one-paragraph fixes for each finding.

## Provenance

This is a teaching artifact. Do not deploy.
