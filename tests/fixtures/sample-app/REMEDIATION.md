# Remediation Guide

Each section identifies the violation, shows replacement code, explains the fix, and cites the
relevant control IDs.

---

## 1. pii-in-logs — `backend/logging_config.py`

**Violation (line 9-10):** `logger.info(user.email)` and `logger.info(user.password)` pass raw PII
fields directly to the log sink.

**Fix:**

```python
import logging

logger = logging.getLogger("sample-app")
logger.setLevel(logging.INFO)


def log_user_login(user) -> None:
    # Redact PII — log only a masked identifier
    masked = user.email[:2] + "***" if user.email else "unknown"
    logger.info("user login: %s", masked)
```

Redact or mask PII before writing to any log sink. Use structured logging with a built-in
redaction filter (e.g., `structlog` with a `censor_keys` processor) so PII never reaches the
log stream regardless of call site.

**Controls:** CA-PIPEDA-007, EU-GDPR-014, CA-QC-LAW25-016, US-CA-CCPA-011, CA-AB-PIPA-006,
CA-BC-PIPA-006

---

## 2. missing-consent — `backend/auth.py`

**Violation (line 11):** `send_email(user, "Welcome!", "Buy our stuff")` is called with no
preceding `if user.consent_marketing:` guard.

**Fix:**

```python
from .logging_config import log_user_login


def send_email(user, subject: str, body: str) -> None:
    """Send a marketing email only when consent is confirmed."""
    print(f"sending '{subject}' to {user.email}")


def signup_and_market(user) -> None:
    log_user_login(user)
    # Gate on explicit consent before sending any commercial message
    if user.consent_marketing:
        send_email(user, "Welcome!", "Buy our stuff")
```

CASL, GDPR Art. 6, and PIPEDA require freely given, specific, informed, and unambiguous consent
before sending commercial electronic messages. Store the consent flag at signup and check it
every time a CEM is sent.

**Controls:** EU-GDPR-001, EU-GDPR-004, CA-PIPEDA-003, CA-CASL-001, CA-QC-LAW25-007,
CA-AB-PIPA-002, CA-BC-PIPA-002

---

## 3. missing-dsr — `backend/main.py`

**Violation:** The FastAPI application registers `/signup` and `/admin/users/{user_id}` but
exposes no data-subject-request endpoint (`/dsr`, `/data-rights`, `/users/me/data`, or
`/users/me/delete`).

**Fix:**

```python
@app.get("/users/me/data")
def export_my_data(current_user_id: int) -> dict:
    """DSR: return all personal data held for the authenticated user."""
    # Fetch and return user record, processing logs, consent records, etc.
    return {"user_id": current_user_id, "data": {}}


@app.delete("/users/me/delete")
def delete_my_account(current_user_id: int) -> dict[str, str]:
    """DSR: permanently erase the authenticated user's personal data."""
    user = User(id=current_user_id)  # type: ignore[call-arg]
    delete_user(user)
    return {"status": "erased"}
```

GDPR Arts. 15-17, PIPEDA Principle 9, CCPA §1798.105, and Quebec Law 25 s.27 all require a
documented, user-accessible mechanism for access, erasure, correction, and portability requests.

**Controls:** EU-GDPR-007, EU-GDPR-008, CA-PIPEDA-009, CA-QC-LAW25-017, US-CA-CCPA-001,
US-CA-CCPA-002, CA-AB-PIPA-005, CA-BC-PIPA-005

---

## 4. missing-audit — `backend/users.py`

**Violation (line 4):** `user.delete()` is called with no preceding `audit_log.write(...)` call.
Destructive operations must be journalled before execution.

**Fix:**

```python
import audit_log  # your audit-log client


def delete_user(user) -> None:
    """Admin endpoint: delete a user account."""
    audit_log.write(
        actor="admin",
        target=user.id,
        operation="user.delete",
    )
    user.delete()
```

Write the actor, target, operation, and timestamp to a tamper-resistant audit store **before**
performing the irreversible action. GDPR Art. 30 (RoPA), PIPEDA Principle 1, CASL consent-record
requirements, and Quebec Law 25 governance obligations all require retaining records of data
processing activities.

**Controls:** CA-PIPEDA-001, CA-QC-LAW25-001, EU-GDPR-011, US-CA-CCPA-008, CA-CASL-006

---

## 5. missing-retention — `backend/models.py`

**Violation (line 8):** The `User` SQLAlchemy model class inheriting from `Base` has no
`retention_policy`, `__retention__`, `deleted_at`, `expires_at`, or `purge_after_days` attribute.

**Fix:**

```python
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import DateTime
import datetime


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    retention_policy = "delete-after-3-years"  # satisfies the rule

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str]
    password: Mapped[str]
    expires_at: Mapped[datetime.datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.datetime.utcnow() + datetime.timedelta(days=1095),
    )
```

PIPEDA Principle 5, GDPR Art. 5(1)(e) (storage limitation), CCPA notice-at-collection, and
Quebec Law 25 s.23 all require that personal data be destroyed or anonymised once the purpose
for which it was collected has been fulfilled. Declare a `retention_policy` class attribute and
pair it with an `expires_at` column so a scheduled purge job can enforce the schedule.

**Controls:** CA-PIPEDA-005, EU-GDPR-003, CA-QC-LAW25-022, US-CA-CCPA-007

---

## After remediation

Re-run the scan to verify zero findings remain:

```bash
compliance-assess scan tests/fixtures/sample-app \
  --profile ../compliance-catalog/profiles/use-case/saas-canada-b2c.yaml \
  --catalog ../compliance-catalog \
  --format markdown
```

All 5 rules should now report 0 findings. If any finding persists, re-read the rule file under
`../compliance-catalog/detection-rules/semgrep/` and ensure your replacement code does not
accidentally reproduce a pattern that the rule's `pattern-either` still matches.
