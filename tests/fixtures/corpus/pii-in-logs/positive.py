# Corpus fixture for pii-in-logs-python: PII reaching a logger via string
# concatenation, f-string substitution, a multi-argument call, and direct
# member access. Every log line below must produce a finding.
import logging

logger = logging.getLogger(__name__)


def audit(user, otp):
    logger.info("verification code sent to " + user.phone)
    logger.warning(f"otp {otp} issued for {user.email}")
    logger.error("failed login attempt", user.password)
    log.debug(user.ssn)
