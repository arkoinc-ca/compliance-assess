import logging

logger = logging.getLogger("sample-app")
logger.setLevel(logging.INFO)


def log_user_login(user) -> None:
    # VIOLATION: pii-in-logs-python — logger.$LEVEL($X.email) and logger.$LEVEL($X.password)
    logger.info(user.email)
    logger.info(user.password)
