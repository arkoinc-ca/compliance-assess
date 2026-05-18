# Corpus fixture for pii-in-logs-python: safe logging that must NOT be flagged.
# Guards against the field-name regex matching substrings such as
# 'token_endpoint' or 'email_provider'.


def boot(cfg, request_count):
    logger.info("requests handled: " + str(request_count))
    logger.info(f"auth service online at {cfg.token_endpoint}")
    log.debug(cfg.email_provider)
