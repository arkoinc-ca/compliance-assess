// Corpus fixture for pii-in-logs-javascript: safe logging that must NOT be
// flagged. Guards against the field-name regex matching substrings such as
// 'tokenEndpoint' or 'emailProvider', or matching string literals.

interface Settings {
  tokenEndpoint: string;
  emailProvider: string;
}

export function boot(settings: Settings, requestCount: number): void {
  console.log("requests handled: " + requestCount);
  logger.info(`auth service online at ${settings.tokenEndpoint}`);
  log.debug(settings.emailProvider);
  logger.warn("account.password value is redacted before logging");
}
