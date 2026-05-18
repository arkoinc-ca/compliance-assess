// Corpus fixture for pii-in-logs-javascript: PII reaching a logger via string
// concatenation, template-literal substitution, a multi-argument call, and
// direct member access. Every log line below must produce a finding.

interface Account {
  email: string;
  phone: string;
  password: string;
}

export function audit(account: Account, otp: string): void {
  // String concatenation
  console.log("verification code sent to " + account.phone);
  // Template-literal substitution
  logger.info(`otp ${otp} issued for ${account.email}`);
  // Multi-argument call
  logger.warn("failed login attempt", account.password);
  // Direct member access (the original rule already caught this)
  log.debug(account.email);
}
