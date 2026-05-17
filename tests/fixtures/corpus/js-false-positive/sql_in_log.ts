// Corpus fixture — FALSE POSITIVE guard.
// The text "delete from user" appears inside log/console string arguments, NOT
// in a database call. missing-audit / missing-dsr must NOT flag these: the
// raw-SQL pattern constrains the callee ($FN) to DB-execution method names, so
// a non-DB callee like `logger` or `console` is excluded.

export function announceIntent() {
  logger.info('about to delete from users table');
  console.log('we will delete from user_audit later');
}
