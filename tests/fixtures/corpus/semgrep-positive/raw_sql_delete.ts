// Corpus fixture — TRUE POSITIVE (raw-SQL deletion).
// Exercises the raw-SQL branch of missing-audit-javascript and missing-dsr-javascript:
// a `DELETE FROM <user table>` string passed to a DB-execution method.

export async function purgeUser(db: any, id: string) {
  await db.query('DELETE FROM users WHERE id = $1', [id]);
}

export async function purgeViaHelper(id: string) {
  await queryWithTenantContext('DELETE FROM user_accounts WHERE id = $1', [id]);
}
