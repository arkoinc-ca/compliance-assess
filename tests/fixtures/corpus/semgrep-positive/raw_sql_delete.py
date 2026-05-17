# Corpus fixture — TRUE POSITIVE (raw-SQL deletion).
# Exercises the raw-SQL branch of missing-dsr-python: a `DELETE FROM <user table>`
# string passed to a DB cursor's execute(), in both two-arg and one-arg forms.


def purge_parameterised(cursor, uid):
    cursor.execute("DELETE FROM users WHERE id = %s", (uid,))


def purge_single_arg(cursor):
    cursor.execute("DELETE FROM user_accounts")
