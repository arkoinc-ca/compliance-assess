# Corpus fixture — TRUE POSITIVE.
# A user-record deletion with no audit-log write and no DSR mechanism.
# Expected to trigger: missing-audit-python, missing-dsr-python.


def delete_account(user):
    user.delete()
