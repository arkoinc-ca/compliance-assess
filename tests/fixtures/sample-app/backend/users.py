def delete_user(user) -> None:
    """Admin endpoint: delete a user account."""
    # VIOLATION: missing-audit-python — $USER.delete() with no audit_log.write(...)
    user.delete()
