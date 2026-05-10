from .logging_config import log_user_login


def send_email(user, subject: str, body: str) -> None:
    """Send a marketing email."""
    print(f"sending '{subject}' to {user.email}")


def signup_and_market(user) -> None:
    log_user_login(user)
    # VIOLATION: missing-consent-python — send_email($USER, ...) with no consent guard
    send_email(user, "Welcome!", "Buy our stuff")
