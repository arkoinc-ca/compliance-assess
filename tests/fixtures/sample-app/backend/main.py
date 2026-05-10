from fastapi import FastAPI

from .auth import signup_and_market
from .models import User
from .users import delete_user

app = FastAPI(title="Sample App")


@app.get("/")
def root() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/signup")
def signup(email: str, password: str) -> dict[str, str]:
    user = User(email=email, password=password)
    signup_and_market(user)
    return {"id": "new"}


@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: int) -> dict[str, str]:
    user = User(id=user_id)  # type: ignore[call-arg]
    delete_user(user)
    return {"status": "deleted"}


# VIOLATION: missing-dsr-python — no /dsr, /data-rights, or /users/me/delete endpoint
