from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str]
    password: Mapped[str]
    # VIOLATION: missing-retention-python — no retention_policy / __retention__ / deleted_at / expires_at

    def delete(self) -> None:
        """Stub: remove this user from the DB."""
        pass
