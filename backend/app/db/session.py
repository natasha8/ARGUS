"""Database engine and sessions."""

from collections.abc import Iterator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings

connect_args: dict = {}
if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)

if settings.database_url.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _enable_sqlite_fks(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def ensure_schema(bind: Engine | None = None) -> None:
    """Create tables, then add columns introduced after the first release.

    `create_all` does not alter an existing table. Local databases created
    before security schemes were stored gain that column here.
    """
    from app.models import Base

    target = bind or engine
    Base.metadata.create_all(bind=target)
    inspector = inspect(target)
    if "endpoints" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("endpoints")}
    if "security" in columns:
        return
    with target.begin() as connection:
        connection.execute(text("ALTER TABLE endpoints ADD COLUMN security JSON"))


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
