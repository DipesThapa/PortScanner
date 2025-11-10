from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Iterator

from sqlmodel import Session, SQLModel, create_engine

DEFAULT_DB_PATH = Path("web_runs/webapp.db")


def get_engine(db_path: Path = DEFAULT_DB_PATH):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})


engine = get_engine()


def _ensure_column(engine, table: str, column: str, ddl: str) -> None:
    with engine.connect() as conn:
        result = conn.exec_driver_sql(f"PRAGMA table_info('{table}')")
        existing = {row[1] for row in result.fetchall()}
        if column not in existing:
            conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def init_db():
    SQLModel.metadata.create_all(engine)
    _ensure_column(engine, "scanrecord", "vulnerabilities_json", "VARCHAR")


@contextmanager
def get_session() -> Iterator[Session]:
    with Session(engine, expire_on_commit=False) as session:
        yield session


@asynccontextmanager
async def lifespan(app):
    init_db()
    yield
