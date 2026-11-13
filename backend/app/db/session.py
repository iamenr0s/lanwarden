from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker


def make_engine(url: str, db_key: bytes | None = None, *, pragmas: bool = True) -> Engine:
    """`db_key` (32 bytes) opens an SQLCipher-encrypted SQLite file; None is plain SQLite. `pragmas=False` is
    for Alembic, whose batch migrations must not run with foreign keys enforced."""
    kwargs: dict = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        if db_key:
            import sqlcipher3.dbapi2 as sqlcipher  # imported only when encryption is on

            kwargs["module"] = sqlcipher
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _setup(dbapi_conn, _):  # noqa: ANN001
            cur = dbapi_conn.cursor()
            if db_key:  # must be the first statement on the connection; hex only, so nothing to escape
                cur.execute(f"PRAGMA key = \"x'{db_key.hex()}'\"")
                cur.execute("SELECT count(*) FROM sqlite_master")  # fails here, clearly, on a wrong key
            if pragmas:
                cur.execute("PRAGMA foreign_keys=ON")
                cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)
