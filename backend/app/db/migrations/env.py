import os

from alembic import context

import app.models  # noqa: F401  (registers all tables on Base.metadata)
from app.db.base import Base
from app.db.session import make_engine

config = context.config
# URL comes from app startup (config.attributes) or LANWARDEN_DATABASE_URL for the alembic CLI.
url = config.attributes.get("url") or os.environ.get("LANWARDEN_DATABASE_URL", "sqlite:///data/lanwarden.db")
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True, render_as_batch=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = make_engine(url, config.attributes.get("db_key"), pragmas=False)
    with engine.connect() as connection:
        # render_as_batch: SQLite cannot ALTER most things in place
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
