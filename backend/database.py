import os
from sqlalchemy import create_engine, MetaData

# PostgreSQL connection URL
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:123456@127.0.0.1:5432/monitoring_db"
)

# SQLAlchemy Core Engine & MetaData
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
metadata = MetaData()

def get_db():
    """FastAPI Dependency providing a SQLAlchemy Core database Connection."""
    with engine.connect() as conn:
        yield conn

def init_db():
    """Create all defined SQLAlchemy Core tables if they do not exist."""
    metadata.create_all(bind=engine)
