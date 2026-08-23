import os
from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker, declarative_base

# PostgreSQL connection URL
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:123456@127.0.0.1:5432/monitoring_db"
)

# SQLAlchemy Core Engine & MetaData
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
metadata = MetaData()

# ORM Session Local & Base
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db_connection():
    """Returns a raw connection from the SQLAlchemy Core engine pool."""
    connection = engine.connect()
    try:
        yield connection
    finally:
        connection.close()

def get_db():
    """FastAPI Dependency providing a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Create all defined tables if they do not exist."""
    metadata.create_all(bind=engine)
    try:
        Base.metadata.create_all(bind=engine)
    except Exception:
        pass
