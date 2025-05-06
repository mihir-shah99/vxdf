"""
Database configuration and connection management for VXDF Validate.
"""
import os
import logging
from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from pathlib import Path

# Try different import paths for config
try:
    from config import DATABASE_URL, DB_PATH
except ImportError:
    try:
        from api.config import DATABASE_URL, DB_PATH
    except ImportError:
        # Default fallbacks if config can't be imported
        API_DIR = Path(__file__).resolve().parent.parent
        PROJECT_ROOT = API_DIR.parent
        DB_PATH = PROJECT_ROOT / "vxdf_validate.db"
        DATABASE_URL = f"sqlite:///{DB_PATH}"

logger = logging.getLogger(__name__)

# Create metadata with naming convention
metadata = MetaData(naming_convention={
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
})

# Create base class for models
Base = declarative_base(metadata=metadata)

# Create SQLAlchemy engine with improved error handling
try:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_recycle=300,
        connect_args={"check_same_thread": False}  # Required for SQLite
    )
    logger.info(f"Connected to database at {DB_PATH}")
except Exception as e:
    logger.error(f"Error connecting to database: {e}")
    raise

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """
    Get a database session.
    
    Yields:
        SQLAlchemy Session: Database session
    """
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

def init_db():
    """
    Initialize the database, creating tables if they don't exist.
    """
    try:
        # Import models here to avoid circular imports
        from api.models.finding import Finding, Evidence
        
        # Create tables
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully.")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise  # Raise the error to ensure we know if initialization fails
