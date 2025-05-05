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

# Create SQLAlchemy engine with improved error handling
try:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_recycle=300
    )
    logger.info(f"Connected to database at {DB_PATH}")
except Exception as e:
    logger.error(f"Error connecting to database: {e}")
    raise

# Create metadata with extend_existing=True to handle existing tables
metadata = MetaData()

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create base class for models with extend_existing=True
Base = declarative_base(metadata=metadata)

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
        # Import models using relative imports to avoid circular issues
        try:
            # Try relative import first
            from . import finding
        except ImportError:
            # Fall back to absolute import
            from api.models import finding
        
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully.")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        # Log but don't raise to allow server to continue running
        # This is often due to table already existing which isn't critical
