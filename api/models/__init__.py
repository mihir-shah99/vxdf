"""
Database models package for VXDF Validate.

This package contains all database models used by the application.
The import order is important to avoid circular imports:

1. Import database.py first to set up the Base
2. Import models using conditional paths
"""
import sys
from pathlib import Path

# Fix import paths - add project root to Python path
API_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = API_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

# Import Base and DB utilities first with path resolution
try:
    from api.models.database import Base, SessionLocal, init_db, get_db
    from api.models.finding import Finding, Evidence
except ImportError:
    # Fallback for running from api directory
    from models.database import Base, SessionLocal, init_db, get_db
    from models.finding import Finding, Evidence

__all__ = [
    'Base', 'SessionLocal', 'init_db', 'get_db',
    'Finding', 'Evidence'
]
