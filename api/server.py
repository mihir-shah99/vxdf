"""
Flask web server for VXDF Validate.
"""
import os
import sys
import logging
import tempfile
import json
import uuid
import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

# Fix import paths - add project root to Python path
API_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = API_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from werkzeug.utils import secure_filename
from flasgger import Swagger

# Import version with fallback
try:
    from api import __version__
except ImportError:
    try:
        from __init__ import __version__
    except ImportError:
        __version__ = "1.0.0"

# Import models with path resolution
try:
    from api.models.finding import Finding, Evidence
    from api.models.database import init_db, SessionLocal
    from api.parsers import ParserType, get_parser
    from api.core.engine import ValidationEngine
except ImportError:
    # Fallback for running from api directory
    from models.finding import Finding, Evidence
    from models.database import init_db, SessionLocal
    from parsers import ParserType, get_parser
    from core.engine import ValidationEngine

# Import config with comprehensive fallback
try:
    from api.config import (
        TEMPLATE_DIR, STATIC_DIR, OUTPUT_DIR, SUPPORTED_VULN_TYPES,
        LOG_DIR, TEMP_DIR, DB_PATH, PROJECT_ROOT as CONFIG_PROJECT_ROOT
    )
    PROJECT_ROOT = CONFIG_PROJECT_ROOT
except ImportError:
    try:
        from config import (
            TEMPLATE_DIR, STATIC_DIR, OUTPUT_DIR, SUPPORTED_VULN_TYPES,
            LOG_DIR, TEMP_DIR, DB_PATH, PROJECT_ROOT as CONFIG_PROJECT_ROOT
        )
        PROJECT_ROOT = CONFIG_PROJECT_ROOT
    except ImportError:
        # Default fallbacks if config can't be imported
        TEMPLATE_DIR = PROJECT_ROOT / "templates"
        STATIC_DIR = PROJECT_ROOT / "static"
        OUTPUT_DIR = PROJECT_ROOT / "output"
        LOG_DIR = PROJECT_ROOT / "logs"
        TEMP_DIR = PROJECT_ROOT / "temp"
        DB_PATH = PROJECT_ROOT / "vxdf_validate.db"
        SUPPORTED_VULN_TYPES = []

# Configure logging at the module level
LOG_DIR = Path(LOG_DIR) if isinstance(LOG_DIR, str) else LOG_DIR
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "vxdf_validate.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24))

    # Initialize database
    logger.info("Initializing database...")
    init_db()
    logger.info("Database initialized successfully")

    # Configure Swagger UI
    Swagger(app)

    # Register API blueprint with error handling
    try:
        from api.api import api_bp
        logger.info("Importing API blueprint from api.api")
    except ImportError:
        from api import api_bp
        logger.info("Importing API blueprint from api")
    except ImportError:
        # Last resort - try relative import
        from .api import api_bp
        logger.info("Importing API blueprint from relative api")
    
    app.register_blueprint(api_bp, url_prefix='/api')
    logger.info("API blueprint registered successfully")

    @app.errorhandler(404)
    def page_not_found(e):
        """Handle 404 errors."""
        return jsonify({'error': 'Not found'}), 404

    @app.errorhandler(500)
    def server_error(e):
        """Handle 500 errors."""
        logger.error(f"Server error: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

    @app.route('/health')
    def health_check():
        """Health check endpoint."""
        return jsonify({
            'status': 'healthy',
            'version': __version__,
            'timestamp': datetime.datetime.now().isoformat()
        })

    return app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    logger.info(f"Starting VXDF Validate server on port {port}")
    logger.info(f"Project root: {PROJECT_ROOT}")
    logger.info(f"API directory: {API_DIR}")
    logger.info(f"Python path: {sys.path[:3]}...")  # Show first 3 entries
    
    try:
        app = create_app()
        logger.info("✅ Server created successfully")
        app.run(host="0.0.0.0", port=port, debug=True)
    except Exception as e:
        logger.error(f"❌ Failed to start server: {e}", exc_info=True)
        sys.exit(1)
