"""
Flask web server for VXDF Validate.
"""
import os
import logging
import tempfile
import json
import uuid
import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from werkzeug.utils import secure_filename
from flasgger import Swagger

# Import version
try:
    # When imported as a module from outside
    from api import __version__
except ImportError:
    # When imported directly within api directory
    try:
        from __init__ import __version__
    except ImportError:
        __version__ = "1.0.0"

# Ensure models are imported first to register with declarative base
from api.models.finding import Finding, Evidence
from api.models.database import init_db, SessionLocal
from api.parsers import ParserType, get_parser
from api.core.engine import ValidationEngine

# Import config with fallback
try:
    from config import (
        TEMPLATE_DIR, STATIC_DIR, OUTPUT_DIR, SUPPORTED_VULN_TYPES,
        LOG_DIR, TEMP_DIR, DB_PATH, PROJECT_ROOT
    )
except ImportError:
    try:
        from api.config import (
            TEMPLATE_DIR, STATIC_DIR, OUTPUT_DIR, SUPPORTED_VULN_TYPES,
            LOG_DIR, TEMP_DIR, DB_PATH, PROJECT_ROOT
        )
    except ImportError:
        # Default fallbacks if config can't be imported
        from pathlib import Path
        API_DIR = Path(__file__).resolve().parent
        PROJECT_ROOT = API_DIR.parent
        TEMPLATE_DIR = PROJECT_ROOT / "templates"
        STATIC_DIR = PROJECT_ROOT / "static"
        OUTPUT_DIR = PROJECT_ROOT / "output"
        LOG_DIR = PROJECT_ROOT / "logs"
        TEMP_DIR = PROJECT_ROOT / "temp"
        DB_PATH = PROJECT_ROOT / "vxdf_validate.db"
        SUPPORTED_VULN_TYPES = []

# Configure logging at the module level
LOG_DIR = Path(__file__).parent.parent / 'logs'
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
    init_db()

    # Configure Swagger UI
    Swagger(app)

    # Register API blueprint
    from api.api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    logger.info("API blueprint registered")

    # Remove all non-API routes and template rendering

    @app.errorhandler(404)
    def page_not_found(e):
        """Handle 404 errors."""
        return jsonify({'error': 'Not found'}), 404

    @app.errorhandler(500)
    def server_error(e):
        """Handle 500 errors."""
        logger.error(f"Server error: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

    return app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    logger.info(f"Starting VXDF Validate on port {port}")
    app = create_app()
    app.run(host="0.0.0.0", port=port, debug=True)
