#!/usr/bin/env python3
"""
Main entry point for the VXDF Validate API.
"""
import os
import logging
from pathlib import Path
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add the current directory to path to help with imports
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent
sys.path.insert(0, str(project_root))

try:
    # Import server and API modules
    from server import app
    
    # Try to import and register API blueprint if not already registered
    try:
        if not any(bp.name == 'api' for bp in app.blueprints.values()):
            from api import api_bp
            app.register_blueprint(api_bp)
            logger.info("API blueprint registered")
    except ImportError:
        logger.warning("Could not import API blueprint")
    
    if __name__ == "__main__":
        port = int(os.environ.get("PORT", 5001))
        logger.info(f"Starting VXDF Validate on port {port}")
        app.run(host="0.0.0.0", port=port, debug=True)
except Exception as e:
    logger.error(f"Failed to start server: {e}", exc_info=True)
    sys.exit(1) 