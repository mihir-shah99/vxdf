#!/usr/bin/env python3
"""
Main entry point for the VXDF Validate API.
"""
import os
import sys
import logging
import argparse
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Fix import paths - add project root to Python path
API_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = API_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

try:
    # Import server and API modules with path resolution
    try:
        from api.server import create_app
        from api.api import api_bp
        logger.info("Imported from api.* (project root context)")
    except ImportError:
        from server import create_app
        from api import api_bp
        logger.info("Imported from local modules (api directory context)")
    
    # Create the Flask app
    app = create_app()
    logger.info("✅ Flask app created successfully")
    
    if __name__ == "__main__":
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='VXDF Validate API Server')
        parser.add_argument('--port', type=int, default=6789, help='Port to run the server on')
        args = parser.parse_args()
        
        # Use the port from command line arguments
        port = args.port
        logger.info(f"Starting VXDF Validate on port {port}")
        logger.info(f"Project root: {PROJECT_ROOT}")
        logger.info(f"API directory: {API_DIR}")
        
        app.run(host="0.0.0.0", port=port, debug=True)
        
except Exception as e:
    logger.error(f"❌ Failed to start server: {e}", exc_info=True)
    sys.exit(1) 