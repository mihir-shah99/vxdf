#!/usr/bin/env python3
"""
Main entry point for the VXDF Validate API.
"""
import os
import logging
import argparse
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
    from api.server import app
    from api.api import api_bp
    
    # Register API blueprint
    app.register_blueprint(api_bp, url_prefix='/api')
    logger.info("API blueprint registered")
    
    if __name__ == "__main__":
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='VXDF Validate API Server')
        parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
        args = parser.parse_args()
        
        # Use the port from command line arguments
        port = args.port
        logger.info(f"Starting VXDF Validate on port {port}")
        app.run(host="0.0.0.0", port=port, debug=True)
except Exception as e:
    logger.error(f"Failed to start server: {e}", exc_info=True)
    sys.exit(1) 