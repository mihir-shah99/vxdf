import os
from pathlib import Path
import sys
import logging
import argparse
from api.server import app
from api.api import api_bp
from api.utils.logger import setup_logging

# Add the parent directory to sys.path
project_root = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, project_root)

# Set up logging
setup_logging()
logger = logging.getLogger(__name__)

# Register API blueprint with a unique name
app.register_blueprint(api_bp, url_prefix='/api', name='vxdf_api_v1')

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='VXDF Validate API Server')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    args = parser.parse_args()
    
    # Use the port from command line arguments
    port = args.port
    logger.info(f"Starting VXDF Validate on port {port}")
    app.run(host="0.0.0.0", port=port, debug=True)
