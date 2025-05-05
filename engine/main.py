import os
from pathlib import Path
import sys
import logging
from api.server import app
from api.api import api_bp
from api.utils.logger import setup_logging

# Add the parent directory to sys.path
sys.path.insert(0, Path(Path(os.path.abspath(__file__).parent.parent)))

# Set up logging
setup_logging()
logger = logging.getLogger(__name__)

# Register API blueprint
app.register_blueprint(api_bp)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    logger.info(f"Starting VXDF Validate on port {port}")
    app.run(host="0.0.0.0", port=port, debug=True)
