import os
import logging
from vxdf_validate.server import app
from vxdf_validate.utils.logger import setup_logging

# Set up logging
setup_logging()
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    logger.info(f"Starting VXDF Validate on port {port}")
    app.run(host="0.0.0.0", port=port, debug=True)
