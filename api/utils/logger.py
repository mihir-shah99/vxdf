"""
Logging configuration for VXDF Validate.
"""
import os
import logging
import sys
from pathlib import Path
from api.config import LOG_LEVEL, LOG_FILE

def setup_logging():
    """
    Configure logging for the application.
    """
    # Ensure log directory exists
    log_dir = Path(LOG_FILE).parent
    os.makedirs(log_dir, exist_ok=True)
    
    # Set up root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.getLevelName(LOG_LEVEL))
    
    # Create handlers
    console_handler = logging.StreamHandler(sys.stdout)
    file_handler = logging.FileHandler(LOG_FILE)
    
    # Create formatters
    verbose_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    simple_formatter = logging.Formatter(
        '%(levelname)s - %(message)s'
    )
    
    # Set formatters
    console_handler.setFormatter(simple_formatter)
    file_handler.setFormatter(verbose_formatter)
    
    # Add handlers
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    # Set level for specific loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
    
    # Log initial message
    root_logger.debug("Logging initialized")
    
    return root_logger
