"""
Configuration settings for the VXDF Validate tool.
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.resolve()

# Database config
DATABASE_URL = os.environ.get("VXDF_DATABASE_URL", f"sqlite:///{PROJECT_ROOT}/vxdf_validate.db")

# Output directories
LOG_DIR = PROJECT_ROOT / "logs"
OUTPUT_DIR = PROJECT_ROOT / "output"
TEMP_DIR = PROJECT_ROOT / "temp"

# Docker settings
DOCKER_ENABLED = True
DOCKER_BASE_IMAGE = "python:3.9-slim"
DOCKER_NETWORK = "vxdf_validate_network"

# Validation settings
VALIDATION_TIMEOUT = 60  # seconds
MAX_CONCURRENT_VALIDATIONS = 5

# Logging settings
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_FILE = LOG_DIR / "vxdf_validate.log"

# Severity thresholds
SEVERITY_THRESHOLDS = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 0.1,
    "NONE": 0.0
}

# Supported vulnerability types
SUPPORTED_VULN_TYPES = [
    "sql_injection",
    "xss",
    "path_traversal",
    "command_injection"
]

# Mapping of CWE to vulnerability types
CWE_TO_VULN_TYPE = {
    # SQL Injection
    "89": "sql_injection",
    "564": "sql_injection",
    # XSS
    "79": "xss",
    "80": "xss",
    "83": "xss",
    "84": "xss",
    # Path Traversal
    "22": "path_traversal",
    "23": "path_traversal",
    "36": "path_traversal",
    # Command Injection
    "77": "command_injection",
    "78": "command_injection",
    "917": "command_injection"
}

# Ensure directories exist
for directory in [OUTPUT_DIR, TEMP_DIR, LOG_DIR]:
    os.makedirs(directory, exist_ok=True)

# Print directory configuration for debugging
if os.environ.get("DEBUG_PATHS", "0") == "1":
    print(f"Project Root: {PROJECT_ROOT}")
    print(f"Database Path: {DATABASE_URL}")
    print(f"Log Directory: {LOG_DIR}")
    print(f"Output Directory: {OUTPUT_DIR}")
    print(f"Temp Directory: {TEMP_DIR}")
