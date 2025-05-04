"""
Configuration settings for the VXDF Validate tool.
"""
import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Database settings
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR}/vxdf_validate.db")

# Docker settings
DOCKER_ENABLED = True
DOCKER_BASE_IMAGE = "python:3.9-slim"
DOCKER_NETWORK = "vxdf_validate_network"

# Validation settings
VALIDATION_TIMEOUT = 60  # seconds
MAX_CONCURRENT_VALIDATIONS = 5

# Logging settings
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_FILE = os.path.join(BASE_DIR, "logs", "vxdf_validate.log")

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

# Output directory for VXDF files
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

# Temp directory for validation artifacts
TEMP_DIR = os.path.join(BASE_DIR, "temp")

# Ensure directories exist
for directory in [OUTPUT_DIR, TEMP_DIR, os.path.dirname(LOG_FILE)]:
    os.makedirs(directory, exist_ok=True)
