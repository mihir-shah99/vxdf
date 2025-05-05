"""
Configuration settings for the VXDF Validate tool.
"""
import os
import sys
from pathlib import Path

# Path resolution - handles both development and production scenarios
API_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = API_DIR.parent

# Check for directories that might contain resources
TEMPLATE_DIRS = [
    PROJECT_ROOT / "templates",        # project_root/templates
    PROJECT_ROOT / "engine/templates", # project_root/engine/templates
]

STATIC_DIRS = [
    PROJECT_ROOT / "static",          # project_root/static
    PROJECT_ROOT / "engine/static",   # project_root/engine/static
]

# Find the first existing template and static directories
TEMPLATE_DIR = next((d for d in TEMPLATE_DIRS if d.exists()), TEMPLATE_DIRS[0])
STATIC_DIR = next((d for d in STATIC_DIRS if d.exists()), STATIC_DIRS[0])

# Database settings
DB_PATH = PROJECT_ROOT / "vxdf_validate.db"
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DB_PATH}")

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
    print(f"API Directory: {API_DIR}")
    print(f"Project Root: {PROJECT_ROOT}")
    print(f"Template Directory: {TEMPLATE_DIR}")
    print(f"Static Directory: {STATIC_DIR}")
    print(f"Database Path: {DB_PATH}")
    print(f"Log Directory: {LOG_DIR}")
    print(f"Output Directory: {OUTPUT_DIR}")
    print(f"Temp Directory: {TEMP_DIR}")
