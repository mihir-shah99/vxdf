#!/usr/bin/env bash
# Enable strict mode
set -o errexit  # Exit on error
set -o errtrace # Exit on error in functions
set -o nounset  # Exit on undefined variables
set -o pipefail # Exit on pipe failures
# set -o xtrace # Uncomment for debugging

# Set safe field separator
# nosemgrep: ifs-tampering
IFS=$'\n\t'

# Get the directory of the script and project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
cd "$PROJECT_ROOT"

# Check if the virtual environment exists
if [ ! -d "venv" ]; then
    echo "Setting up virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r api/requirements.txt
else
    source venv/bin/activate
fi

# Initialize database if it doesn't exist
mkdir -p data
if [ ! -f "data/vxdf_validate.db" ]; then
    echo "Database not found. Initializing database..."
    python3 api/load_sarif_to_db.py
else
    echo "Database already exists."
fi

# Start the API server
echo "Starting API server on port 6789..."
python3 api/main.py 
