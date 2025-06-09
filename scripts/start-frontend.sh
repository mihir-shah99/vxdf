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

echo "Starting frontend on port 3000..."
cd frontend

# Check if package.json exists
if [ ! -f "package.json" ]; then
    echo "Error: frontend/package.json not found"
    exit 1
fi

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi

# Start the frontend
npm run dev 
