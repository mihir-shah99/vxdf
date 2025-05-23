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

# Start the API server in the background
cd api || exit 1
python3 main.py &
API_PID=$!

echo "API server starting on port 5001..."
sleep 3  # Wait for the server to start

# Test the API
echo "Testing API endpoints..."
curl -s http://localhost:5001/api/stats | jq || echo "Failed to get API stats"

# Kill the API server
kill $API_PID

echo "Test completed" 
