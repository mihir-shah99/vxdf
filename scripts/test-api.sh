#!/bin/bash

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