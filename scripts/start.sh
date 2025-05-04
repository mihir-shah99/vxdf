#!/bin/bash

# Function to kill processes on exit
function cleanup {
    echo "Shutting down servers..."
    kill $API_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    exit 0
}

# Register the cleanup function on exit
trap cleanup EXIT

# Set the paths
ROOT_DIR=$(pwd)
API_DIR="$ROOT_DIR/api"
FRONTEND_DIR="$ROOT_DIR/frontend"

# Check if port 5001 is in use
if lsof -Pi :5001 -sTCP:LISTEN -t >/dev/null ; then
    echo "Port 5001 is already in use. Please close the application using that port and try again."
    exit 1
fi

# Start the API server
echo "Starting API server on port 5001..."
cd "$API_DIR" || exit 1
python3 main.py &
API_PID=$!

# Start the frontend
echo "Starting frontend on port 5173..."
cd "$FRONTEND_DIR" || exit 1
npm run dev &
FRONTEND_PID=$!

echo "VXDF Validate is running!"
echo "API: http://localhost:5001"
echo "Frontend: http://localhost:5173"
echo "Press Ctrl+C to stop"

# Wait for the user to press Ctrl+C
wait 