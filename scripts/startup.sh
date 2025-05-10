#!/bin/bash

# Startup script for VXDF Validate
# Author: Mihir Shah <mihir@mihirshah.tech>

# Colors for terminal output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Default ports
API_PORT=8888
FRONTEND_PORT=3000

# Check if custom ports are provided
if [ ! -z "$1" ]; then
    API_PORT=$1
    echo "Using custom API port: $API_PORT"
fi

if [ ! -z "$2" ]; then
    FRONTEND_PORT=$2
    echo "Using custom frontend port: $FRONTEND_PORT"
fi

echo "Running from scripts directory, using parent directory as root: $PROJECT_ROOT"

# Set PYTHONPATH to include the project root
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"
echo "Setting PYTHONPATH to include $PROJECT_ROOT"

# Run path fixing script
echo "Running path fixing script to ensure consistent path handling..."
python3 "$SCRIPT_DIR/fix_paths.py"

# Initialize database
echo "Initializing database..."
cd "$PROJECT_ROOT"
python3 -c "from api.models.database import init_db; init_db()"

# Kill any existing processes
echo "Cleaning up any existing processes..."
pkill -f "python3 main.py" || true
lsof -ti:$API_PORT,$FRONTEND_PORT | xargs kill -9 2>/dev/null || true

# Start API server
echo "Starting API server on port $API_PORT..."
cd "$PROJECT_ROOT/api"
export FLASK_APP=main.py
export FLASK_ENV=development
python3 main.py --port $API_PORT &
API_PID=$!

# Wait for API server to initialize
echo "Waiting for API server to initialize..."
sleep 5

# Test API endpoints
echo "Testing API endpoints..."
if curl -s "http://localhost:$API_PORT/api/stats" > /dev/null; then
    echo "✓ API is running and responding correctly"
else
    echo "✗ API is not responding"
    exit 1
fi

# Test supported types endpoint
echo "Testing supported vulnerability types..."
SUPPORTED_TYPES=$(curl -s "http://localhost:$API_PORT/api/supported-types")
if [ ! -z "$SUPPORTED_TYPES" ]; then
    echo "✓ Supported vulnerability types: $SUPPORTED_TYPES"
else
    echo "✗ Failed to get supported types"
    exit 1
fi

# Test findings endpoint
echo "Testing findings endpoint..."
if curl -s "http://localhost:$API_PORT/api/findings" > /dev/null; then
    echo "✓ Findings endpoint is working"
else
    echo "✗ Database connection failed"
    echo "Please check database configuration."
    exit 1
fi

# Update frontend configuration
echo "Updating frontend configuration..."
cd "$PROJECT_ROOT/frontend"
cat > vite.config.ts << EOL
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    exclude: ['lucide-react'],
  },
  server: {
    port: $FRONTEND_PORT,
    proxy: {
      '/api': {
        target: 'http://localhost:$API_PORT',
        changeOrigin: true,
        rewrite: (path) => path,
      },
    },
  },
});
EOL

# Install frontend dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi

# Start frontend
echo "Starting frontend on port $FRONTEND_PORT..."
npm run dev &
FRONTEND_PID=$!

# Wait for frontend to start
echo "Waiting for frontend to initialize..."
sleep 5

# Function to kill processes on exit
function cleanup {
    echo -e "${YELLOW}Shutting down servers...${NC}"
    kill $API_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    exit 0
}

# Register the cleanup function on exit
trap cleanup EXIT INT

echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}✓ VXDF Validate is running!${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "API: ${YELLOW}http://localhost:$API_PORT${NC}"
echo -e "Frontend: ${YELLOW}http://localhost:$FRONTEND_PORT${NC}"
echo ""
echo "You can now use the application. Open the frontend URL in your browser."
echo "Press Ctrl+C to stop all services."

# Wait for the user to press Ctrl+C
wait 