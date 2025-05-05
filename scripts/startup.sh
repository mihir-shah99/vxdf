#!/bin/bash

# Startup script for VXDF Validate
# Author: Mihir Shah <mihir@mihirshah.tech>

# Colors for terminal output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Define ports with defaults
API_PORT=5001
FRONTEND_PORT=5173

# Check if alternative ports were provided
if [ ! -z "$1" ]; then
    API_PORT=$1
    echo -e "${YELLOW}Using custom API port: $API_PORT${NC}"
fi

if [ ! -z "$2" ]; then
    FRONTEND_PORT=$2
    echo -e "${YELLOW}Using custom frontend port: $FRONTEND_PORT${NC}"
fi

# Function to kill processes on exit
function cleanup {
    echo -e "${YELLOW}Shutting down servers...${NC}"
    kill $API_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    exit 0
}

# Register the cleanup function on exit
trap cleanup EXIT INT

# Determine the project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")

# If running from the scripts directory, go up one level
if [[ "$SCRIPT_DIR" == *"/scripts" ]]; then
    ROOT_DIR="$(dirname "$SCRIPT_DIR")"
    echo -e "${YELLOW}Running from scripts directory, using parent directory as root: $ROOT_DIR${NC}"
else
    ROOT_DIR="$SCRIPT_DIR"
fi

# Set PYTHONPATH to include the project root
export PYTHONPATH="$ROOT_DIR:$PYTHONPATH"
echo -e "${YELLOW}Setting PYTHONPATH to include $ROOT_DIR${NC}"

# Essential directories
API_DIR="$ROOT_DIR/api"
FRONTEND_DIR="$ROOT_DIR/frontend"
ENGINE_DIR="$ROOT_DIR/engine"
DB_FILE="$ROOT_DIR/vxdf_validate.db"

# Verify directory structure
if [ ! -d "$API_DIR" ]; then
    echo -e "${RED}Error: API directory not found at $API_DIR${NC}"
    echo "Please run this script from the project root directory or the scripts directory."
    exit 1
fi

if [ ! -d "$FRONTEND_DIR" ]; then
    echo -e "${RED}Error: Frontend directory not found at $FRONTEND_DIR${NC}"
    echo "Please run this script from the project root directory or the scripts directory."
    exit 1
fi

if [ ! -d "$ENGINE_DIR" ]; then
    echo -e "${RED}Error: Engine directory not found at $ENGINE_DIR${NC}"
    echo "Please run this script from the project root directory or the scripts directory."
    exit 1
fi

# Run path fixing script if it exists
FIX_PATHS_SCRIPT="$ROOT_DIR/scripts/fix_paths.py"
if [ -f "$FIX_PATHS_SCRIPT" ]; then
    echo -e "${YELLOW}Running path fixing script to ensure consistent path handling...${NC}"
    if ! python3 "$FIX_PATHS_SCRIPT"; then
        echo -e "${RED}Warning: Path fixing script failed, but continuing...${NC}"
    fi
fi

# Run template fixing script
FIX_TEMPLATES_SCRIPT="$ROOT_DIR/scripts/fix_templates.py"
if [ -f "$FIX_TEMPLATES_SCRIPT" ]; then
    echo -e "${YELLOW}Running template fixing script to ensure templates and static files are available...${NC}"
    if ! python3 "$FIX_TEMPLATES_SCRIPT"; then
        echo -e "${RED}Error: Template fixing script failed!${NC}"
        echo "This script is required for setting up templates and static files."
        exit 1
    fi
else
    echo -e "${RED}Error: Template fixing script not found at $FIX_TEMPLATES_SCRIPT${NC}"
    echo "This script is required for setting up templates and static files."
    exit 1
fi

# Create other required directories
for dir in "$ENGINE_DIR/logs" "$ENGINE_DIR/output" "$ENGINE_DIR/temp"; do
    if [ ! -d "$dir" ]; then
        echo -e "${YELLOW}Creating directory: $dir${NC}"
        mkdir -p "$dir"
    fi
done

# Check if the database exists, if not create an empty one
if [ ! -f "$DB_FILE" ]; then
    echo -e "${YELLOW}Database file not found. Creating a new database...${NC}"
    touch "$DB_FILE"
fi

# Check if required ports are in use
function is_port_in_use {
    if command -v lsof >/dev/null 2>&1; then
        if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null ; then
            return 0
        else
            return 1
        fi
    else
        if netstat -tuln | grep ":$1 " >/dev/null; then
            return 0
        else
            return 1
        fi
    fi
}

if is_port_in_use $API_PORT; then
    echo -e "${RED}Error: Port $API_PORT is already in use.${NC}"
    echo "Please close the application using that port and try again, or specify a different port."
    echo "Usage: $0 [api_port] [frontend_port]"
    exit 1
fi

if is_port_in_use $FRONTEND_PORT; then
    echo -e "${RED}Error: Port $FRONTEND_PORT is already in use.${NC}"
    echo "Please close the application using that port and try again, or specify a different port."
    echo "Usage: $0 [api_port] [frontend_port]"
    exit 1
fi

# Export port configuration as environment variables
export PORT=$API_PORT
export VITE_API_PORT=$API_PORT
export VITE_PORT=$FRONTEND_PORT

# Start the API server
echo -e "${YELLOW}Starting API server on port $API_PORT...${NC}"
cd "$API_DIR" || exit 1
python3 main.py &
API_PID=$!
API_EXIT_CODE=$?

if [ $API_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}Error: API server failed to start!${NC}"
    echo "Check api/main.py for errors."
    exit 1
fi

cd "$ROOT_DIR" || exit 1

# Wait for API to start
echo "Waiting for API server to initialize..."
sleep 3

# Verify API is running
if ! ps -p $API_PID > /dev/null; then
    echo -e "${RED}Error: API server process has terminated!${NC}"
    echo "Check logs for errors."
    exit 1
fi

# Test API endpoints
echo -e "${YELLOW}Testing API endpoints...${NC}"
API_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$API_PORT/api/stats)

if [ "$API_STATUS" -eq 200 ]; then
    echo -e "${GREEN}✓ API is running and responding correctly${NC}"
    # Check supported vulnerability types
    VULN_TYPES=$(curl -s http://localhost:$API_PORT/api/supported-types)
    echo -e "${GREEN}✓ Supported vulnerability types:${NC} $VULN_TYPES"
else
    echo -e "${RED}✗ API server is not responding correctly. Status code: $API_STATUS${NC}"
    echo "Please check logs for errors."
    exit 1
fi

# Test database connection by querying findings
DB_TEST=$(curl -s http://localhost:$API_PORT/api/findings)
if [[ "$DB_TEST" == *"findings"* ]]; then
    echo -e "${GREEN}✓ Database connection is working correctly${NC}"
else
    echo -e "${RED}✗ Database connection failed${NC}"
    echo "Please check database configuration."
    exit 1
fi

# Start the frontend (only if API is running)
echo -e "${YELLOW}Starting frontend on port $FRONTEND_PORT...${NC}"
cd "$FRONTEND_DIR" || exit 1
npm run dev -- --port $FRONTEND_PORT &
FRONTEND_PID=$!
cd "$ROOT_DIR" || exit 1

# Wait for frontend to start
echo "Waiting for frontend to initialize..."
sleep 5

# Verify frontend is running
if ! ps -p $FRONTEND_PID > /dev/null; then
    echo -e "${RED}Warning: Frontend process seems to have terminated!${NC}"
    echo "The API server is still running on port $API_PORT."
    # Don't exit - the API might still be useful without the frontend
fi

# Test frontend
FRONTEND_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$FRONTEND_PORT)
if [ "$FRONTEND_STATUS" -eq 200 ]; then
    echo -e "${GREEN}✓ Frontend is running and responding correctly${NC}"
else
    echo -e "${YELLOW}! Frontend status check returned $FRONTEND_STATUS${NC}"
    echo "This might be normal depending on your frontend configuration."
    echo "Try opening http://localhost:$FRONTEND_PORT in your browser."
fi

# All services started
echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}✓ VXDF Validate is running!${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "API: ${YELLOW}http://localhost:$API_PORT${NC}"

if ps -p $FRONTEND_PID > /dev/null; then
    echo -e "Frontend: ${YELLOW}http://localhost:$FRONTEND_PORT${NC}"
else
    echo -e "${YELLOW}Note: Frontend is not running. Only the API is available.${NC}"
fi

echo ""
echo "You can now use the application. Open the frontend URL in your browser."
echo "Press Ctrl+C to stop all services."

# Wait for the user to press Ctrl+C
wait 