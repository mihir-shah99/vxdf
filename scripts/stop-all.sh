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

# Print colorful message
echo -e "\033[1;31m🛑 Stopping VXDF Validate...\033[0m"

# Check if PID file exists
if [ ! -f ".vxdf_pids" ]; then
    echo -e "\033[0;33m⚠️  PID file not found. Attempting to find and kill processes manually.\033[0m"
    
    # Try to find and kill Python processes
    echo -e "\033[0;36m🔍 Looking for backend processes...\033[0m"
    BACKEND_PIDS=$(ps -ef | grep "python3 api/main.py" | grep -v grep | awk '{print $2}')
    if [ ! -z "$BACKEND_PIDS" ]; then
        echo -e "\033[0;32m✅ Found backend processes: $BACKEND_PIDS\033[0m"
        for pid in $BACKEND_PIDS; do
            echo -e "\033[0;31m❌ Killing backend process $pid\033[0m"
            kill -9 $pid 2>/dev/null || true
        done
    else
        echo -e "\033[0;33m⚠️  No backend processes found\033[0m"
    fi
    
    # Try to find and kill frontend processes
    echo -e "\033[0;36m🔍 Looking for frontend processes...\033[0m"
    FRONTEND_PIDS=$(ps -ef | grep "vite" | grep -v grep | awk '{print $2}')
    if [ ! -z "$FRONTEND_PIDS" ]; then
        echo -e "\033[0;32m✅ Found frontend processes: $FRONTEND_PIDS\033[0m"
        for pid in $FRONTEND_PIDS; do
            echo -e "\033[0;31m❌ Killing frontend process $pid\033[0m"
            kill -9 $pid 2>/dev/null || true
        done
    else
        echo -e "\033[0;33m⚠️  No frontend processes found\033[0m"
    fi
    
    # Try to kill any processes using the ports
    echo -e "\033[0;36m🔍 Checking for processes using ports 6789 and 3000...\033[0m"
    PORT_PIDS=$(lsof -ti:6789,3000 2>/dev/null)
    if [ ! -z "$PORT_PIDS" ]; then
        echo -e "\033[0;32m✅ Found processes using ports: $PORT_PIDS\033[0m"
        for pid in $PORT_PIDS; do
            echo -e "\033[0;31m❌ Killing process $pid using ports\033[0m"
            kill -9 $pid 2>/dev/null || true
        done
    else
        echo -e "\033[0;33m⚠️  No processes found using ports 6789 or 3000\033[0m"
    fi
else
    # Read PIDs from file
    read BACKEND_PID FRONTEND_PID < .vxdf_pids
    
    # Kill backend process
    if [ ! -z "$BACKEND_PID" ]; then
        echo -e "\033[0;31m❌ Killing backend process $BACKEND_PID\033[0m"
        kill $BACKEND_PID 2>/dev/null || kill -9 $BACKEND_PID 2>/dev/null || true
    fi
    
    # Kill frontend process
    if [ ! -z "$FRONTEND_PID" ]; then
        echo -e "\033[0;31m❌ Killing frontend process $FRONTEND_PID\033[0m"
        kill $FRONTEND_PID 2>/dev/null || kill -9 $FRONTEND_PID 2>/dev/null || true
    fi
    
    # Remove PID file
    rm -f .vxdf_pids
fi

echo -e "\033[1;32m✅ All services stopped\033[0m" 
