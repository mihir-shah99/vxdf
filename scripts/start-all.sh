#!/bin/bash
set -e  # Exit on error

# Get the directory of the script and project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
cd "$PROJECT_ROOT"

# Create log directory if it doesn't exist
mkdir -p logs

# Print colorful message
echo -e "\033[1;36m📊 Starting VXDF Validate...\033[0m"

# Check if requirements.txt exists
if [ ! -f "api/requirements.txt" ]; then
    echo -e "\033[0;31m❌ Error: api/requirements.txt not found\033[0m"
    exit 1
fi

# Create symlink for requirements.txt in root if it doesn't exist
if [ ! -f "requirements.txt" ]; then
    echo -e "\033[0;33mℹ️  Creating symlink for requirements.txt in project root\033[0m"
    ln -sf api/requirements.txt requirements.txt
fi

# Check if test-data directory exists
if [ ! -d "test-data" ]; then
    echo -e "\033[0;31m❌ Error: test-data directory not found\033[0m"
    exit 1
fi

# Check if sample SARIF file exists
if [ ! -f "test-data/sample-sarif.json" ]; then
    echo -e "\033[0;31m❌ Error: test-data/sample-sarif.json not found\033[0m"
    exit 1
fi

# Check if the virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "\033[1;33m🔧 Setting up virtual environment...\033[0m"
    python3 -m venv venv
    source venv/bin/activate
    pip install -r api/requirements.txt
else
    echo -e "\033[1;33m🔧 Activating virtual environment...\033[0m"
    source venv/bin/activate
    
    # Check if Flask is installed
    if ! python3 -c "import flask" &>/dev/null; then
        echo -e "\033[1;33m📦 Flask not found. Installing dependencies...\033[0m"
        pip install -r api/requirements.txt
    fi
fi

# Initialize database if it doesn't exist
mkdir -p data
if [ ! -f "data/vxdf_validate.db" ]; then
    echo -e "\033[1;33m🗄️  Database not found. Initializing database...\033[0m"
    python3 api/load_sarif_to_db.py
else
    echo -e "\033[1;32m✅ Database already exists.\033[0m"
fi

# Check if frontend directory exists
if [ ! -d "frontend" ]; then
    echo -e "\033[0;31m❌ Error: frontend directory not found\033[0m"
    exit 1
fi

# Start the API server in the background
echo -e "\033[1;34m🚀 Starting API server on port 6789...\033[0m"
python3 api/main.py > logs/backend.log 2>&1 &
BACKEND_PID=$!
echo -e "\033[0;32m✅ Backend process started with PID $BACKEND_PID\033[0m"

# Wait for the API server to start (up to 30 seconds)
echo -e "\033[0;33m⏳ Waiting for backend to start (this may take a moment)...\033[0m"
for i in {1..30}; do
    if curl -s http://localhost:6789/api/stats > /dev/null; then
        echo -e "\033[0;32m✅ Backend started successfully!\033[0m"
        break
    fi
    
    # Check if the process is still running
    if ! ps -p $BACKEND_PID > /dev/null; then
        echo -e "\033[0;31m❌ Backend process terminated unexpectedly. Check logs/backend.log for errors\033[0m"
        # Print the last 10 lines of the log
        echo -e "\033[0;33mLast lines from logs/backend.log:\033[0m"
        tail -n 10 logs/backend.log
        exit 1
    fi
    
    if [ $i -eq 30 ]; then
        echo -e "\033[0;31m❌ Backend failed to start within timeout. Check logs/backend.log\033[0m"
        kill $BACKEND_PID
        exit 1
    fi
    sleep 1
    echo -n "."
done
echo

# Start the frontend
echo -e "\033[1;35m🌐 Starting frontend on port 3000...\033[0m"
cd frontend

# Check if package.json exists
if [ ! -f "package.json" ]; then
    echo -e "\033[0;31m❌ Error: frontend/package.json not found\033[0m"
    kill $BACKEND_PID
    exit 1
fi

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo -e "\033[1;33m📦 Installing frontend dependencies...\033[0m"
    npm install
fi

# Start frontend and store its PID
npm run dev > ../logs/frontend.log 2>&1 &
FRONTEND_PID=$!
echo -e "\033[0;32m✅ Frontend process started with PID $FRONTEND_PID\033[0m"

# Wait for frontend to start (up to 30 seconds)
echo -e "\033[0;33m⏳ Waiting for frontend to start (this may take a moment)...\033[0m"
for i in {1..30}; do
    if curl -s http://localhost:3000 > /dev/null; then
        echo -e "\033[0;32m✅ Frontend started successfully!\033[0m"
        break
    fi
    
    # Check if the process is still running
    if ! ps -p $FRONTEND_PID > /dev/null; then
        echo -e "\033[0;31m❌ Frontend process terminated unexpectedly. Check logs/frontend.log for errors\033[0m"
        # Print the last 10 lines of the log
        echo -e "\033[0;33mLast lines from logs/frontend.log:\033[0m"
        tail -n 10 ../logs/frontend.log
        kill $BACKEND_PID
        exit 1
    fi
    
    if [ $i -eq 30 ]; then
        echo -e "\033[0;31m❌ Frontend failed to start within timeout. Check logs/frontend.log\033[0m"
        kill $BACKEND_PID
        kill $FRONTEND_PID
        exit 1
    fi
    sleep 1
    echo -n "."
done
echo

# Store PIDs in a file for later cleanup
cd "$PROJECT_ROOT"
echo "$BACKEND_PID $FRONTEND_PID" > .vxdf_pids

# Print success message with URLs
echo -e "\033[1;32m✅ VXDF Validate is running!\033[0m"
echo -e "\033[1;34m🔗 Backend: http://localhost:6789\033[0m"
echo -e "\033[1;35m🔗 Frontend: http://localhost:3000\033[0m"
echo -e "\033[0;33mℹ️  Logs are saved to logs/backend.log and logs/frontend.log\033[0m"
echo -e "\033[0;33mℹ️  To stop all services, run: ./scripts/stop-all.sh\033[0m"

# Keep the script running so that stopping it (Ctrl+C) will kill both processes
trap "echo -e '\033[1;31m🛑 Stopping all services...\033[0m'; kill $BACKEND_PID $FRONTEND_PID; rm -f .vxdf_pids; exit 0" INT TERM
echo -e "\033[0;36m📝 Press Ctrl+C to stop all services\033[0m"
wait 