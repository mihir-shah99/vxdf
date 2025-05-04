#!/bin/bash

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

echo "Setting up VXDF Validate..."

# Check for Python
if ! command_exists python3; then
  echo "Python 3 is required but not installed. Please install Python 3.9 or newer."
  exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]); then
  echo "Python 3.9 or newer is required. You have Python $PYTHON_VERSION."
  exit 1
fi

# Check for Node.js
if ! command_exists node; then
  echo "Node.js is required but not installed. Please install Node.js 18 or newer."
  exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2)
NODE_MAJOR=$(echo $NODE_VERSION | cut -d. -f1)

if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "Node.js 18 or newer is required. You have Node.js $NODE_VERSION."
  exit 1
fi

# Set the paths
ROOT_DIR=$(pwd)
API_DIR="$ROOT_DIR/api"
FRONTEND_DIR="$ROOT_DIR/frontend"

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -e . || { echo "Failed to install Python dependencies"; exit 1; }

# Install frontend dependencies
echo "Installing frontend dependencies..."
cd "$FRONTEND_DIR" || exit 1
npm install || { echo "Failed to install frontend dependencies"; exit 1; }

echo "Setup complete! Use ./scripts/start.sh to run the application." 