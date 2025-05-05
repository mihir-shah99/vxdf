# Installation Guide

This guide provides step-by-step instructions for setting up the VXDF Validate application.

## Prerequisites

- Python 3.9 or newer
- Node.js 16 or newer 
- npm 8 or newer
- Git

## Quick Installation

For a quick start:

```bash
# Clone the repository
git clone https://github.com/your-username/vxdf.git
cd vxdf

# Install Python dependencies
pip install -r api/requirements.txt

# Install frontend dependencies
cd frontend
npm install
cd ..

# Run the application
./scripts/startup.sh
```

## Manual Installation

If you prefer a more detailed installation process:

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/vxdf.git
cd vxdf
```

### 2. Backend Setup

```bash
# Install Python dependencies
pip install -r api/requirements.txt

# Verify the installation
cd api
python -c "from pathlib import Path; print('Path module available')"
python -c "import api; print(f'API version: {api.__version__}')"
cd ..
```

### 3. Frontend Setup

```bash
# Navigate to the frontend directory
cd frontend

# Install dependencies
npm install

# Return to project root
cd ..
```

### 4. Set Up Templates and Static Files

Run the template fixing script to ensure all necessary files and directories are created:

```bash
python3 scripts/fix_templates.py
```

### 5. Running the Application

You can run the application using the startup script:

```bash
./scripts/startup.sh
```

Or specify custom ports:

```bash
./scripts/startup.sh 8000 3000  # API on port 8000, frontend on port 3000
```

The application will be available at:
- Frontend: http://localhost:5173 (or your custom port)
- API: http://localhost:5001 (or your custom port)

## Directory Structure

After installation, your project structure should look like this:

```
vxdf/
├── api/                # API server and core functionality
├── engine/             # Templates, static files, and engine code
├── frontend/           # React/TypeScript frontend
├── scripts/            # Utility scripts
├── docs/               # Documentation
├── templates -> engine/templates  # Symlink
└── static -> engine/static        # Symlink
```

## Environment Variables

Customize the application behavior with environment variables:

- `PORT`: API server port (default: 5001)
- `VITE_API_PORT`: Port for the API server, used by frontend (default: 5001)
- `VITE_PORT`: Port for the frontend server (default: 5173)
- `PYTHONPATH`: Should include the project root directory
- `DEBUG_PATHS`: Set to "1" to print debug information about paths

## Troubleshooting

### Import Errors

If you encounter import errors:
```bash
# Set PYTHONPATH to include the project root
export PYTHONPATH=/path/to/vxdf:$PYTHONPATH
```

### Path-related Errors

If you encounter path-related errors:
```bash
# Run the path fixing scripts
python3 scripts/fix_paths.py
python3 scripts/fix_templates.py
```

### Port Conflicts

If the default ports are in use:
```bash
# Use custom ports
./scripts/startup.sh 5002 5174
```

### Database Issues

If database errors occur:
```bash
# Reset the database
rm vxdf_validate.db
touch vxdf_validate.db
```

## Next Steps

After installation:
1. Upload a security scan file to see the application in action
2. Check out the [API documentation](docs/API.md) for integration options
3. View the [STARTUP.md](docs/STARTUP.md) for more details on running the application 