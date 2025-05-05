# VXDF Validate

VXDF (Validated eXploitable Data Flow) is a security validation application for verifying and exploiting security findings.

## Overview

The VXDF Validate tool helps security professionals validate security findings from various scanners and generate standardized reports. It provides:

- Parsing of security findings from various formats (SARIF, JSON, CSV)
- Validation of findings through dynamic analysis
- Exploitation verification
- Standardized reporting using the VXDF format

## Project Structure

The application uses a clean architecture with clear separation of concerns:

```
vxdf/
├── api/                # Backend API and core functionality
│   ├── core/           # Core validation engine
│   ├── models/         # Data models
│   ├── parsers/        # Input format parsers
│   └── validators/     # Vulnerability validators
├── engine/             # Template and static files
│   ├── templates/      # Flask HTML templates
│   └── static/         # CSS, JS, and other static assets
├── frontend/           # React/TypeScript frontend
├── scripts/            # Utility scripts
│   ├── fix_paths.py    # Script to fix path references
│   ├── fix_templates.py # Script to set up templates
│   └── startup.sh      # Main startup script
├── docs/               # Documentation
├── templates → engine/templates  # Symlink
└── static → engine/static        # Symlink
```

## Key Features

- **Consistent Path Handling**: Uses pathlib.Path for reliable path resolution
- **Flexible Deployment**: Works in development and production environments
- **Modular Design**: Clean separation between components
- **Backward Compatibility**: Support for legacy module structure

## Installation

### Prerequisites

- Python 3.9+
- Node.js 16+ and npm
- Git

### Setup

1. Clone the repository:
```bash
git clone https://github.com/your-username/vxdf.git
cd vxdf
```

2. Install Python dependencies:
```bash
pip install -r api/requirements.txt
```

3. Install frontend dependencies:
```bash
cd frontend
npm install
cd ..
```

## Running the Application

### Using the startup script (recommended)

The easiest way to run the application is with the startup script:

```bash
./scripts/startup.sh
```

This will:
1. Run path fixing scripts to ensure consistent path handling
2. Create necessary symlinks for templates and static files
3. Start the API server on port 5001
4. Start the frontend development server on port 5173

You can customize the ports:

```bash
./scripts/startup.sh 8000 3000  # Run API on port 8000 and frontend on port 3000
```

### Running components manually

If you prefer to run the components separately:

1. Run the template fixing script first:
```bash
python3 scripts/fix_templates.py
```

2. Start the API server:
```bash
cd api
python3 main.py
```

3. Start the frontend server (in a separate terminal):
```bash
cd frontend
npm run dev
```

## Path Handling Solution

This project uses a robust approach to path handling that solves common issues:

- Uses `pathlib.Path` consistently throughout the codebase
- Centralizes path definitions in `api/config.py`
- Creates symlinks for Flask template and static directories
- Provides automated scripts to fix path references and create templates
- Sets PYTHONPATH to include the project root during startup
- Handles both absolute and relative imports with fallbacks

If you encounter any path-related issues, simply run:
```bash
python3 scripts/fix_paths.py   # Fix path references in code
python3 scripts/fix_templates.py  # Create template symlinks
```

## Documentation

- [Installation Guide](INSTALLATION.md) - Detailed installation instructions
- [Startup Guide](docs/STARTUP.md) - How to run the application
- [API Documentation](docs/API.md) - API endpoints reference

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Mihir Shah <mihir@mihirshah.tech> 