# VXDF Validate

VXDF (Validated eXploitable Data Flow) is a security validation application for verifying and exploiting security findings.

## Overview

The VXDF Validate tool helps security professionals validate security findings from various scanners and generate standardized reports. It provides:

- Parsing of security findings from various formats (SARIF, JSON, CSV)
- Validation of findings through dynamic analysis
- Exploitation verification
- Standardized reporting using the VXDF format

## Project Structure

The application has been restructured to use a clean organization:

```
vxdf/
├── api/                # API server and core functionality
├── engine/             # Core validation engine
├── frontend/           # React/TypeScript frontend
├── scripts/            # Utility scripts
├── docs/               # Documentation
└── templates, static/  # Symlinks for Flask template handling
```

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

The application can be started in two ways:

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

1. Run the template fixing script to ensure the template directories are set up:
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

## Path Handling

This project uses a consistent approach to path handling:

- All paths are managed using the `pathlib.Path` library
- The project root is defined as the directory containing the api/, engine/, frontend/ directories
- Templates and static files are located in engine/templates and engine/static
- Symlinks to these directories are created at the project root for Flask to access them

If you encounter any path-related issues, run:
```bash
python3 scripts/fix_paths.py
python3 scripts/fix_templates.py
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Mihir Shah <mihir@mihirshah.tech> 