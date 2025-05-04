# VXDF Validate

VXDF (Validated eXploitable Data Flow) is a security validation application designed to process, validate, and document security vulnerabilities. The application includes a React/TypeScript frontend and a Python/Flask backend.

## Features

- Parse security tool outputs (SAST, DAST, SCA)
- Validate actual exploitability of reported vulnerabilities
- Generate standardized VXDF reports with detailed evidence
- Interactive dashboard to visualize and manage findings
- REST API for integration with other tools

## Quick Start

Prerequisites:
- Python 3.9+
- Node.js 18+

```bash
# Clone the repository
git clone https://github.com/yourusername/vxdf.git
cd vxdf

# Install dependencies
./scripts/setup.sh

# Start both frontend and backend
./scripts/start.sh
```

The application will be available at:
- Frontend: http://localhost:5173
- API: http://localhost:5001

## Project Structure

```
vxdf/
├── api/                 # Backend API service
│   ├── models/          # Data models
│   ├── validators/      # Validation logic
│   ├── core/            # Core business logic
│   ├── parsers/         # Data parsers (SARIF, etc.)
│   └── utils/           # Utility functions
├── frontend/            # React frontend
│   ├── src/             # Frontend source code
│   │   ├── components/  # UI components
│   │   ├── services/    # API service integrations
│   │   └── types/       # TypeScript type definitions
├── scripts/             # Utility scripts
│   ├── setup.sh         # Setup script
│   └── start.sh         # Start both frontend and backend
└── docs/                # Documentation
```

## Documentation

- [Installation Guide](INSTALLATION.md)
- [API Documentation](docs/API.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [License](LICENSE)

## API Endpoints

- `GET /api/stats` - Get server statistics
- `POST /api/upload` - Upload security scan results
- `GET /api/findings` - List all findings
- `GET /api/findings/<id>` - Get a specific finding
- `PUT /api/findings/<id>/validate` - Validate a finding
- `GET /api/report` - Generate a VXDF report

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 