# VXDF API

This directory contains the VXDF (Validated eXploitable Data Flow) API, which serves as the backend for the VXDF validation application. It provides RESTful endpoints for processing security scan results, validating vulnerabilities, and generating standardized VXDF reports.

## Structure

```
api/
├── main.py              # Application entry point
├── api.py               # API endpoint definitions
├── server.py            # Flask server implementation
├── config.py            # Configuration settings
├── __init__.py          # Package initialization
├── models/              # Data models and database definitions
├── validators/          # Validation logic for different vulnerability types
├── core/                # Core business logic
├── parsers/             # Data parsers (SARIF, etc.)
└── utils/               # Utility functions
```

## Key Components

### API Endpoints (`api.py`)

Defines the RESTful endpoints exposed by the API, including:
- File upload for security scan results
- Vulnerability validation
- Report generation
- Statistics retrieval

### Server (`server.py`)

Implements the Flask server that hosts the API, including:
- Route definitions
- CORS configuration
- Error handling

### Models (`models/`)

Data models for the application, including:
- Finding: Represents a security finding from a scanner
- VXDF: Contains the VXDF document structure definitions
- Database: Database connection and session management

### Validators (`validators/`)

Specialized validators for different vulnerability types:
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection

### Parsers (`parsers/`)

Parsers for different security tool outputs:
- SARIF (Static Analysis Results Interchange Format)
- DAST (Dynamic Application Security Testing)
- CycloneDX (Software Bill of Materials)

## Running the API

From the `api/` directory:

```bash
python main.py
```

Or from the project root:

```bash
./scripts/start.sh
```

The API server will be available at http://localhost:5001.

## API Documentation

For detailed API documentation, see [API Documentation](../docs/API.md). 