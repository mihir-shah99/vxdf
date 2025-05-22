# VXDF API

This directory contains the VXDF (Validated eXploitable Data Flow) API, which serves as the backend for the VXDF validation application. It provides RESTful endpoints for processing security scan results, validating vulnerabilities, and generating standardized VXDF reports.

## Quickstart

```bash
pip install -r requirements.txt
python3 -m api.server --port 5001
```

- API endpoints are available at `/api/*`.
- Swagger/OpenAPI docs: [http://localhost:5001/apidocs](http://localhost:5001/apidocs)
- The backend is API-only. There are no Flask-rendered pages or templates.

## Troubleshooting
- If you see port conflicts, kill any processes using ports 5001 or 3000:
  ```bash
  lsof -ti:5001,3000 | xargs kill -9
  ```
- If you see proxy errors in the frontend, make sure the backend is running on port 5001.

## Makefile
- `make dev` — Start backend and frontend together
- `make check` — Run health checks on API endpoints

## Structure

```
api/
├── server.py         # Flask server (entrypoint)
├── api.py            # API endpoint definitions
├── config.py         # Configuration settings
├── models/           # VXDF Pydantic models defining the canonical schema (see models/vxdf.py)
├── validators/       # Validation logic for different vulnerability types
├── core/             # Core business logic
├── parsers/          # Data parsers (SARIF, etc.)
└── utils/            # Utility functions
```

## Environment
- See `.env.example` for environment variables.

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

Contains the Pydantic models defining the canonical VXDF data structure, primarily in `vxdf.py`.
These models serve as the source of truth for the VXDF format and are used for data validation, serialization, and deserialization across the application.
They directly implement the [VXDF Specification](https://github.com/VXDF/vxdf/blob/main/docs/Validated%20Exploitable%20Data%20Flow%20(VXDF)%20Format.md).

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

**Always start the backend using:**

```bash
python3 -m api.server --port 5001
```

The API server will be available at http://localhost:5001.

## API Documentation

For detailed API documentation, see [API Documentation](../docs/API.md). 