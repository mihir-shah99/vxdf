# VXDF Engine (Legacy Documentation)

> **IMPORTANT**: The functionality described in this document has been refactored and moved to the `api/` directory in the project root. This file is kept for historical reference only. Please refer to the main project README.md for current structure and operation instructions.

The VXDF Engine was the original implementation of the Validated Exploitable Data Flow validation framework. The application has since been restructured with:

- Backend functionality moved to `api/` directory
- Core validation logic maintained in `api/core/`
- Models moved to `api/models/`
- Parsers moved to `api/parsers/`
- Templates and static files moved to `engine/templates` and `engine/static`

## Current Architecture

The current architecture uses:

```
vxdf/
├── api/                # API server and core functionality
│   ├── core/           # Core validation logic
│   ├── models/         # Data models
│   ├── parsers/        # Input format parsers
│   └── validators/     # Vulnerability validators
├── engine/             # Templates, static files, and legacy code
├── frontend/           # React/TypeScript frontend
└── scripts/            # Utility scripts for setup and path handling
```

For the current documentation, please refer to:
- Main [README.md](../README.md) in the project root
- [STARTUP.md](../docs/STARTUP.md) for instructions on running the application
- [API.md](../docs/API.md) for API endpoint documentation

DO NOT use the information below for the current application structure!

----

# Historical Documentation (For Reference Only)

The VXDF (Validated Exploitable Data Flow) Engine is a comprehensive security validation framework designed to process security scanning outputs (SAST, DAST, SCA), validate the actual exploitability of reported vulnerabilities, and produce standardized output with detailed evidence.

## Architecture Overview

The VXDF Engine consists of several interconnected components that work together to provide a complete vulnerability validation workflow:

```
                  ┌───────────────┐
                  │  Input Files  │
                  │ (SARIF/DAST/  │
                  │  CycloneDX)   │
                  └───────┬───────┘
                          │
                          ▼
┌───────────────┐  ┌─────┴──────┐  ┌───────────────┐
│   Web UI      │◄─┤  Parsers   │  │  CLI Interface │
│ (Flask Server)│  │            │◄─┤                │
└───────┬───────┘  └─────┬──────┘  └───────┬───────┘
        │                │                  │
        └────────┬───────┴──────────┬──────┘
                 │                  │
                 ▼                  ▼
        ┌────────────────┐  ┌───────────────┐
        │ Core Engine    │  │  Database     │
        │ & Validators   │◄─┤  (SQLite)     │
        └────────┬───────┘  └───────────────┘
                 │
                 ▼
        ┌────────────────┐
        │  VXDF Output   │
        │  (JSON)        │
        └────────────────┘
```

## Core Components

### 1. Main Application Entry Points

- **`main.py`**: The main entry point for the web application, initializes and runs the Flask server.
- **`vxdf_validate/cli.py`**: Command-line interface for using the engine without the web interface.
- **`vxdf_validate/server.py`**: The Flask web server implementation providing a user interface.

### 2. Core Engine (`vxdf_validate/core/`)

- **`engine.py`**: The core validation engine that coordinates the validation process, manages findings, and generates VXDF documents.
- **`validator.py`**: Base validator implementation and factory for creating validators.

### 3. Parsers (`vxdf_validate/parsers/`)

Different parsers to handle various security tool outputs:

- **`sarif_parser.py`**: Parser for SARIF (Static Analysis Results Interchange Format) files.
- **`dast_parser.py`**: Parser for DAST (Dynamic Application Security Testing) results.
- **`cyclonedx_parser.py`**: Parser for CycloneDX Software Bill of Materials (SBOM) format.

### 4. Validators (`vxdf_validate/validators/`)

Specialized validators for different vulnerability types:

- **`sql_injection.py`**: Validator for SQL injection vulnerabilities.
- **`xss.py`**: Validator for Cross-Site Scripting (XSS) vulnerabilities.
- **`path_traversal.py`**: Validator for path traversal vulnerabilities.
- **`command_injection.py`**: Validator for command injection vulnerabilities.

### 5. Models (`vxdf_validate/models/`)

Data models for the application:

- **`finding.py`**: Represents a security finding from a scanner.
- **`vxdf.py`**: Contains the VXDF document structure definitions.
- **`database.py`**: Database connection and session management.

### 6. Utilities (`vxdf_validate/utils/`)

Supporting utilities:

- **`http_utils.py`**: Utilities for HTTP requests and responses, used in validation.
- **`docker_utils.py`**: Docker-related utilities for containerized validation.
- **`logger.py`**: Logging configuration.

### 7. Support Directories

- **`templates/`**: HTML templates for the web interface.
- **`static/`**: Static files (CSS, JavaScript, images) for the web interface.
- **`output/`**: Directory for storing generated VXDF output files.
- **`logs/`**: Log files directory.
- **`temp/`**: Temporary files used during processing.
- **`attached_assets/`**: Additional assets that may be used by the engine.

## Workflow

1. **Input Processing**:
   - Security scan results are uploaded through the web interface or CLI.
   - The appropriate parser is selected based on the file format.
   - The parser extracts findings from the input file.

2. **Validation**:
   - The core engine filters findings based on criteria like vulnerability type and severity.
   - For each finding, the appropriate validator is invoked.
   - Validators attempt to confirm the exploitability of the vulnerability.
   - Evidence is gathered during validation (HTTP requests/responses, code execution traces, etc.).

3. **Output Generation**:
   - Validated findings are converted to the standardized VXDF format.
   - A comprehensive VXDF document is generated, including metadata, validated flows, and evidence.
   - The document is saved to the output directory and can be downloaded or viewed in the web interface.

## Key Features

1. **Vulnerability Validation**: Determines the true exploitability of vulnerabilities, reducing false positives.
2. **Multi-Format Support**: Handles multiple security tool output formats.
3. **Detailed Evidence Collection**: Captures proof of exploitability for each vulnerability.
4. **Standardized Output**: Provides a consistent VXDF format for all findings.
5. **Web and CLI Interfaces**: Offers flexible usage options.

## Database

The engine uses SQLite (`vxdf_validate.db`) to store:
- Parsed findings
- Validation results
- Evidence for each finding

## Configuration

Configuration settings are defined in `vxdf_validate/config.py`, including:
- Supported vulnerability types
- Severity thresholds
- Output directory paths

## Dependencies

Key dependencies (from pyproject.toml):
- Flask: Web framework
- SQLAlchemy: Database ORM
- Pydantic: Data validation and settings management
- Requests: HTTP client for validation
- BeautifulSoup4: HTML parsing
- Cryptography: Cryptographic operations
- Flask-SQLAlchemy: Flask integration with SQLAlchemy

## Architecture Details

### VXDF Document Structure

The VXDF document (`vxdf_validate/models/vxdf.py`) is structured as follows:

- **VXDFDocument**: Top-level container with metadata, flows, and summary.
  - **VXDFMetadata**: Information about the document, generator, and target.
  - **VXDFFlow**: Represents a validated vulnerability flow.
    - **CodeLocation**: Source and sink locations in code.
    - **DataFlowStep**: Steps in the data flow from source to sink.
    - **EvidenceItem**: Proof of exploitability.
  - **VXDFSummary**: Statistics about the document's findings.

### Validation Process

1. The `ValidationEngine` receives a finding from a parser.
2. It uses `ValidatorFactory` to get the appropriate validator.
3. The validator performs specialized checks based on vulnerability type.
4. Results include exploitability determination and collected evidence.
5. Findings are stored in the database and included in the VXDF output.

### Parser Design

Parsers are designed with a common interface but specialized implementations:
- They convert tool-specific formats to a unified `Finding` model.
- Each parser handles format-specific details (SARIF, DAST reports, CycloneDX).
- The factory pattern (`get_parser()`) allows dynamically selecting the appropriate parser.

### Extension Points

The engine is designed for extensibility:
1. **New Vulnerability Types**: Add new validator classes.
2. **Additional Tool Formats**: Implement new parsers.
3. **Custom Validation Logic**: Extend or override existing validators. 