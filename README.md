# VXDF Ultimate

VXDF Ultimate is a comprehensive platform for validating and verifying the exploitability of security vulnerabilities. It combines cutting-edge analysis techniques to determine whether reported vulnerabilities are actually exploitable in real-world scenarios.

## Overview

VXDF (Validated eXploitable Data Flow) Ultimate helps security teams focus their efforts on remediation of vulnerabilities that pose actual risk. The platform:

- Validates security scanner findings to confirm exploitability
- Generates detailed data flow evidence
- Produces standardized VXDF documents for integration with security tools
- Provides a modern web interface for managing the validation process

## Repository Structure

This repository contains two main components:

### 1. Engine (Backend)

The validation engine is a Python-based application that:
- Parses vulnerability reports from various security scanners (SARIF, CycloneDX, DAST)
- Validates reported vulnerabilities to determine exploitability
- Generates standardized VXDF documents with validation results
- Provides a REST API for integration with other tools

### 2. Frontend

A modern React-based web application that:
- Provides an intuitive interface for uploading vulnerability reports
- Displays validation results with detailed evidence
- Visualizes security trends and statistics
- Supports reviewing and managing validated vulnerabilities

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Node.js 16 or higher
- npm/yarn

### Running the Engine (Backend)

1. Navigate to the engine directory:
   ```
   cd engine
   ```

2. Install Python dependencies:
   ```
   pip install beautifulsoup4 click cryptography email-validator flask flask-sqlalchemy gunicorn psycopg2-binary pydantic requests sqlalchemy
   ```

3. Start the engine:
   ```
   python main.py
   ```

4. The engine will run on port 5001 by default: http://localhost:5001

### Running the Frontend

1. Navigate to the frontend directory:
   ```
   cd frontend
   ```

2. Install Node.js dependencies:
   ```
   npm install
   ```

3. Start the frontend development server:
   ```
   npm run dev
   ```

4. The frontend will run on port 5173 by default: http://localhost:5173

## Key Features

- **Multi-Format Support**: Parse vulnerability findings from SARIF, CycloneDX, and DAST scanner outputs
- **Intelligent Validation**: Analyze code and data flows to verify exploitability
- **Evidence Collection**: Gather and document proof of exploitability
- **Standardized Output**: Generate VXDF documents that follow a consistent format
- **Modern UI**: Navigate findings and results with an intuitive interface
- **API Access**: Integrate with your existing security tools via REST API

## Supported Vulnerability Types

- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection

## Architecture

VXDF Ultimate follows a client-server architecture:

1. **Backend Engine**:
   - Flask web server for API and web interface
   - SQLite/PostgreSQL database for storing findings and results
   - Validation engine for analyzing vulnerability exploitability
   - Parsers for different security scanner formats
   - VXDF document generator

2. **Frontend**:
   - React application with TypeScript
   - TailwindCSS for styling
   - Component-based architecture
   - Dashboard for visualizing results

## Development

### Backend Development

The engine is built with Flask and uses SQLAlchemy for database operations. The main components are:

- `vxdf_validate/server.py`: Flask application with routes
- `vxdf_validate/core/engine.py`: Core validation logic
- `vxdf_validate/parsers/`: Input format parsers
- `vxdf_validate/validators/`: Validation implementations for different vulnerability types
- `vxdf_validate/models/`: Database models and VXDF document structure

### Frontend Development

The frontend is built with React, TypeScript, and Vite. Key files include:

- `src/App.tsx`: Main application component
- `src/components/`: UI components
- `src/api/`: API client for backend communication
- `src/services/`: Business logic services
- `src/types/`: TypeScript type definitions

## Configuration

### Engine Configuration

Edit `engine/vxdf_validate/config.py` to configure:
- Database connection
- Supported vulnerability types
- Validation settings
- Output directories

### Frontend Configuration

Edit `frontend/vite.config.ts` for:
- Development server settings
- Backend API proxy configuration

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- All the open-source projects that made this possible
- The security research community for advancing vulnerability analysis techniques 