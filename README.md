<div align="center">
<img src="frontend/src/assets/VXDF logo.png" alt="VXDF Logo" width="200"/>
</div>

# VXDF: Validated eXploitable Data Flow

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Frontend](https://img.shields.io/badge/frontend-React%2FTS-blue)
![Backend](https://img.shields.io/badge/backend-Python%2FFlask-yellow)
![Evidence Types](https://img.shields.io/badge/evidence_types-30%2B-green)

---

## 🖼️ Demo

<img src="frontend/src/assets/dashboard.png" alt="VXDF Dashboard" width="100%" style="border-radius:8px;box-shadow:0 2px 8px #0002;"/>

*VXDF Dashboard*

---

> **VXDF (Validated eXploitable Data Flow)** is a security validation platform that verifies and validates security findings from various scanners, providing standardized reporting with comprehensive evidence collection.

---

## 📑 Table of Contents
- [Core Architecture](#core-architecture)
- [Key Features](#-key-features)
- [Evidence System](#-evidence-system)
- [Key Components](#-key-components)
- [Validation Workflow](#-validation-workflow)
- [Data Model](#-data-model)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Running the Application](#-running-the-application)
- [API Documentation](#-api-documentation)
- [Documentation](#-documentation)
- [License](#-license)

---

## 🏛️ Core Architecture

VXDF follows a modular microservices architecture with clear separation between:

1. **Validation Engine** - Core vulnerability verification logic
2. **API Layer** - RESTful interface with evidence ingestion
3. **Data Processing** - SARIF/DAST/SCA parsing pipeline
4. **Evidence Collection** - Automated exploit validation system
5. **Reporting** - VXDF format generation and export

---

## ✨ Key Features

### 🔍 **Multi-Tool Integration**
- **SARIF Support** - Static analysis results from tools like Semgrep, CodeQL
- **DAST Integration** - Dynamic analysis from OWASP ZAP, Burp Suite
- **SCA Support** - Dependency scanning from npm audit, pip-audit
- **Auto-Detection** - Intelligent parser selection based on file content

### 🛡️ **Security Validation**
- **Docker-based Validation** - Isolated exploitation testing
- **Vulnerability Types** - SQL injection, XSS, path traversal, and more
- **Evidence Collection** - Automated capture of exploit attempts
- **Correlation Engine** - Smart grouping of related findings

### 📊 **Evidence Management**
- **30+ Evidence Types** - HTTP logs, code snippets, screenshots, tool outputs
- **Flexible Matching** - Link evidence to findings via multiple strategies
- **Real-world Integration** - Support for popular security tools
- **Structured Storage** - Type-safe evidence validation

---

## 🔗 Evidence System

VXDF includes a comprehensive evidence system that allows security professionals to attach evidence from any source to vulnerability findings.

### **Supported Evidence Types**

#### **Network & HTTP Evidence**
- `HTTP_REQUEST_LOG` - Request logs with payloads
- `HTTP_RESPONSE_LOG` - Server responses
- `NETWORK_TRAFFIC_CAPTURE_SUMMARY` - Network analysis

#### **Code Analysis Evidence**
- `CODE_SNIPPET_SOURCE` - Vulnerable source code
- `CODE_SNIPPET_SINK` - Vulnerability points
- `POC_SCRIPT` - Proof-of-concept scripts

#### **Runtime Evidence**
- `RUNTIME_APPLICATION_LOG_ENTRY` - Application logs
- `RUNTIME_SYSTEM_LOG_ENTRY` - System events
- `RUNTIME_DATABASE_LOG_ENTRY` - Database logs

#### **Security Tool Integration**
- `TOOL_SPECIFIC_OUTPUT_LOG` - Security tool outputs
- `VULNERABLE_COMPONENT_SCAN_OUTPUT` - SCA results
- `STATIC_ANALYSIS_DATA_FLOW_PATH` - SAST analysis

#### **Visual Evidence**
- `SCREENSHOT_EMBEDDED_BASE64` - Visual proof
- `MANUAL_VERIFICATION_NOTES` - Manual testing results

### **Matching Strategies**
- **Rule ID Matching** - Link to specific scanner rules
- **CWE Matching** - Associate with weakness IDs
- **Location Matching** - File and line-based matching
- **Pattern Matching** - Regex-based matching

---

## 🧩 Key Components

### Backend Services
- **Validation Engine**: Core vulnerability verification
- **Flask API**: RESTful endpoints
- **SQLAlchemy ORM**: Database management
- **Parser System**: Multi-format input processing
- **Evidence Handler**: Evidence processing and validation
- **Validator Plugins**: Vulnerability-specific logic

### Frontend Features
- **React/TypeScript**: Modern web interface
- **Dynamic Dashboard**: Real-time statistics
- **File Upload**: Scanner report ingestion
- **Evidence Viewer**: Evidence inspection
- **Report Generator**: VXDF export

---

## 🔄 Validation Workflow

1. **Input Ingestion**
   - Upload scanner results (SARIF, DAST JSON, SCA)
   - Attach external evidence files
   - Auto-detect file formats

2. **Processing**
   - Parse and normalize findings
   - Extract vulnerability details
   - Apply correlation logic

3. **Validation**
   - Docker-based exploitation testing
   - Evidence collection
   - Exploitability assessment

4. **Reporting**
   - Generate VXDF documents
   - Include all evidence
   - Maintain audit trail

---

## 🗃️ Data Model

The data model is defined using Pydantic in `api/models/vxdf.py`.

### **Core Models**
- **`VXDFModel`**: Root document model
- **`VulnerabilityDetailsModel`**: Individual vulnerabilities
- **`EvidenceModel`**: Evidence items
- **`ExploitFlowModel`**: Attack sequences

### **Evidence Models**
Each evidence type has a corresponding Pydantic model for validation.

---

## 📁 Project Structure

```
vxdf/
├── api/                          # Backend API
│   ├── core/                     # Validation engine
│   ├── models/                   # Data models
│   ├── parsers/                  # Input parsers
│   ├── utils/                    # Utilities
│   ├── validators/               # Vulnerability validators
│   ├── api.py                   # API endpoints
│   └── server.py                # Flask server
├── frontend/                     # React frontend
├── tests/                        # Test suites
├── docs/                        # Documentation
├── config/                      # Configuration
├── data/                        # Database
├── scripts/                     # Utility scripts
└── README.md                    # This file
```

---

## 🚀 Installation

### Prerequisites
- Python 3.9+
- Node.js 16+ and npm
- Git

### Setup
```bash
git clone https://github.com/your-username/vxdf.git
cd vxdf
pip install -r requirements.txt
cd frontend
npm install
cd ..
```

---

## ▶️ Running the Application

### Quick Start
```bash
# One-command startup
python3 start_vxdf.py
```

### Manual Setup

#### Backend
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m api.server --port 5001
```

#### Frontend
```bash
cd frontend
npm install
npm run dev
```

Access the application:
- Backend API: http://localhost:5001
- Frontend UI: http://localhost:3000

---

## 📚 API Documentation

### Core Endpoints
- `POST /api/upload` - Upload scanner results
- `POST /api/findings/{finding_id}/attach_evidence_file` - Attach evidence
- `GET /api/vulnerabilities` - List vulnerabilities
- `POST /api/validation/start` - Start validation workflow
- `GET /api/stats` - Dashboard statistics

### Usage Examples

#### Upload Scanner Report
```bash
curl -X POST http://localhost:5001/api/upload \
  -F "file=@scan_results.sarif" \
  -F "parser_type=sarif"
```

#### Attach Evidence
```bash
curl -X POST http://localhost:5001/api/findings/{finding_id}/attach_evidence_file \
  -F "evidence_file=@screenshot.png" \
  -F "evidence_type_str=SCREENSHOT_EMBEDDED_BASE64"
```

---

## 📚 Documentation

- **[API Documentation](docs/API.md)** - Complete API reference
- **[VXDF Format](docs/Validated%20Exploitable%20Data%20Flow%20(VXDF)%20Format.md)** - Format specification
- **[Installation Guide](INSTALLATION.md)** - Setup instructions
- **[Contributing Guide](CONTRIBUTING.md)** - Development guidelines

---

## 🔧 Configuration

- Backend runs on port 5001
- Frontend runs on port 3000
- Database: SQLite at `data/vxdf_validate.db`
- Logs: `logs/vxdf_validate.log`

---

## ❓ Troubleshooting

### Reset Database
```bash
rm data/vxdf_validate.db
python3 api/load_sarif_to_db.py
```

### Check Status
```bash
curl http://localhost:5001/api/stats
```

### View Logs
```bash
tail -f logs/vxdf_validate.log
```

---

## 📄 License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details. 