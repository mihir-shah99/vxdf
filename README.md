<div align="center">
<img src="frontend/src/assets/VXDF logo.png" alt="VXDF Logo" width="200"/>
</div>

# VXDF: Validated eXploitable Data Flow

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Frontend](https://img.shields.io/badge/frontend-React%2FTS-blue)
![Backend](https://img.shields.io/badge/backend-Python%2FFlask-yellow)
![Evidence Types](https://img.shields.io/badge/evidence_types-30%2B-green)
![Testing](https://img.shields.io/badge/testing-comprehensive-brightgreen)

---

## 🖼️ Demo

<img src="frontend/src/assets/dashboard.png" alt="VXDF Dashboard" width="100%" style="border-radius:8px;box-shadow:0 2px 8px #0002;"/>

*VXDF Dashboard*

---

> **VXDF (Validated eXploitable Data Flow)** is a next-generation security validation platform for verifying, validating, and reporting on security findings from any scanner. Now with **comprehensive evidence ingestion** supporting 30+ evidence types from real-world security tools.

---

## 📑 Table of Contents
- [Core Architecture](#core-architecture)
- [Key Features](#-key-features)
- [Evidence Ingestion System](#-evidence-ingestion-system)
- [Key Components](#-key-components)
- [Validation Workflow](#-validation-workflow)
- [Data Model](#-data-model)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Running the Application](#-running-the-application)
- [API Documentation](#-api-documentation)
- [Testing](#-testing)
- [Documentation](#-documentation)
- [License](#-license)

---

## 🏛️ Core Architecture

VXDF follows a modular microservices architecture with clear separation between:

1. **Validation Engine** - Core vulnerability verification logic
2. **API Layer** - RESTful interface with comprehensive evidence ingestion
3. **Data Processing** - SARIF/DAST/CycloneDX parsing pipeline
4. **Evidence Collection** - Automated exploit validation and evidence ingestion system
5. **Reporting** - VXDF format generation and export

![VXDF Architecture](docs/screenshots/architecture.png)

---

## ✨ Key Features

### 🔍 **Advanced Evidence Ingestion**
- **30+ Evidence Types** supported (HTTP logs, code snippets, screenshots, tool outputs)
- **External Evidence JSON** integration with scanner uploads
- **Individual Evidence File Upload** endpoint for specific findings
- **Real-world Security Tool Integration** (Burp Suite, SQLMap, OWASP ZAP, MobSF, etc.)

### 🛡️ **Comprehensive Security Validation**
- **OWASP Top 10 (2021)** complete coverage
- **Enterprise-grade** SQL injection, XSS, and vulnerability testing
- **Mobile Application Security** testing support
- **Cloud Infrastructure Security** assessment capabilities

### 📊 **Production-Ready Testing**
- **Exhaustive test suites** covering all evidence types
- **Real-world data patterns** from actual security assessments
- **Performance testing** with large-scale data processing
- **Error handling** and edge case validation

---

## 🔗 Evidence Ingestion System

VXDF now includes a **comprehensive evidence ingestion system** that allows security professionals to attach evidence from any source to vulnerability findings.

### **Supported Evidence Types (30+)**

#### **Network & HTTP Evidence**
- `HTTP_REQUEST_LOG` - Request logs with SQL injection payloads, XSS attempts
- `HTTP_RESPONSE_LOG` - Server responses showing successful exploits
- `NETWORK_TRAFFIC_CAPTURE_SUMMARY` - Packet analysis results

#### **Code Analysis Evidence**
- `CODE_SNIPPET_SOURCE` - Vulnerable source code (Java, Python, JavaScript)
- `CODE_SNIPPET_SINK` - Data sink vulnerability points
- `POC_SCRIPT` - Complete exploitation scripts and proof-of-concepts

#### **Runtime Evidence**
- `RUNTIME_APPLICATION_LOG_ENTRY` - Application logs showing attacks
- `RUNTIME_SYSTEM_LOG_ENTRY` - System-level security events
- `RUNTIME_DATABASE_LOG_ENTRY` - Database query logs with injections
- `COMMAND_EXECUTION_OUTPUT` - Security tool execution results

#### **Security Tool Integration**
- `TOOL_SPECIFIC_OUTPUT_LOG` - Burp Suite, SQLMap, Nmap, OWASP ZAP outputs
- `VULNERABLE_COMPONENT_SCAN_OUTPUT` - SCA scan results
- `STATIC_ANALYSIS_DATA_FLOW_PATH` - SAST tool analysis paths

#### **Visual & Verification Evidence**
- `SCREENSHOT_EMBEDDED_BASE64` - Visual proof of exploits
- `MANUAL_VERIFICATION_NOTES` - Detailed manual testing results
- `DATABASE_STATE_CHANGE_PROOF` - Before/after attack state changes
- `EXFILTRATED_DATA_SAMPLE` - Actual data stolen via vulnerabilities

### **Finding Matcher Strategies**
- **Rule ID Matching** - Link evidence to specific scanner rule IDs
- **CWE Matching** - Associate evidence with Common Weakness Enumeration IDs
- **Location Matching** - Match based on file paths and line numbers
- **Pattern Matching** - Regex-based finding name/description matching
- **Apply to All** - Universal evidence application

---

## 🧩 Key Components

### Backend Services
- **Validation Engine**: Core business logic for vulnerability verification
- **Flask API**: RESTful endpoints with evidence ingestion capabilities
- **SQLAlchemy ORM**: Database management with finding and evidence models
- **Parser System**: Modular input processors (SARIF, DAST, CycloneDX)
- **Evidence Handler**: Comprehensive evidence processing and validation
- **Validator Plugins**: Vulnerability-specific validation logic

### Frontend Features
- **React/TypeScript**: Modern UI with Vite build system
- **Dynamic Dashboard**: Real-time validation statistics
- **Evidence Viewer**: Comprehensive evidence inspection interface
- **File Upload**: Support for scanner reports and individual evidence files
- **Report Generator**: Export of findings in VXDF format

---

## 🔄 Validation Workflow

1. **Input Ingestion**
   - Accepts SARIF, DAST JSON, CycloneDX SBOMs
   - **NEW**: External evidence JSON alongside scanner reports
   - **NEW**: Individual evidence file uploads for specific findings

2. **Evidence Processing**
   - Validates evidence against 30+ supported types
   - Links evidence to findings using flexible matching strategies
   - Stores structured evidence data in database

3. **Vulnerability Processing**
   - Filters by severity/vulnerability type
   - Enriches with CWE/CVSS data
   - Associates with collected evidence

4. **Automated Validation**
   - Docker-based isolated testing
   - Evidence collection (HTTP requests, stack traces)
   - Exploitability confirmation

5. **Reporting**
   - Generates VXDF-standard reports with comprehensive evidence
   - Maintains audit trail of validation attempts and evidence

---

## 🗃️ Data Model

The canonical data model for VXDF is defined using Pydantic in Python, located in `api/models/vxdf.py`. This provides a structured and validated way to represent security findings according to the VXDF specification.

### **Core Models**
- **`VXDFModel`**: Root model encapsulating the entire VXDF document
- **`VulnerabilityDetailsModel`**: Single vulnerability with evidence and exploit flows
- **`EvidenceModel`**: Evidence items with type-specific structured data
- **`ExploitFlowModel`**: Sequence of attack steps with evidence references

### **Evidence Data Models (30+ Types)**
Each evidence type has a corresponding Pydantic model for structured validation:
- `HttpRequestDataModel`, `HttpResponseDataModel`
- `CodeSnippetDataModel`, `PocScriptDataModel`
- `ApplicationLogDataModel`, `CommandOutputDataModel`
- `ScreenshotDataModel`, `ManualVerificationDataModel`
- And many more...

For the complete normative JSON schema, refer to [docs/normative-schema.json](docs/normative-schema.json).

---

## 📁 Project Structure

```
vxdf/
├── api/                          # Backend API and core functionality
│   ├── core/                     # Core validation engine
│   ├── models/                   # VXDF Pydantic models and database models
│   │   ├── vxdf.py              # Canonical VXDF specification models
│   │   ├── finding.py           # Database models for findings and evidence
│   │   └── database.py          # Database configuration
│   ├── parsers/                  # Input format parsers (SARIF, etc.)
│   ├── utils/                    # Utility functions and evidence handling
│   │   ├── evidence_handler.py  # NEW: Evidence ingestion system
│   │   ├── vxdf_loader.py       # VXDF document loading and validation
│   │   └── http_utils.py        # HTTP utilities for validation
│   ├── validators/               # Vulnerability validators
│   ├── api.py                   # API endpoint definitions (enhanced)
│   └── server.py                # Flask server entrypoint
├── tests/                        # Comprehensive test suites
│   ├── test_evidence_comprehensive.py    # NEW: Comprehensive evidence tests
│   ├── test_exhaustive_vxdf.py          # NEW: Exhaustive VXDF tests
│   ├── test_wild_data_comprehensive.py   # NEW: Real-world data tests
│   ├── test_evidence_ingestion.py       # Evidence ingestion unit tests
│   └── test_vxdf_loader.py              # VXDF loader tests
├── frontend/                     # React/TypeScript frontend
│   ├── src/                     # Frontend source code
│   └── package.json             # NPM dependencies
├── docs/                        # Documentation
│   ├── API.md                   # Comprehensive API documentation
│   ├── normative-schema.json    # VXDF JSON schema
│   └── Validated Exploitable Data Flow (VXDF) Format.md
├── config/                      # Configuration files
├── data/                        # Database files
├── output/                      # Generated VXDF reports
├── scripts/                     # Utility scripts
├── EVIDENCE_INGESTION_README.md # NEW: Evidence ingestion guide
├── COMPREHENSIVE_TESTING_REPORT.md # NEW: Testing validation report
└── README.md                    # This file
```

### Key Configuration Files

- `api/requirements.txt` - Backend Python dependencies
- `api/models/vxdf.py` - Canonical VXDF Pydantic models
- `api/utils/evidence_handler.py` - Evidence ingestion system
- `docs/normative-schema.json` - VXDF JSON schema
- `frontend/vite.config.ts` - Frontend configuration
- `data/vxdf_validate.db` - SQLite database

### Important Paths

- Backend API: http://localhost:5001
- Frontend UI: http://localhost:3000
- API Documentation: http://localhost:5001/apidocs
- Log files: `logs/backend.log` and `logs/frontend.log`

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

### Quick Start (Recommended)

The easiest and most reliable way to start the VXDF v1.0.0 application:

```bash
# One-command startup with automatic dependency installation and validation
python3 start_vxdf.py
```

This comprehensive startup script will:
- ✅ Check all prerequisites (Python 3.9+, Node.js, npm)
- 📦 Install Python and Node.js dependencies automatically
- 🔌 Verify port availability (5001 for backend, 3000 for frontend)
- 🔧 Start the backend API server
- 🎨 Start the frontend development server
- 🧪 Run integration tests to verify everything works
- 🎉 Provide clear status updates and error messages

### Enhanced API Server

```bash
# Start the enhanced API server with evidence ingestion capabilities
python3 -m api.server --port 5001
```

### Alternative: Shell Scripts

You can also use the provided shell scripts for more control:

```bash
# Start both backend and frontend with one command
./scripts/start-all.sh

# To stop all services
./scripts/stop-all.sh

# Start individual services
./scripts/start.sh              # Backend only
./scripts/start-frontend.sh     # Frontend only
```

The backend will be available at http://localhost:5001 and the frontend at http://localhost:3000.

### Manual Setup

If you prefer to set up the application manually:

#### Backend

1. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Initialize the database (if it doesn't exist):
```bash
python3 api/load_sarif_to_db.py
```

4. Start the API server:
```bash
python3 -m api.server --port 5001
```

#### Frontend

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

---

## 📚 API Documentation

### **Enhanced API Endpoints**

#### **Core Endpoints**
- `POST /api/upload` - **Enhanced** with external evidence JSON support
- `POST /api/findings/{finding_id}/attach_evidence_file` - **NEW** Individual evidence upload
- `POST /api/validate` - VXDF document validation
- `GET /api/vulnerabilities` - List vulnerabilities with evidence
- `GET /api/stats` - Dashboard statistics
- `GET /api/findings` - List all findings
- `GET /api/supported-types` - Supported vulnerability types

#### **Evidence-Specific Features**
- Upload evidence files with automatic type detection
- Support for 30+ evidence types with structured validation
- Real-world security tool output integration
- Flexible finding matcher strategies

### **Usage Examples**

#### Upload Scanner Report with External Evidence
```bash
curl -X POST http://localhost:5001/api/upload \
  -F "file=@scan_results.sarif" \
  -F "parser_type=sarif" \
  -F 'external_evidence_json=[{"findingMatcher": {"cwe_match": 89}, "evidenceType": "HTTP_REQUEST_LOG", "description": "SQL injection demo", "data": {...}}]'
```

#### Upload Individual Evidence File
```bash
curl -X POST http://localhost:5001/api/findings/{finding_id}/attach_evidence_file \
  -F "evidence_file=@screenshot.png" \
  -F "evidence_type_str=SCREENSHOT_EMBEDDED_BASE64" \
  -F "description=XSS vulnerability proof"
```

See [docs/API.md](docs/API.md) for complete API documentation.

---

## 🧪 Testing

### **Comprehensive Test Suites**

VXDF includes the most **exhaustive testing possible** for security evidence ingestion:

```bash
# Run comprehensive evidence ingestion tests (5/5 suites)
python3 tests/test_evidence_comprehensive.py

# Run exhaustive VXDF specification tests (15/15 suites)
python3 tests/test_exhaustive_vxdf.py

# Run real-world data pattern tests (10/10 tests)
python3 tests/test_wild_data_comprehensive.py

# Run evidence ingestion unit tests
python3 tests/test_evidence_ingestion.py
```

### **Test Coverage**
- ✅ **All 30+ evidence types** tested with realistic data
- ✅ **OWASP Top 10 (2021)** complete coverage
- ✅ **Real security tool outputs** (Burp Suite, SQLMap, MobSF, etc.)
- ✅ **Enterprise security scenarios** (SQL injection, XSS, API security)
- ✅ **Performance and scalability** testing
- ✅ **Error handling and edge cases**
- ✅ **100% success rate** across all test scenarios

### **Test Results Summary**
- **30 total findings** created during testing
- **83 total evidence items** successfully processed
- **2.8 average evidence items** per finding
- **Production-ready validation** across all scenarios

See [COMPREHENSIVE_TESTING_REPORT.md](COMPREHENSIVE_TESTING_REPORT.md) for detailed test results.

---

## ⚙️ Dynamic Configuration
- **Sidebar navigation**: Driven by `frontend/src/config/sidebarConfig.ts`
- **Dashboard data**: All stats, charts, and tables are fetched from the backend API
- **Evidence types**: Dynamically loaded from backend configuration
- **Branding**: Logo and product name are configurable
- **API endpoints**: Configurable through environment variables

---

## 📚 Documentation

### **Core Documentation**
- **[Evidence Ingestion Guide](EVIDENCE_INGESTION_README.md)** - Complete evidence system documentation
- **[API Documentation](docs/API.md)** - Comprehensive API reference
- **[VXDF Format Specification](docs/Validated%20Exploitable%20Data%20Flow%20(VXDF)%20Format.md)** - Format specification
- **[Testing Report](COMPREHENSIVE_TESTING_REPORT.md)** - Comprehensive testing validation
- **[Installation Guide](INSTALLATION.md)** - Detailed setup instructions

### **Additional Resources**
- **[Contributing Guide](CONTRIBUTING.md)** - Development guidelines
- **[Startup Guide](docs/STARTUP.md)** - Quick start instructions
- **[Normative Schema](docs/normative-schema.json)** - VXDF JSON schema

---

## 🔧 Avoiding Common Issues

1. **Port Configuration**: Backend runs on **port 5001**, frontend on **port 3000**
2. **Database Connection**: Ensure `data/vxdf_validate.db` is accessible and initialized
3. **Evidence Types**: Use exact evidence type names from the VXDF specification
4. **Finding IDs**: Use string UUIDs, not integers, for finding identification
5. **Import Order**: Always import models in correct order to avoid circular imports

---

## ❓ Troubleshooting

### **Common Issues**

1. **Reset the database**:
```bash
rm data/vxdf_validate.db
python3 api/load_sarif_to_db.py
```

2. **Check logs**:
```bash
tail -f logs/backend.log
tail -f logs/frontend.log
```

3. **Verify API is accessible**:
```bash
curl http://localhost:5001/api/stats
```

4. **Clear temporary files**:
```bash
rm -rf logs/*.log
rm -f .vxdf_pids
```

5. **Fix port conflicts**:
```bash
lsof -ti:5001,3000 | xargs kill -9
```

### **Evidence Ingestion Issues**

1. **Invalid evidence types**: Check supported types with `GET /api/supported-types`
2. **Finding matcher failures**: Verify finding IDs exist in database
3. **File upload errors**: Ensure file size is within limits and format is supported

---

## 🛠️ Makefile

A `Makefile` is provided for easy startup and health checks:

- `make dev` — Start both backend and frontend in dev mode
- `make check` — Run health checks to ensure both servers are up and API endpoints respond

---

## 🏆 Key Achievements

### **Production-Ready Features**
- ✅ **Comprehensive evidence ingestion** system with 30+ types
- ✅ **Real-world security tool integration** (Burp Suite, SQLMap, etc.)
- ✅ **Enterprise-grade testing** covering all security scenarios
- ✅ **VXDF specification compliance** with full validation
- ✅ **Performance and scalability** for production deployment

### **Security Coverage**
- ✅ **OWASP Top 10 (2021)** complete validation
- ✅ **Enterprise SQL injection** with database dump capabilities
- ✅ **Advanced XSS scenarios** including CSP bypass
- ✅ **API security weaknesses** and JWT vulnerabilities
- ✅ **Mobile application security** comprehensive testing
- ✅ **Cloud infrastructure security** assessment support

---

## 📝 License

This project is licensed under the Apache License 2.0 — see the [LICENSE](./LICENSE) file for details.

---

## 👤 Author
Mihir Shah <mihirshah@vxdf.org>

---

## 👥 Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [INSTALLATION.md](INSTALLATION.md) for details on our code of conduct and the process for submitting pull requests. 