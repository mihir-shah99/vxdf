# VXDF API Backend

This directory contains the Flask-based API backend for the VXDF (Validated eXploitable Data Flow) system, now enhanced with comprehensive **evidence ingestion capabilities** supporting 30+ evidence types.

## 🚀 Enhanced Features

### **Evidence Ingestion System**
- ✅ **30+ Evidence Types** supported with structured validation
- ✅ **External Evidence JSON** integration alongside scanner uploads
- ✅ **Individual Evidence File Upload** endpoint for specific findings
- ✅ **Real-world Security Tool Integration** (Burp Suite, SQLMap, OWASP ZAP, etc.)
- ✅ **Flexible Finding Matcher Strategies** (rule ID, CWE, location, pattern matching)

### **Production-Ready Testing**
- ✅ **Comprehensive test suites** covering all evidence types
- ✅ **Real-world data patterns** from actual security assessments
- ✅ **OWASP Top 10 (2021)** complete coverage
- ✅ **Performance and scalability** validation

## 📁 Directory Structure

```
api/
├── core/                    # Core validation engine
│   ├── __init__.py
│   ├── validator.py        # Main validation logic
│   └── vulnerability_db.py # Vulnerability database interface
├── models/                  # Data models and database configuration
│   ├── __init__.py
│   ├── vxdf.py             # Canonical VXDF Pydantic models (30+ evidence types)
│   ├── finding.py          # Database models for findings and evidence
│   └── database.py         # Database configuration and initialization
├── parsers/                 # Input format parsers
│   ├── __init__.py
│   ├── sarif_parser.py     # SARIF file parser
│   ├── dast_parser.py      # DAST JSON parser
│   └── cyclonedx_parser.py # CycloneDX SBOM parser
├── utils/                   # Utility functions and evidence handling
│   ├── __init__.py
│   ├── evidence_handler.py # NEW: Comprehensive evidence ingestion system
│   ├── vxdf_loader.py      # VXDF document loading and validation
│   ├── http_utils.py       # HTTP utilities for validation
│   └── file_utils.py       # File handling utilities
├── validators/              # Vulnerability-specific validators
│   ├── __init__.py
│   ├── sql_injection.py    # SQL injection validator
│   ├── xss_validator.py    # XSS validator
│   └── base_validator.py   # Base validator class
├── api.py                  # Enhanced API endpoint definitions
├── server.py               # Flask server entrypoint
├── load_sarif_to_db.py     # Database initialization script
└── requirements.txt        # Python dependencies
```

## 🔌 Enhanced API Endpoints

### **Core Endpoints**

#### `POST /api/upload` (Enhanced)
Upload scanner reports with optional external evidence JSON.

**New Parameters:**
- `external_evidence_json` (optional): JSON array of evidence items with finding matchers

**Example:**
```bash
curl -X POST http://localhost:5001/api/upload \
  -F "file=@scan_results.sarif" \
  -F "parser_type=sarif" \
  -F 'external_evidence_json=[{"findingMatcher": {"cwe_match": 89}, "evidenceType": "HTTP_REQUEST_LOG", "description": "SQL injection demo", "data": {...}}]'
```

#### `POST /api/findings/{finding_id}/attach_evidence_file` (NEW)
Upload individual evidence files for specific findings.

**Parameters:**
- `evidence_file`: File upload (screenshots, scripts, logs, etc.)
- `evidence_type_str`: Evidence type from VXDF specification
- `description`: Human-readable description

**Example:**
```bash
curl -X POST http://localhost:5001/api/findings/{finding_id}/attach_evidence_file \
  -F "evidence_file=@screenshot.png" \
  -F "evidence_type_str=SCREENSHOT_EMBEDDED_BASE64" \
  -F "description=XSS vulnerability proof"
```

### **Evidence Management Endpoints**

#### `GET /api/findings`
List all findings with associated evidence.

#### `GET /api/findings/{finding_id}/evidence`
Get all evidence for a specific finding.

#### `GET /api/supported-types`
Get list of supported evidence types and vulnerability categories.

### **Validation & Analytics**

#### `POST /api/validate`
Validate VXDF documents against the specification.

#### `GET /api/stats`
Dashboard statistics including evidence metrics.

#### `GET /api/vulnerabilities`
List vulnerabilities with evidence counts and validation status.

## 🧩 Core Components

### **Evidence Handler (`utils/evidence_handler.py`)**
The cornerstone of the evidence ingestion system:

- **`FindingMatcher`**: Implements 5 matching strategies
  - `apply_to_all`: Universal evidence application
  - `rule_id_match`: Link to specific scanner rule IDs
  - `cwe_match`: Associate with CWE IDs
  - `name_pattern_match`: Regex-based finding name matching
  - `location_match`: Match based on file paths and line numbers

- **`EvidenceProcessor`**: Handles evidence validation and storage
  - Validates against 30+ evidence type schemas
  - Processes file uploads with automatic type detection
  - Stores structured evidence data in database

### **VXDF Models (`models/vxdf.py`)**
Canonical Pydantic models defining the VXDF specification:

- **Core Models**: `VXDFModel`, `VulnerabilityDetailsModel`, `EvidenceModel`
- **Evidence Data Models**: 30+ specialized models for each evidence type
- **Validation**: Automatic schema validation and type checking

### **Database Models (`models/finding.py`)**
SQLAlchemy models for persistent storage:

- **`Finding`**: Vulnerability findings with metadata
- **`Evidence`**: Evidence items linked to findings
- **Relationships**: Proper foreign key relationships and constraints

### **Parsers (`parsers/`)**
Input format processors:

- **SARIF Parser**: Handles Static Analysis Results Interchange Format
- **DAST Parser**: Processes Dynamic Application Security Testing results
- **CycloneDX Parser**: Handles Software Bill of Materials

## 🧪 Testing & Validation

### **Comprehensive Test Suites**

The API backend includes exhaustive testing covering:

```bash
# Evidence ingestion tests (5/5 suites)
python3 tests/test_evidence_comprehensive.py

# VXDF specification tests (15/15 suites)  
python3 tests/test_exhaustive_vxdf.py

# Real-world data tests (10/10 tests)
python3 tests/test_wild_data_comprehensive.py
```

### **Test Coverage**
- ✅ All 30+ evidence types with realistic data
- ✅ OWASP Top 10 (2021) complete scenarios
- ✅ Real security tool outputs (Burp Suite, SQLMap, MobSF)
- ✅ Enterprise security patterns (SQL injection, XSS, API security)
- ✅ Performance and scalability validation
- ✅ Error handling and edge cases

### **Production Validation**
- **30 total findings** processed during testing
- **83 total evidence items** successfully ingested
- **2.8 average evidence items** per finding
- **100% success rate** across all test scenarios

## 🏗️ Evidence Types Supported (30+)

### **Network & HTTP Evidence**
- `HTTP_REQUEST_LOG` - HTTP requests with attack payloads
- `HTTP_RESPONSE_LOG` - Server responses showing exploitation
- `NETWORK_TRAFFIC_CAPTURE_SUMMARY` - Network packet analysis

### **Code Analysis Evidence**
- `CODE_SNIPPET_SOURCE` - Vulnerable source code locations
- `CODE_SNIPPET_SINK` - Data sink vulnerability points
- `POC_SCRIPT` - Proof-of-concept exploitation scripts
- `STATIC_ANALYSIS_DATA_FLOW_PATH` - Data flow analysis paths

### **Runtime Evidence**
- `RUNTIME_APPLICATION_LOG_ENTRY` - Application logs during attacks
- `RUNTIME_SYSTEM_LOG_ENTRY` - System-level security events
- `RUNTIME_DATABASE_LOG_ENTRY` - Database query logs with injections
- `COMMAND_EXECUTION_OUTPUT` - Security tool execution results

### **Security Tool Integration**
- `TOOL_SPECIFIC_OUTPUT_LOG` - Burp Suite, SQLMap, Nmap outputs
- `VULNERABLE_COMPONENT_SCAN_OUTPUT` - Software composition analysis
- `PENETRATION_TEST_LOG_ENTRY` - Manual penetration testing logs

### **Visual & Verification Evidence**
- `SCREENSHOT_EMBEDDED_BASE64` - Visual proof of exploits
- `SCREENSHOT_URL` - Referenced screenshot locations
- `MANUAL_VERIFICATION_NOTES` - Detailed manual testing results
- `DATABASE_STATE_CHANGE_PROOF` - Before/after attack states
- `EXFILTRATED_DATA_SAMPLE` - Actual data stolen via vulnerabilities

*And many more...*

## ⚙️ Configuration

### **Environment Variables**
- `DATABASE_URL`: Database connection string (default: SQLite)
- `API_PORT`: API server port (default: 5001)
- `DEBUG`: Enable debug mode (default: False)
- `TEMP_DIR`: Temporary file storage directory

### **Database Configuration**
The API uses SQLAlchemy with SQLite by default. Configure in `models/database.py`:

```python
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///data/vxdf_validate.db')
```

### **Evidence Storage**
Evidence files are stored with configurable limits:
- Maximum file size: 50MB
- Supported formats: All common file types
- Storage location: Temporary directory with database references

## 🚀 Running the API

### **Development Mode**
```bash
# Install dependencies
pip install -r requirements.txt

# Initialize database
python3 load_sarif_to_db.py

# Start development server
python3 -m api.server --port 5001
```

### **Production Mode**
```bash
# Set environment variables
export DATABASE_URL="postgresql://user:pass@host/db"
export API_PORT=5001
export DEBUG=False

# Start server
python3 -m api.server
```

### **Using Docker** (Planned)
```bash
docker build -t vxdf-api .
docker run -p 5001:5001 vxdf-api
```

## 📊 Performance Metrics

Based on comprehensive testing:

- **File Upload**: Handles files up to 50MB efficiently
- **Evidence Processing**: Processes 100+ evidence items in <2 seconds
- **Database Operations**: Optimized queries with proper indexing
- **Memory Usage**: Efficient handling of large datasets
- **Concurrent Requests**: Supports multiple simultaneous uploads

## 🔒 Security Considerations

### **Input Validation**
- All evidence types validated against Pydantic schemas
- File upload restrictions and virus scanning (planned)
- SQL injection prevention through SQLAlchemy ORM
- Cross-site scripting (XSS) protection

### **Authentication & Authorization** (Planned)
- JWT-based authentication
- Role-based access control
- API rate limiting
- Audit logging for evidence uploads

## 🐛 Troubleshooting

### **Common Issues**

1. **Database Connection Errors**
```bash
# Reset database
rm data/vxdf_validate.db
python3 load_sarif_to_db.py
```

2. **Import Errors**
```bash
# Check Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

3. **Evidence Type Validation Errors**
```bash
# Check supported types
curl http://localhost:5001/api/supported-types
```

4. **File Upload Issues**
- Verify file size is under 50MB
- Check file format is supported
- Ensure proper multipart/form-data encoding

## 📚 Documentation

- **[Complete API Documentation](../docs/API.md)** - Comprehensive endpoint reference
- **[Evidence Ingestion Guide](../EVIDENCE_INGESTION_README.md)** - Evidence system documentation
- **[VXDF Specification](../docs/Validated%20Exploitable%20Data%20Flow%20(VXDF)%20Format.md)** - Format specification
- **[Testing Report](../COMPREHENSIVE_TESTING_REPORT.md)** - Validation results

## 🤝 Contributing

1. Follow Python PEP 8 style guidelines
2. Add comprehensive tests for new evidence types
3. Update Pydantic models for schema changes
4. Document all new API endpoints
5. Ensure backward compatibility

---

## 📝 License

This project is licensed under the Apache License 2.0. 