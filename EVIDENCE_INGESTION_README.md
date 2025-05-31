# VXDF Evidence Ingestion System

A comprehensive evidence ingestion system for the VXDF (Validated Exploitable Data Flow) engine that allows users to provide external evidence alongside scanner reports and upload individual evidence files linked to specific findings.

## 🚀 Features

### 1. External Evidence JSON Ingestion
- **Enhanced `/api/upload` endpoint** supports optional `external_evidence_json` parameter
- **Flexible finding matching** strategies to link evidence to scanner findings
- **Structured evidence validation** against normative VXDF Pydantic models
- **Database integration** for persistent evidence storage

### 2. Individual Evidence File Upload
- **New `/api/findings/{finding_id}/attach_evidence_file` endpoint** for file uploads
- **Multi-format support** including text files, images, scripts, logs
- **Intelligent file processing** based on evidence type hints
- **Metadata extraction** and structured data creation

### 3. Comprehensive Evidence Type Support
- **Network/HTTP Evidence**: Request/response logs, traffic captures
- **Code Evidence**: Source snippets, PoC scripts, analysis paths
- **Runtime Evidence**: Application logs, debugger output, exceptions
- **Visual Evidence**: Screenshots with embedded base64 encoding
- **Testing Evidence**: Test payloads, manual verification notes
- **System Evidence**: Command output, file system changes, database state

## 📋 Table of Contents

- [Installation & Setup](#installation--setup)
- [API Reference](#api-reference)
- [Usage Examples](#usage-examples)
- [Evidence Types](#evidence-types)
- [Finding Matcher Strategies](#finding-matcher-strategies)
- [Error Handling](#error-handling)
- [Testing](#testing)
- [Architecture](#architecture)

## 🛠 Installation & Setup

### Prerequisites
- Python 3.8+
- SQLAlchemy database setup
- Flask application running
- Required Python packages: `requests`, `pydantic`, `sqlalchemy`

### Setup Steps

1. **Install dependencies** (if not already installed):
   ```bash
   pip install flask sqlalchemy pydantic requests
   ```

2. **Import evidence handler utilities**:
   ```python
   from api.utils.evidence_handler import (
       FindingMatcher, EvidenceProcessor,
       create_evidence_from_structured_data,
       create_evidence_from_file_upload
   )
   ```

3. **Start the VXDF API server**:
   ```bash
   python3 -m api.server --port 5001
   ```

4. **Verify installation** by running tests:
   ```bash
   python tests/test_evidence_ingestion.py
   ```

## 📚 API Reference

### Enhanced Upload Endpoint

**POST** `/api/upload`

Upload scanner reports with optional external evidence.

**Parameters:**
- `file` (File, required): Scanner report file (SARIF, JSON, etc.)
- `parser_type` (String, optional): Parser type (default: "sarif")
- `external_evidence_json` (String, optional): JSON array of evidence objects

**Response:**
```json
{
  "message": "File processed successfully with 3 external evidence items",
  "vxdf_file": "vxdf_results_20240115-103000.vxdf.json",
  "evidenceProcessed": 3,
  "download_url": "/download/vxdf_results_20240115-103000.vxdf.json"
}
```

### Evidence File Upload Endpoint

**POST** `/api/findings/{finding_id}/attach_evidence_file`

Upload evidence files for specific findings.

**Parameters:**
- `finding_id` (Integer, path): Finding ID to attach evidence to
- `evidence_file` (File, required): Evidence file to upload
- `evidence_type_str` (String, required): Evidence type (see [Evidence Types](#evidence-types))
- `description` (String, required): Evidence description
- Additional parameters based on evidence type

**Response:**
```json
{
  "success": true,
  "message": "Evidence file 'screenshot.png' attached successfully to finding 123",
  "evidence_id": "evidence-uuid-here"
}
```

## 💡 Usage Examples

### Example 1: Upload Scanner Report with External Evidence

```bash
curl -X POST http://localhost:5001/api/upload \
  -F "file=@scan_results.sarif" \
  -F "parser_type=sarif" \
  -F "target_name=My Web Application" \
  -F 'external_evidence_json=[
    {
      "findingMatcher": {"cwe_match": 89},
      "evidenceType": "HTTP_REQUEST_LOG",
      "description": "SQL injection demonstration request",
      "data": {
        "method": "POST",
        "url": "/api/login",
        "headers": [
          {"name": "Content-Type", "value": "application/x-www-form-urlencoded"}
        ],
        "body": "username=admin&password=1'\'' OR '\''1'\''='\''1",
        "bodyEncoding": "plaintext"
      }
    }
  ]'
```

### Example 2: Upload Screenshot Evidence

```bash
curl -X POST http://localhost:5001/api/findings/123/attach_evidence_file \
  -F "evidence_file=@vulnerability_screenshot.png" \
  -F "evidence_type_str=SCREENSHOT_EMBEDDED_BASE64" \
  -F "description=Screenshot showing XSS vulnerability in action" \
  -F "caption=Browser displaying malicious script execution"
```

### Example 3: Upload PoC Script

```bash
curl -X POST http://localhost:5001/api/findings/456/attach_evidence_file \
  -F "evidence_file=@exploit.py" \
  -F "evidence_type_str=POC_SCRIPT" \
  -F "description=Python script demonstrating command injection" \
  -F "script_language=python" \
  -F "expected_outcome=Remote code execution confirmed"
```

### Example 4: Upload Log File

```bash
curl -X POST http://localhost:5001/api/findings/789/attach_evidence_file \
  -F "evidence_file=@application.log" \
  -F "evidence_type_str=RUNTIME_APPLICATION_LOG_ENTRY" \
  -F "description=Application logs showing exploitation attempt" \
  -F "log_source=WebApp-Production-Server" \
  -F "log_level=ERROR"
```

## 📝 Evidence Types

### Network/HTTP Evidence
- `HTTP_REQUEST_LOG` - HTTP request logs with method, URL, headers, body
- `HTTP_RESPONSE_LOG` - HTTP response logs with status, headers, body
- `NETWORK_TRAFFIC_CAPTURE_SUMMARY` - Network packet capture summaries

### Code Evidence
- `CODE_SNIPPET_SOURCE` - Vulnerable source code snippets
- `CODE_SNIPPET_SINK` - Data sink code snippets
- `CODE_SNIPPET_CONTEXT` - Contextual code snippets
- `POC_SCRIPT` - Proof of concept exploitation scripts

### Runtime Evidence
- `RUNTIME_APPLICATION_LOG_ENTRY` - Application log entries
- `RUNTIME_SYSTEM_LOG_ENTRY` - System log entries
- `RUNTIME_WEB_SERVER_LOG_ENTRY` - Web server log entries
- `RUNTIME_DATABASE_LOG_ENTRY` - Database log entries
- `RUNTIME_DEBUGGER_OUTPUT` - Debugger output and traces
- `RUNTIME_EXCEPTION_TRACE` - Exception stack traces

### Visual Evidence
- `SCREENSHOT_URL` - Screenshot URLs
- `SCREENSHOT_EMBEDDED_BASE64` - Base64 encoded screenshots

### Testing Evidence
- `TEST_PAYLOAD_USED` - Test payloads used in exploitation
- `MANUAL_VERIFICATION_NOTES` - Manual verification and testing notes

### Analysis Evidence
- `STATIC_ANALYSIS_DATA_FLOW_PATH` - Static analysis data flow paths
- `STATIC_ANALYSIS_CONTROL_FLOW_GRAPH` - Control flow graphs
- `CONFIGURATION_FILE_SNIPPET` - Configuration file snippets
- `VULNERABLE_COMPONENT_SCAN_OUTPUT` - SCA tool output

### System Evidence
- `COMMAND_EXECUTION_OUTPUT` - Command execution output
- `FILE_SYSTEM_CHANGE_PROOF` - File system change evidence
- `DATABASE_STATE_CHANGE_PROOF` - Database state change evidence
- `ENVIRONMENT_CONFIGURATION_DETAILS` - Environment configuration

### Other Evidence
- `TOOL_SPECIFIC_OUTPUT_LOG` - Tool-specific output logs
- `EXTERNAL_INTERACTION_PROOF` - External interaction proof
- `EXFILTRATED_DATA_SAMPLE` - Data exfiltration samples
- `SESSION_INFORMATION_LEAK` - Session information leaks
- `DIFFERENTIAL_ANALYSIS_RESULT` - Differential analysis results
- `MISSING_ARTIFACT_VERIFICATION` - Missing artifact verification
- `OBSERVED_BEHAVIORAL_CHANGE` - Behavioral change observations
- `OTHER_EVIDENCE` - Generic evidence type for unstructured data

## 🎯 Finding Matcher Strategies

The `findingMatcher` object supports multiple strategies for linking evidence to findings:

### Apply to All Findings
```json
{
  "findingMatcher": {
    "apply_to_all": true
  }
}
```

### Match by Scanner Rule ID
```json
{
  "findingMatcher": {
    "rule_id_match": "RULE_ID_123"
  }
}
```

### Match by CWE ID
```json
{
  "findingMatcher": {
    "cwe_match": 89
  }
}
```

### Match by Finding Name Pattern
```json
{
  "findingMatcher": {
    "name_pattern_match": "SQL.*injection"
  }
}
```

### Match by File Location
```json
{
  "findingMatcher": {
    "location_match": {
      "filePath": "src/login.py",
      "startLine": 42
    }
  }
}
```

## ⚠️ Error Handling

The system provides comprehensive error handling:

### Validation Errors (400 Bad Request)
- Invalid evidence type
- Missing required fields
- Malformed JSON in external evidence
- Invalid Pydantic model data

### Not Found Errors (404 Not Found)
- Finding ID not found
- Invalid file paths

### Server Errors (500 Internal Server Error)
- Database connection issues
- File processing errors
- Unexpected validation failures

**Example Error Response:**
```json
{
  "error": "Evidence validation failed",
  "details": "evidenceType 'INVALID_TYPE' is not supported"
}
```

## 🧪 Testing

### Run Comprehensive Tests

```bash
# Run all evidence ingestion tests
python tests/test_evidence_ingestion.py

# Run specific test categories
python tests/test_evidence_ingestion.py --test upload
python tests/test_evidence_ingestion.py --test files
python tests/test_evidence_ingestion.py --test errors

# Test against different API endpoints
python tests/test_evidence_ingestion.py --base-url http://localhost:5001/api
```

### Test Categories

1. **External Evidence JSON Tests**
   - Multiple evidence types
   - Various finding matcher strategies
   - Validation and error handling

2. **File Upload Tests**
   - Screenshot uploads (PNG images)
   - PoC script uploads (Python, shell scripts)
   - Log file uploads (application logs)
   - Command output uploads

3. **Error Handling Tests**
   - Invalid evidence types
   - Missing required fields
   - Malformed JSON
   - Database constraint violations

## 🏗 Architecture

### Core Components

1. **FindingMatcher Class**
   - Implements finding matching strategies
   - Supports regex patterns and exact matches
   - Handles location-based matching

2. **EvidenceProcessor Class**
   - Validates evidence types and data structures
   - Processes file content based on evidence type
   - Maps evidence to appropriate Pydantic models

3. **API Integration**
   - Enhanced `/upload` endpoint with JSON evidence support
   - New `/attach_evidence_file` endpoint for file uploads
   - Database integration with SQLAlchemy Evidence model

4. **Data Flow**
   ```
   Scanner Report + External Evidence JSON
                     ↓
   Parse findings + Match evidence to findings
                     ↓
   Validate evidence data against Pydantic models
                     ↓
   Store in database as JSON strings
                     ↓
   Generate enhanced VXDF documents
   ```

### Database Schema

The implementation uses the existing `Evidence` SQLAlchemy model:

```python
class Evidence(Base):
    id = Column(String, primary_key=True)
    finding_id = Column(String, ForeignKey('findings.id'))
    evidence_type = Column(String, nullable=False)
    description = Column(String, nullable=False)
    content = Column(Text, nullable=False)  # JSON string
    created_at = Column(DateTime, default=datetime.utcnow)
```

### File Processing Pipeline

1. **File Type Detection**: Based on MIME type and file extension
2. **Content Processing**: Text extraction, base64 encoding for binary files
3. **Data Structure Creation**: Map to appropriate Pydantic evidence models
4. **Validation**: Validate against normative VXDF schema
5. **Storage**: Serialize and store as JSON in database

## 🔧 Configuration

### Environment Variables

- `VXDF_API_PORT`: API server port (default: 5001)
- `DATABASE_URL`: Database connection string
- `UPLOAD_MAX_SIZE`: Maximum file upload size (default: 10MB)

### Evidence Type Configuration

Evidence type mappings are defined in `api/utils/evidence_handler.py` and can be extended for custom evidence types.

## 📖 Additional Resources

- [VXDF Specification](docs/specification.md)
- [API Documentation](docs/API.md)
- [Normative Schema](docs/normative-schema.json)
- [Contributing Guidelines](CONTRIBUTING.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add comprehensive tests
5. Update documentation
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Happy Evidence Ingesting! 🎉**

For questions, issues, or feature requests, please open an issue on the GitHub repository. 