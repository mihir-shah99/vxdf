# VXDF Validate API Documentation

This document describes the API endpoints provided by the VXDF Validate backend.

## Base URL

All API endpoints are relative to the base URL:

```
http://localhost:5001/api
```

To run the application locally:

- Start the backend:
  ```bash
  python3 -m api.server --port 5001
  ```
- Start the frontend:
  ```bash
  npm run dev --prefix frontend
  ```

For production deployments, replace with your actual domain and port.

## Authentication

Authentication is not currently implemented. Future versions will support authentication mechanisms.

## Endpoints

### Get Statistics

Get statistics about findings in the database.

**URL**: `/stats`

**Method**: `GET`

**Response**:

```json
{
  "total_findings": 25,
  "validated_findings": 20,
  "exploitable_findings": 12,
  "by_type": {
    "sql_injection": 7,
    "xss": 10,
    "path_traversal": 5,
    "command_injection": 3
  },
  "by_severity": {
    "CRITICAL": 3,
    "HIGH": 8,
    "MEDIUM": 10,
    "LOW": 4,
    "INFORMATIONAL": 0
  }
}
```

### Get Supported Vulnerability Types

Get a list of supported vulnerability types.

**URL**: `/supported-types`

**Method**: `GET`

**Response**:

```json
[
  "sql_injection",
  "xss",
  "path_traversal",
  "command_injection"
]
```

### Upload File

Upload and process security scan files (SARIF, JSON, etc.) with optional external evidence.

**URL**: `/upload`

**Method**: `POST`

**Content-Type**: `multipart/form-data`

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| file | File | Yes | The scan file to upload |
| parser_type | String | No | Type of parser to use (sarif, json, csv). Default: sarif |
| validate | Boolean | No | Whether to validate findings. Default: true |
| target_name | String | No | Name of the target application |
| target_version | String | No | Version of the target application |
| vuln_types | Array[String] | No | Vulnerability types to process |
| min_severity | String | No | Minimum severity to include (LOW, MEDIUM, HIGH, CRITICAL). Default: LOW |
| strict | Boolean | No | Whether to perform strict validation. Default: false |
| external_evidence_json | String | No | JSON string containing array of external evidence items |

**External Evidence JSON Format**:

The `external_evidence_json` parameter should contain a JSON string representing an array of evidence objects. Each evidence object must have the following structure:

```json
[
  {
    "findingMatcher": {
      // One of the following matching strategies:
      "apply_to_all": true,  // Apply to all findings
      // OR
      "rule_id_match": "RULE_ID_123",  // Match by scanner rule ID
      // OR  
      "cwe_match": 89,  // Match by CWE ID
      // OR
      "name_pattern_match": "SQL.*injection",  // Match by regex pattern on finding name
      // OR
      "location_match": {  // Match by file location
        "filePath": "src/main.py",
        "startLine": 42  // optional
      }
    },
    "evidenceType": "HTTP_REQUEST_LOG",  // Must be valid EvidenceTypeEnum value
    "description": "HTTP request demonstrating SQL injection",
    "data": {
      // Data structure depends on evidenceType
      // For HTTP_REQUEST_LOG:
      "method": "POST",
      "url": "/api/users",
      "headers": [
        {"name": "Content-Type", "value": "application/json"}
      ],
      "body": "{\"id\": \"1' OR '1'='1\"}",
      "bodyEncoding": "plaintext"
    },
    "validationMethod": "MANUAL_PENETRATION_TESTING_EXPLOIT",  // Optional
    "timestamp": "2024-01-15T10:30:00Z"  // Optional, ISO 8601 format
  }
]
```

**Evidence Types and Data Structures**:

The `evidenceType` field must be one of the supported VXDF evidence types, and the corresponding `data` object must match the expected structure:

- `HTTP_REQUEST_LOG`: Requires `method`, `url`; optional `headers`, `body`, `bodyEncoding`
- `HTTP_RESPONSE_LOG`: Requires `statusCode`; optional `url`, `headers`, `body`, `bodyEncoding`
- `CODE_SNIPPET_SOURCE|SINK|CONTEXT`: Requires `content`; optional `language`, `filePath`, `startLine`, `endLine`
- `POC_SCRIPT`: Requires `scriptLanguage`, `scriptContent`; optional `scriptArguments`, `expectedOutcome`
- `RUNTIME_APPLICATION_LOG_ENTRY`: Requires `message`; optional `logSourceIdentifier`, `logLevel`, etc.
- `SCREENSHOT_EMBEDDED_BASE64`: Requires `imageDataBase64`, `imageFormat`; optional `caption`
- `TEST_PAYLOAD_USED`: Requires `payloadContent`; optional `payloadDescription`, `payloadEncoding`
- `MANUAL_VERIFICATION_NOTES`: Requires `verificationSteps`, `observedOutcome`; optional `testerName`, `toolsUsed`
- `CONFIGURATION_FILE_SNIPPET`: Requires `filePath`, `snippet`; optional `settingName`, `interpretation`
- `COMMAND_EXECUTION_OUTPUT`: Requires `command`, `output`; optional `exitCode`, `executionContext`
- `OTHER_EVIDENCE`: Requires `dataTypeDescription`, `dataContent`; optional `encodingFormat`

**Response**:

```json
{
  "message": "File processed successfully with 3 external evidence items",
  "vxdf_file": "vxdf_results_20240115-103000.vxdf.json",
  "validation_mode": "normal",
  "download_url": "/download/vxdf_results_20240115-103000.vxdf.json",
  "evidenceProcessed": 3
}
```

### Attach Evidence File to Finding

Upload an evidence file and attach it to an existing finding.

**URL**: `/findings/{finding_id}/attach_evidence_file`

**Method**: `POST`

**Content-Type**: `multipart/form-data`

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| finding_id | Integer | Yes | ID of the finding to attach evidence to (path parameter) |
| evidence_file | File | Yes | The evidence file to upload |
| evidence_type_str | String | Yes | Type of evidence (must be valid EvidenceTypeEnum value) |
| description | String | Yes | Description of the evidence |
| validation_method_str | String | No | Validation method used (ValidationMethodEnum value) |
| timestamp_str | String | No | Timestamp in ISO 8601 format |

**Additional Parameters for Specific Evidence Types**:

| Name | Type | Description | Evidence Types |
|------|------|-------------|----------------|
| language | String | Programming language | CODE_SNIPPET_* |
| script_language | String | Script language | POC_SCRIPT |
| command | String | Command executed | COMMAND_EXECUTION_OUTPUT |
| tool_name | String | Tool name | TOOL_SPECIFIC_OUTPUT_LOG |
| caption | String | Image caption | SCREENSHOT_EMBEDDED_BASE64 |
| log_source | String | Log source identifier | RUNTIME_*_LOG_ENTRY |
| log_level | String | Log level | RUNTIME_*_LOG_ENTRY |
| component_name | String | Component name | RUNTIME_*_LOG_ENTRY |
| file_path | String | File path override | CODE_SNIPPET_*, CONFIGURATION_FILE_SNIPPET |
| start_line | Integer | Starting line number | CODE_SNIPPET_* |
| end_line | Integer | Ending line number | CODE_SNIPPET_* |
| script_arguments | Array[String] | Script arguments | POC_SCRIPT |
| expected_outcome | String | Expected outcome | POC_SCRIPT |
| setting_name | String | Configuration setting name | CONFIGURATION_FILE_SNIPPET |
| interpretation | String | Interpretation of the data | CONFIGURATION_FILE_SNIPPET |
| exit_code | Integer | Command exit code | COMMAND_EXECUTION_OUTPUT |
| execution_context | String | Execution context | COMMAND_EXECUTION_OUTPUT |
| tool_version | String | Tool version | TOOL_SPECIFIC_OUTPUT_LOG |
| command_line | String | Command line executed | TOOL_SPECIFIC_OUTPUT_LOG |
| data_type_description | String | Data type description | OTHER_EVIDENCE |

**Response**:

```json
{
  "success": true,
  "message": "Evidence file 'screenshot.png' attached successfully to finding 123",
  "evidence_id": "evidence-uuid-here"
}
```

**Example cURL Commands**:

```bash
# Upload scan with external evidence
curl -X POST http://localhost:5001/api/upload \
  -F "file=@scan_results.sarif" \
  -F "parser_type=sarif" \
  -F "target_name=My Application" \
  -F 'external_evidence_json=[{"findingMatcher":{"cwe_match":89},"evidenceType":"HTTP_REQUEST_LOG","description":"SQL injection request","data":{"method":"POST","url":"/api/login","body":"username=admin&password=1'\''OR'\''1'\''='\''1"}}]'

# Attach evidence file to finding
curl -X POST http://localhost:5001/api/findings/123/attach_evidence_file \
  -F "evidence_file=@screenshot.png" \
  -F "evidence_type_str=SCREENSHOT_EMBEDDED_BASE64" \
  -F "description=Screenshot showing SQL injection vulnerability" \
  -F "caption=Login page with malicious input"
```

### Download VXDF File

Download a generated VXDF file.

**URL**: `/download/{filename}`

**Method**: `GET`

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| filename | String | Yes | Name of the VXDF file to download |

**Response**: VXDF file download with appropriate headers

### Get Vulnerabilities

Get a list of vulnerabilities/findings.

**URL**: `/vulnerabilities`

**Method**: `GET`

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| page | Integer | No | Page number for pagination (default: 1) |
| limit | Integer | No | Number of items per page (default: 10) |
| severity | String | No | Filter by severity level |
| type | String | No | Filter by vulnerability type |
| validated | Boolean | No | Filter by validation status |

**Response**:

```json
{
  "vulnerabilities": [
    {
      "id": "123",
      "name": "SQL Injection in login form",
      "type": "sql_injection",
      "severity": "HIGH",
      "isValidated": true,
      "isExploitable": true,
      "evidence": [
        {
          "id": "evidence-1",
          "type": "HTTP_REQUEST_LOG",
          "description": "Malicious SQL injection request"
        }
      ]
    }
  ],
  "total": 50,
  "page": 1,
  "limit": 10
}
```

### Get Single Vulnerability

Get detailed information about a specific vulnerability.

**URL**: `/vulnerabilities/{vulnerability_id}`

**Method**: `GET`

**Response**: Detailed vulnerability information including all evidence

### Get Findings

Get a list of findings in a simplified format.

**URL**: `/findings`

**Method**: `GET`

**Response**: List of findings with basic information

## Error Handling

All endpoints return appropriate HTTP status codes and error messages:

- `200`: Success
- `400`: Bad Request (validation errors, malformed input)
- `404`: Not Found (finding not found, file not found)
- `500`: Internal Server Error

Error responses include details:

```json
{
  "error": "Validation failed",
  "details": "evidenceType 'INVALID_TYPE' is not supported"
}
```

## Evidence Type Reference

The following evidence types are supported for the VXDF format:

### Network/HTTP Evidence
- `HTTP_REQUEST_LOG` - HTTP request logs
- `HTTP_RESPONSE_LOG` - HTTP response logs
- `NETWORK_TRAFFIC_CAPTURE_SUMMARY` - Network packet capture summaries

### Code Evidence  
- `CODE_SNIPPET_SOURCE` - Source code snippets
- `CODE_SNIPPET_SINK` - Sink code snippets  
- `CODE_SNIPPET_CONTEXT` - Contextual code snippets
- `POC_SCRIPT` - Proof of concept scripts

### Runtime Evidence
- `RUNTIME_APPLICATION_LOG_ENTRY` - Application log entries
- `RUNTIME_SYSTEM_LOG_ENTRY` - System log entries
- `RUNTIME_WEB_SERVER_LOG_ENTRY` - Web server log entries
- `RUNTIME_DATABASE_LOG_ENTRY` - Database log entries
- `RUNTIME_DEBUGGER_OUTPUT` - Debugger output
- `RUNTIME_EXCEPTION_TRACE` - Exception stack traces

### Visual Evidence
- `SCREENSHOT_URL` - Screenshot URLs
- `SCREENSHOT_EMBEDDED_BASE64` - Base64 encoded screenshots

### Testing Evidence
- `TEST_PAYLOAD_USED` - Test payloads used in exploitation
- `MANUAL_VERIFICATION_NOTES` - Manual verification notes

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