# VXDF Validate API Documentation

This document describes the API endpoints provided by the VXDF Validate backend.

## Base URL

All API endpoints are relative to the base URL:

```
http://localhost:5001/api
```

For production deployments, replace with your actual domain.

## Authentication

Authentication is not currently implemented. Future versions will support authentication mechanisms.

## Endpoints

### File Upload

Upload and process security scan files.

**URL**: `/upload`

**Method**: `POST`

**Content-Type**: `multipart/form-data`

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| file | File | Yes | The scan file to upload (SARIF, CycloneDX, DAST) |
| parser_type | String | No | Type of parser to use (sarif, cyclonedx, dast). Default: sarif |
| validate | Boolean | No | Whether to validate findings. Default: true |
| target_name | String | No | Name of the target application |
| target_version | String | No | Version of the target application |
| vuln_types | Array | No | Vulnerability types to process. If empty, all types are processed |
| min_severity | String | No | Minimum severity to process (CRITICAL, HIGH, MEDIUM, LOW). Default: LOW |

**Response**:

```json
{
  "success": true,
  "message": "Processed 3 findings",
  "findings": [
    {
      "id": "a549f9d9-c4cd-4b7d-9a10-5ea2c6893612",
      "title": "SQL Injection",
      "description": "SQL injection vulnerability in login form",
      "severity": "HIGH",
      "category": "sql_injection",
      "cwe": "CWE-89",
      "source": {
        "file": "src/login.php",
        "line": 42
      },
      "sink": {
        "file": "src/db.php",
        "line": 15
      },
      "exploitable": true,
      "validated": true,
      "validationDate": "2025-05-04T15:30:00Z",
      "validationMessage": "Confirmed SQL Injection vulnerability."
    },
    // Additional findings...
  ],
  "outputFile": "vxdf_results_20250504-153000.json"
}
```

### Get Statistics

Get validation statistics for the dashboard.

**URL**: `/stats`

**Method**: `GET`

**Response**:

```json
{
  "total": 25,
  "validated": 20,
  "exploitable": 12,
  "nonExploitable": 8,
  "inProgress": 5,
  "bySeverity": {
    "critical": 3,
    "high": 8,
    "medium": 10,
    "low": 4,
    "informational": 0
  },
  "byType": {
    "sql_injection": 7,
    "xss": 10,
    "path_traversal": 5,
    "command_injection": 3
  },
  "recentFindings": [
    // Recent findings list
  ]
}
```

### List Findings

Get a list of findings with optional filtering.

**URL**: `/findings`

**Method**: `GET`

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| limit | Integer | No | Maximum number of results to return. Default: 10 |
| offset | Integer | No | Number of results to skip. Default: 0 |
| vuln_type | String | No | Filter by vulnerability type |
| exploitable | Boolean | No | Filter by exploitable status |

**Response**:

```json
{
  "findings": [
    {
      "id": "a549f9d9-c4cd-4b7d-9a10-5ea2c6893612",
      "name": "SQL Injection in login form",
      "vulnerability_type": "sql_injection",
      "severity": "HIGH",
      "is_validated": true,
      "is_exploitable": true,
      "created_at": "2025-05-04T15:30:00Z"
    },
    // Additional findings...
  ],
  "total": 25,
  "limit": 10,
  "offset": 0
}
```

### Get Finding Details

Get detailed information about a specific finding.

**URL**: `/finding/{finding_id}`

**Method**: `GET`

**Response**:

```json
{
  "id": "a549f9d9-c4cd-4b7d-9a10-5ea2c6893612",
  "source_id": "CWE-89-1",
  "source_type": "SARIF",
  "vulnerability_type": "sql_injection",
  "name": "SQL Injection in login form",
  "description": "SQL injection vulnerability in login form",
  "severity": "HIGH",
  "cvss_score": 8.5,
  "cwe_id": "CWE-89",
  "file_path": "src/login.php",
  "line_number": 42,
  "column": 15,
  "is_validated": true,
  "is_exploitable": true,
  "validation_date": "2025-05-04T15:30:00Z",
  "validation_message": "Confirmed SQL Injection vulnerability.",
  "validation_attempts": 1,
  "created_at": "2025-05-04T15:29:30Z",
  "updated_at": "2025-05-04T15:30:00Z",
  "evidence": [
    {
      "id": "b549f9d9-c4cd-4b7d-9a10-5ea2c6893613",
      "evidence_type": "sql_injection_test",
      "description": "SQL Injection test with payload: ' OR '1'='1",
      "content": "{\"query\":\"SELECT * FROM users WHERE username = '' OR '1'='1'\", \"result\":\"success\", \"rows_returned\":2}",
      "created_at": "2025-05-04T15:29:45Z"
    }
  ]
}
```

### Get Supported Types

Get supported vulnerability types.

**URL**: `/supported-types`