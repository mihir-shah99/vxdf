# VXDF Validate API Documentation

This document describes the API endpoints provided by the VXDF Validate backend.

## Base URL

All API endpoints are relative to the base URL:

```
http://localhost:5001/api
```

For production deployments, replace with your actual domain and port. You can customize the port when running the application:

```bash
./scripts/startup.sh <api_port> <frontend_port>
```

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

Upload and process security scan files (SARIF, JSON, etc.).

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
      "validationMessage": "Confirmed SQL Injection vulnerability.",
      "evidence": [
        {
          "description": "SQL Injection test",
          "method": "http_request",
          "timestamp": "2025-05-04T15:30:00Z",
          "content": "HTTP request content here"
        }
      ],
      "createdAt": "2025-05-04T15:29:30Z"
    }
  ],
  "outputFile": "vxdf_results_20250504-153000.json"
}
```

### List Vulnerabilities

Get a list of vulnerabilities with optional filtering.

**URL**: `/vulnerabilities`

**Method**: `GET`

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| limit | Integer | No | Maximum number of results to return. Default: 10 |
| offset | Integer | No | Number of results to skip. Default: 0 |
| category | String | No | Filter by vulnerability type |
| exploitable | Boolean | No | Filter by exploitable status (true/false) |
| severity | String | No | Filter by severity level |

**Response**:

```json
{
  "vulnerabilities": [
    {
      "id": "a549f9d9-c4cd-4b7d-9a10-5ea2c6893612",
      "title": "SQL Injection in login form",
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
      "validationMessage": "Confirmed SQL Injection vulnerability.",
      "evidence": [],
      "createdAt": "2025-05-04T15:29:30Z"
    }
  ],
  "total": 25,
  "limit": 10,
  "offset": 0
}
```

### Get Vulnerability Details

Get detailed information about a specific vulnerability.

**URL**: `/vulnerabilities/{vulnerability_id}`

**Method**: `GET`

**Response**:

```json
{
  "id": "a549f9d9-c4cd-4b7d-9a10-5ea2c6893612",
  "title": "SQL Injection in login form",
  "description": "SQL injection vulnerability in login form",
  "severity": "HIGH",
  "category": "sql_injection",
  "cwe": "CWE-89",
  "source": {
    "file": "src/login.php",
    "line": 42,
    "snippet": "string query = \"SELECT * FROM users WHERE username='\" + username + \"'\";"
  },
  "sink": {
    "file": "src/db.php",
    "line": 15,
    "snippet": "db.execute(query);"
  },
  "steps": [
    {
      "file": "src/auth.php",
      "line": 28,
      "snippet": "processLogin(username, password);",
      "note": "Data passes through authentication module"
    }
  ],
  "exploitable": true,
  "validated": true,
  "validationDate": "2025-05-04T15:30:00Z",
  "validationMessage": "Confirmed SQL Injection vulnerability.",
  "evidence": [
    {
      "description": "SQL Injection test with payload: ' OR '1'='1",
      "method": "sql_injection_test",
      "timestamp": "2025-05-04T15:29:45Z",
      "content": "{\"query\":\"SELECT * FROM users WHERE username = '' OR '1'='1'\", \"result\":\"success\", \"rows_returned\":2}"
    }
  ],
  "createdAt": "2025-05-04T15:29:30Z"
}
```

## Error Handling

All API endpoints return appropriate HTTP status codes and error messages:

* `200 OK`: Request was successful
* `400 Bad Request`: Invalid parameters
* `404 Not Found`: Resource not found
* `500 Internal Server Error`: Server-side error

Error responses include a JSON object with an `error` field containing the error message.

Example:

```json
{
  "error": "No file part in the request"
}
```

## CORS Support

The API supports Cross-Origin Resource Sharing (CORS) for specified origins:
- http://localhost:5173
- http://localhost:3000

For production, you should modify the CORS configuration in `api/api.py` to allow requests from your frontend domain.