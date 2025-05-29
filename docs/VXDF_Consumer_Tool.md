# VXDF Consumer Tool Documentation

## Overview

The VXDF Consumer Tool is a comprehensive Python module and command-line interface (CLI) designed to parse, validate, and summarize VXDF (Validated Exploitable Data Flow) documents. This tool ensures VXDF files can be correctly loaded into the project's normative Pydantic models and validated against the authoritative JSON schema.

## Features

- **Dual Validation**: Validates VXDF files against both Pydantic models and JSON schema
- **Comprehensive Error Reporting**: Provides detailed, human-readable error messages
- **Flexible Output Formats**: Supports both formatted text and JSON output
- **Consistency Checks**: Performs additional consistency validation beyond schema compliance
- **CLI Integration**: User-friendly command-line interface with multiple output modes

## Components

### 1. Python Module (`api/utils/vxdf_loader.py`)

The core Python module provides the following main functions:

#### `load_and_validate_vxdf(file_path: str) -> Tuple[Optional[VXDFModel], List[str]]`

Primary function for loading and validating VXDF files.

**Parameters:**
- `file_path`: Path to the .vxdf.json file to process

**Returns:**
- Tuple of (parsed VXDFModel or None, list of error messages)
- If successful: `(VXDFModel instance, [])`
- If failed: `(None, [error1, error2, ...])`

**Validation Steps:**
1. File existence and extension validation
2. JSON parsing and syntax validation
3. JSON schema validation against authoritative schema
4. Pydantic model parsing and validation
5. Consistency checks (evidence requirements, reference validation, etc.)

#### `get_vxdf_summary(vxdf_model: VXDFModel, verbose: bool = False) -> Dict[str, Any]`

Generates a structured summary of a VXDF document.

**Parameters:**
- `vxdf_model`: Parsed VXDF model instance
- `verbose`: Whether to include detailed information

**Returns:**
- Dictionary containing document summary with:
  - Document metadata (ID, version, generation time)
  - Generator tool information
  - Application information
  - Exploit flow counts and details
  - Evidence statistics

### 2. CLI Tool (`scripts/consume_vxdf.py`)

Command-line interface for consuming VXDF files.

## Usage

### Basic Usage

```bash
# Parse and validate a VXDF file
python3 scripts/consume_vxdf.py path/to/file.vxdf.json

# Verbose output with detailed information
python3 scripts/consume_vxdf.py path/to/file.vxdf.json --verbose

# JSON output format
python3 scripts/consume_vxdf.py path/to/file.vxdf.json --json

# Quiet mode (CI/CD friendly)
python3 scripts/consume_vxdf.py path/to/file.vxdf.json --quiet
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `vxdf_file` | **Required.** Path to the VXDF JSON file to process |
| `-v, --verbose` | Show detailed information in the summary output |
| `--quiet` | Suppress all output except errors (useful for CI/scripts) |
| `--json` | Output summary as JSON instead of formatted text |
| `--debug` | Enable debug logging |
| `--version` | Show program version and exit |
| `-h, --help` | Show help message and exit |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (file is valid) |
| 1 | Validation/parsing errors |
| 2 | File not found or invalid arguments |

## Example Outputs

### Successful Validation (Basic)

```
🔍 Processing VXDF file: test-data/example1_flow_based.vxdf.json
✅ VXDF file 'test-data/example1_flow_based.vxdf.json' is valid and successfully parsed.

============================================================
VXDF DOCUMENT SUMMARY
============================================================
📄 Document ID: bc9f193c-7e73-4c69-9d44-1b024632b16b
📋 VXDF Version: 1.0.0
🕒 Generated At: 2025-05-17T18:30:00+00:00
🔧 Generator Tool: AcmeSecurityScanner Suite v2.5.1
🎯 Target Application: Acme WebApp vv2.3.1-patch2

📊 EXPLOIT FLOWS: 2
📋 TOTAL EVIDENCE: 6

🔍 EXPLOIT FLOW DETAILS:

  1. SQL Injection in User Profile Update
     🆔 ID: f47ac10b-58cc-4372-a567-0e02b2c3d479
     📂 Category: INJECTION
     ⚠️  Severity: HIGH
     📋 Evidence: 3 item(s)
     📅 Status: OPEN

  2. Reflected Cross-Site Scripting (XSS) in Search Function
     🆔 ID: a1b2c3d4-e5f6-7890-1234-567890abcdef
     📂 Category: CROSS_SITE_SCRIPTING
     ⚠️  Severity: MEDIUM
     📋 Evidence: 3 item(s)
     📅 Status: OPEN

============================================================
```

### Validation Errors

```
🔍 Processing VXDF file: test-data/invalid_example.vxdf.json
❌ VXDF file 'test-data/invalid_example.vxdf.json' is invalid.

🚨 Found 8 error(s):

1. Schema validation: At exploitFlows -> 0: 'id' is a required property (failed value: {...})

2. Pydantic validation: At id: Input should be a valid UUID, invalid character: expected an optional prefix of `urn:uuid:` followed by [0-9a-fA-F-], found `n` at 1

3. Pydantic validation: At generatedAt: Input should be a valid datetime or date, invalid character in year

4. Pydantic validation: At exploitFlows -> 0 -> id: Required field is missing: Field required

5. Pydantic validation: At exploitFlows -> 0 -> severity -> level: Input should be 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL' or 'NONE'

6. Pydantic validation: At exploitFlows -> 0 -> category: Required field is missing: Field required

7. Pydantic validation: At exploitFlows -> 0 -> validatedAt: Required field is missing: Field required

8. Pydantic validation: At exploitFlows -> 0 -> evidence: List should have at least 1 item after validation, not 0
```

### JSON Output

```json
{
  "document_id": "bc9f193c-7e73-4c69-9d44-1b024632b16b",
  "vxdf_version": "1.0.0",
  "generated_at": "2025-05-17T18:30:00+00:00",
  "generator_tool": {
    "name": "AcmeSecurityScanner Suite",
    "version": "2.5.1"
  },
  "application_info": {
    "name": "Acme WebApp",
    "version": "v2.3.1-patch2"
  },
  "exploit_flows_count": 2,
  "exploit_flows": [
    {
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "title": "SQL Injection in User Profile Update",
      "category": "INJECTION",
      "severity": "HIGH",
      "evidence_count": 3,
      "status": "OPEN",
      "validated_at": "2025-05-17T18:25:00+00:00"
    }
  ],
  "total_evidence_count": 6
}
```

## Validation Process

The tool performs comprehensive validation in the following order:

1. **File Validation**
   - Checks file existence
   - Validates file extension (.json)
   - Parses JSON syntax

2. **Schema Validation**
   - Validates against authoritative JSON schema (`docs/normative-schema.json`)
   - Reports schema compliance issues

3. **Pydantic Model Validation**
   - Parses JSON into normative VXDFModel
   - Validates data types, required fields, and constraints
   - Reports model-specific validation errors

4. **Consistency Checks**
   - Ensures all exploit flows have evidence
   - Validates evidence reference integrity
   - Checks anyOf constraints (source/sink OR affectedComponents)
   - Validates VXDF version compatibility

## Error Types and Meanings

### Schema Validation Errors
- Missing required properties
- Invalid property types
- Constraint violations
- Extra properties (when forbidden)

### Pydantic Validation Errors
- Invalid UUID formats
- Invalid datetime formats
- Enum value violations
- Missing required fields
- Type conversion errors

### Consistency Errors
- Missing evidence in exploit flows
- Invalid evidence references
- Structural constraint violations
- Version compatibility issues

## Integration with CI/CD

The tool is designed for CI/CD integration:

```bash
# CI-friendly usage
python3 scripts/consume_vxdf.py results.vxdf.json --quiet
echo "Exit code: $?"

# Validate multiple files
for file in *.vxdf.json; do
    python3 scripts/consume_vxdf.py "$file" --quiet || exit 1
done
```

## Testing

The tool includes comprehensive test coverage:

- **Unit Tests** (`tests/test_vxdf_loader.py`): Test core module functionality
- **Integration Tests** (`tests/test_consume_vxdf_cli.py`): Test CLI interface

Run tests with:
```bash
python3 -m pytest tests/test_vxdf_loader.py -v
python3 -m pytest tests/test_consume_vxdf_cli.py -v
```

## Requirements

- Python 3.8+
- jsonschema>=4.0.0
- pydantic>=2.11.4
- All project dependencies from requirements.txt

## Error Troubleshooting

### Common Issues

1. **"File not found"**: Verify the file path exists and is accessible
2. **"Invalid JSON format"**: Check JSON syntax with a JSON validator
3. **"Schema validation failed"**: Ensure the file follows VXDF v1.0.0 schema
4. **"Pydantic validation failed"**: Check data types and required fields
5. **"Consistency check failed"**: Review evidence requirements and references

### Getting Help

Run the tool with `--help` for usage information:
```bash
python3 scripts/consume_vxdf.py --help
```

Enable debug logging for detailed troubleshooting:
```bash
python3 scripts/consume_vxdf.py file.vxdf.json --debug
``` 