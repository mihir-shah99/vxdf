#!/usr/bin/env python3
"""
VXDF Document Validation Utility

This CLI tool validates VXDF JSON documents against the authoritative schema.
It loads the normative schema from docs/normative-schema.json and provides
detailed validation results with clear error reporting.

Usage:
    python scripts/validate_vxdf.py <path_to_vxdf_file>
    python scripts/validate_vxdf.py --help
"""
import sys
import json
import argparse
import os
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    import jsonschema
    from jsonschema import validate, ValidationError, SchemaError
except ImportError:
    print("Error: jsonschema library not found. Install with: pip install jsonschema")
    sys.exit(1)

class VXDFValidator:
    """VXDF document validator using the authoritative schema."""
    
    def __init__(self, schema_path: Optional[str] = None):
        """
        Initialize the validator.
        
        Args:
            schema_path: Path to the schema file. If None, uses the default normative schema.
        """
        if schema_path is None:
            # Default to normative schema in docs/
            script_dir = Path(__file__).parent
            project_root = script_dir.parent
            schema_path = project_root / "docs" / "normative-schema.json"
        else:
            schema_path = Path(schema_path)
        
        self.schema_path = schema_path
        self.schema = self._load_schema()
    
    def _load_schema(self) -> Dict[str, Any]:
        """Load the VXDF schema from file."""
        try:
            if not self.schema_path.exists():
                raise FileNotFoundError(f"Schema file not found: {self.schema_path}")
            
            with open(self.schema_path, 'r', encoding='utf-8') as f:
                schema = json.load(f)
            
            # Validate that the schema itself is valid
            jsonschema.Draft7Validator.check_schema(schema)
            
            return schema
        
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in schema file: {e}")
        except SchemaError as e:
            raise ValueError(f"Invalid JSON schema: {e}")
        except Exception as e:
            raise RuntimeError(f"Error loading schema: {e}")
    
    def validate_file(self, vxdf_file_path: str) -> 'ValidationResult':
        """
        Validate a VXDF file against the schema.
        
        Args:
            vxdf_file_path: Path to the VXDF JSON file to validate
            
        Returns:
            ValidationResult object with validation details
        """
        vxdf_path = Path(vxdf_file_path)
        
        try:
            # Load the VXDF document
            if not vxdf_path.exists():
                return ValidationResult(
                    is_valid=False,
                    file_path=vxdf_file_path,
                    errors=[f"File not found: {vxdf_file_path}"]
                )
            
            with open(vxdf_path, 'r', encoding='utf-8') as f:
                vxdf_document = json.load(f)
        
        except json.JSONDecodeError as e:
            return ValidationResult(
                is_valid=False,
                file_path=vxdf_file_path,
                errors=[f"Invalid JSON: {e}"]
            )
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                file_path=vxdf_file_path,
                errors=[f"Error reading file: {e}"]
            )
        
        # Perform validation
        return self._validate_document(vxdf_document, vxdf_file_path)
    
    def _validate_document(self, document: Dict[str, Any], file_path: str) -> 'ValidationResult':
        """Validate a VXDF document against the schema."""
        try:
            # Create validator with detailed error reporting
            validator = jsonschema.Draft7Validator(self.schema)
            
            # Collect all validation errors
            errors = []
            for error in validator.iter_errors(document):
                error_msg = self._format_validation_error(error)
                errors.append(error_msg)
            
            if errors:
                return ValidationResult(
                    is_valid=False,
                    file_path=file_path,
                    errors=errors,
                    document=document
                )
            else:
                return ValidationResult(
                    is_valid=True,
                    file_path=file_path,
                    document=document
                )
        
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                file_path=file_path,
                errors=[f"Validation error: {e}"]
            )
    
    def _format_validation_error(self, error: ValidationError) -> str:
        """Format a validation error into a human-readable message."""
        path = " -> ".join(str(p) for p in error.absolute_path)
        if not path:
            path = "(root)"
        
        # Get the specific value that failed validation
        failed_value = error.instance
        if isinstance(failed_value, (dict, list)) and len(str(failed_value)) > 100:
            failed_value = f"{type(failed_value).__name__} with {len(failed_value)} items"
        
        return (
            f"Path: {path}\n"
            f"  Error: {error.message}\n"
            f"  Schema Rule: {error.schema.get('description', 'No description')}\n"
            f"  Failed Value: {failed_value}"
        )

class ValidationResult:
    """Container for validation results."""
    
    def __init__(self, is_valid: bool, file_path: str, errors: Optional[List[str]] = None, 
                 document: Optional[Dict[str, Any]] = None):
        self.is_valid = is_valid
        self.file_path = file_path
        self.errors = errors or []
        self.document = document
    
    def print_result(self, verbose: bool = False):
        """Print the validation result in a user-friendly format."""
        print(f"\n{'='*60}")
        print(f"VXDF Validation Result for: {self.file_path}")
        print(f"{'='*60}")
        
        if self.is_valid:
            print("✅ VALID: Document passes all schema validation checks!")
            
            if verbose and self.document:
                print(f"\n📊 Document Summary:")
                print(f"  • VXDF Version: {self.document.get('vxdfVersion', 'Unknown')}")
                print(f"  • Document ID: {self.document.get('id', 'Unknown')}")
                print(f"  • Generated At: {self.document.get('generatedAt', 'Unknown')}")
                
                exploit_flows = self.document.get('exploitFlows', [])
                print(f"  • Exploit Flows: {len(exploit_flows)}")
                
                if exploit_flows:
                    for i, flow in enumerate(exploit_flows):
                        print(f"    Flow {i+1}: {flow.get('title', 'Untitled')}")
                        print(f"      Severity: {flow.get('severity', {}).get('level', 'Unknown')}")
                        print(f"      Evidence Items: {len(flow.get('evidence', []))}")
        else:
            print("❌ INVALID: Document has validation errors!")
            print(f"\n🚨 Found {len(self.errors)} validation error(s):")
            
            for i, error in enumerate(self.errors, 1):
                print(f"\n--- Error {i} ---")
                print(error)
        
        print(f"\n{'='*60}")

def create_sample_vxdf_files():
    """Create sample VXDF files for testing."""
    samples_dir = Path("samples")
    samples_dir.mkdir(exist_ok=True)
    
    # Valid sample
    valid_sample = {
        "vxdfVersion": "1.0.0",
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "generatedAt": "2024-01-15T10:30:00Z",
        "generatorTool": {
            "name": "Test Generator",
            "version": "1.0.0"
        },
        "applicationInfo": {
            "name": "Test Application",
            "version": "1.0.0"
        },
        "exploitFlows": [
            {
                "id": "550e8400-e29b-41d4-a716-446655440001",
                "title": "Sample SQL Injection",
                "severity": {
                    "level": "HIGH"
                },
                "category": "SQL Injection",
                "validatedAt": "2024-01-15T10:30:00Z",
                "evidence": [
                    {
                        "evidenceType": "HTTP_REQUEST_LOG",
                        "description": "HTTP request demonstrating SQL injection",
                        "data": {
                            "method": "POST",
                            "url": "/login",
                            "headers": [
                                {"name": "Content-Type", "value": "application/x-www-form-urlencoded"}
                            ],
                            "body": "username=admin&password=' OR '1'='1",
                            "bodyEncoding": "plaintext"
                        }
                    }
                ]
            }
        ]
    }
    
    # Invalid sample (missing required fields)
    invalid_sample = {
        "vxdfVersion": "1.0.0",
        "exploitFlows": [
            {
                "title": "Incomplete Flow",  # Missing required 'id', 'severity', etc.
                "evidence": []
            }
        ]
    }
    
    with open(samples_dir / "valid_sample.json", 'w') as f:
        json.dump(valid_sample, f, indent=2)
    
    with open(samples_dir / "invalid_sample.json", 'w') as f:
        json.dump(invalid_sample, f, indent=2)
    
    print(f"✅ Created sample files in {samples_dir}/")

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Validate VXDF JSON documents against the authoritative schema",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/validate_vxdf.py sample.json
  python scripts/validate_vxdf.py --verbose sample.json
  python scripts/validate_vxdf.py --schema custom-schema.json sample.json
  python scripts/validate_vxdf.py --create-samples
        """
    )
    
    parser.add_argument(
        'vxdf_file', 
        nargs='?',
        help='Path to the VXDF JSON file to validate'
    )
    
    parser.add_argument(
        '--schema', 
        help='Path to custom schema file (default: docs/normative-schema.json)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed information about valid documents'
    )
    
    parser.add_argument(
        '--create-samples',
        action='store_true',
        help='Create sample VXDF files for testing'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='VXDF Validator 1.0.0'
    )
    
    args = parser.parse_args()
    
    if args.create_samples:
        create_sample_vxdf_files()
        return 0
    
    if not args.vxdf_file:
        parser.print_help()
        print("\nError: Please provide a VXDF file to validate or use --create-samples")
        return 1
    
    try:
        # Initialize validator
        validator = VXDFValidator(schema_path=args.schema)
        
        print(f"📋 Using schema: {validator.schema_path}")
        print(f"📄 Validating: {args.vxdf_file}")
        
        # Validate the file
        result = validator.validate_file(args.vxdf_file)
        
        # Print results
        result.print_result(verbose=args.verbose)
        
        # Return appropriate exit code
        return 0 if result.is_valid else 1
    
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 