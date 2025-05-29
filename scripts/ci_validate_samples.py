#!/usr/bin/env python3
"""
CI Sample Validation Script

This script validates all sample VXDF files in the repository against the
authoritative schema. It's designed to be run in CI to ensure all examples
remain valid as the schema evolves.

Usage:
    python scripts/ci_validate_samples.py
    python scripts/ci_validate_samples.py --strict
"""
import sys
import json
import argparse
from pathlib import Path
from typing import List, Tuple
import subprocess

def find_sample_files() -> List[Path]:
    """Find all VXDF sample files in the repository."""
    sample_files = []
    
    # Common locations for sample files
    search_paths = [
        "samples/",
        "examples/",
        "test/samples/",
        "docs/examples/",
        "."
    ]
    
    for search_path in search_paths:
        path = Path(search_path)
        if path.exists():
            # Find JSON files that might be VXDF samples
            for json_file in path.glob("**/*.json"):
                # Skip schema files and other non-sample files
                if any(exclude in str(json_file).lower() for exclude in 
                       ["schema", "config", "package", "tsconfig", "node_modules"]):
                    continue
                
                # Check if it looks like a VXDF file by checking for vxdfVersion
                try:
                    with open(json_file, 'r') as f:
                        data = json.load(f)
                        if isinstance(data, dict) and "vxdfVersion" in data:
                            sample_files.append(json_file)
                except:
                    continue  # Skip files that can't be parsed as JSON
    
    return sample_files

def validate_sample_file(file_path: Path) -> Tuple[bool, List[str]]:
    """
    Validate a single sample file using the validation utility.
    
    Returns:
        Tuple of (is_valid, error_messages)
    """
    try:
        result = subprocess.run(
            [sys.executable, "scripts/validate_vxdf.py", str(file_path)],
            capture_output=True,
            text=True,
            cwd=Path.cwd()
        )
        
        if result.returncode == 0:
            return True, []
        else:
            # Extract error messages from the output
            errors = []
            lines = result.stdout.split('\n')
            in_error_section = False
            
            for line in lines:
                if "validation error(s):" in line:
                    in_error_section = True
                elif in_error_section and line.strip().startswith("---"):
                    # New error, continue collecting
                    continue
                elif in_error_section and line.strip():
                    errors.append(line.strip())
                elif line.startswith("===="):
                    in_error_section = False
            
            if not errors:
                errors = [result.stdout.strip()]
            
            return False, errors
    
    except Exception as e:
        return False, [f"Failed to validate: {e}"]

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Validate all VXDF sample files in the repository",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script automatically finds and validates all VXDF sample files
in the repository against the authoritative schema.

Examples:
  python scripts/ci_validate_samples.py         # Validate all samples
  python scripts/ci_validate_samples.py --strict # Exit on first failure
        """
    )
    
    parser.add_argument(
        '--strict',
        action='store_true',
        help='Exit immediately on first validation failure'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed validation results'
    )
    
    args = parser.parse_args()
    
    print("🔍 Finding VXDF sample files...")
    sample_files = find_sample_files()
    
    if not sample_files:
        print("⚠️  No VXDF sample files found in the repository")
        return 0
    
    print(f"📁 Found {len(sample_files)} sample file(s):")
    for file_path in sample_files:
        print(f"  • {file_path}")
    
    print(f"\n🧪 Validating {len(sample_files)} sample file(s)...")
    
    valid_count = 0
    invalid_count = 0
    all_errors = []
    
    for file_path in sample_files:
        print(f"\n📄 Validating {file_path}...")
        is_valid, errors = validate_sample_file(file_path)
        
        if is_valid:
            print(f"  ✅ VALID")
            valid_count += 1
        else:
            print(f"  ❌ INVALID")
            invalid_count += 1
            all_errors.append((file_path, errors))
            
            if args.verbose:
                for error in errors[:3]:  # Show first 3 errors
                    print(f"    • {error}")
                if len(errors) > 3:
                    print(f"    ... and {len(errors) - 3} more error(s)")
            
            if args.strict:
                print(f"\n💥 Strict mode: Stopping on first failure")
                break
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 VALIDATION SUMMARY")
    print(f"{'='*60}")
    print(f"✅ Valid files:   {valid_count}")
    print(f"❌ Invalid files: {invalid_count}")
    print(f"📁 Total files:   {len(sample_files)}")
    
    if invalid_count > 0:
        print(f"\n🚨 INVALID FILES:")
        for file_path, errors in all_errors:
            print(f"\n📄 {file_path}:")
            for error in errors[:2]:  # Show first 2 errors
                print(f"  • {error}")
            if len(errors) > 2:
                print(f"  ... and {len(errors) - 2} more error(s)")
        
        print(f"\n💡 To see detailed errors, run:")
        print(f"   python scripts/validate_vxdf.py <file_path>")
        
        return 1
    else:
        print(f"\n🎉 All sample files are valid!")
        return 0

if __name__ == "__main__":
    sys.exit(main()) 