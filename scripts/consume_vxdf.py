#!/usr/bin/env python3
"""
VXDF Consumer CLI Tool

A command-line interface for parsing, validating, and summarizing VXDF files.
This tool loads VXDF documents into the normative Pydantic models and validates
them against the authoritative JSON schema.

Usage:
    python scripts/consume_vxdf.py <path_to_vxdf_file> [--verbose]
    python scripts/consume_vxdf.py --help

Examples:
    python scripts/consume_vxdf.py test-data/example1_flow_based.vxdf.json
    python scripts/consume_vxdf.py test-data/example2_component_based.vxdf.json --verbose
    python scripts/consume_vxdf.py my_scan_results.vxdf.json -v
"""

import sys
import argparse
import logging
from pathlib import Path
from typing import Optional

# Add the project root to the path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from api.utils.vxdf_loader import (
        load_and_validate_vxdf, 
        get_vxdf_summary, 
        print_vxdf_summary,
        VXDFLoaderError
    )
except ImportError as e:
    print(f"❌ Error importing VXDF loader: {e}")
    print("Make sure you're running this script from the project root directory.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(levelname)s: %(message)s'
)

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="Parse, validate, and summarize VXDF documents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s test-data/example1_flow_based.vxdf.json
  %(prog)s test-data/example2_component_based.vxdf.json --verbose
  %(prog)s my_scan_results.vxdf.json -v

This tool will:
  1. Parse the VXDF file into Pydantic models
  2. Validate against the authoritative JSON schema
  3. Perform consistency checks
  4. Display a summary of the document contents

Exit codes:
  0 - Success (file is valid)
  1 - Validation/parsing errors
  2 - File not found or invalid arguments
        """
    )
    
    parser.add_argument(
        'vxdf_file',
        help='Path to the VXDF JSON file to process'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information in the summary output'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress all output except errors (useful for CI/scripts)'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output summary as JSON instead of formatted text'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='VXDF Consumer 1.0.0'
    )
    
    return parser.parse_args()

def validate_arguments(args: argparse.Namespace) -> bool:
    """
    Validate command-line arguments.
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if arguments are valid, False otherwise
    """
    # Check if file exists
    file_path = Path(args.vxdf_file)
    if not file_path.exists():
        print(f"❌ Error: File not found: {args.vxdf_file}")
        return False
    
    # Check file extension (warning only)
    if not file_path.name.endswith(('.vxdf.json', '.json')):
        print(f"⚠️  Warning: File does not have .vxdf.json extension: {args.vxdf_file}")
    
    return True

def print_success_message(file_path: str, quiet: bool = False) -> None:
    """
    Print success message.
    
    Args:
        file_path: Path to the validated file
        quiet: Whether to suppress output
    """
    if not quiet:
        print(f"✅ VXDF file '{file_path}' is valid and successfully parsed.")

def print_failure_message(file_path: str, errors: list, quiet: bool = False) -> None:
    """
    Print failure message with errors.
    
    Args:
        file_path: Path to the file that failed validation
        errors: List of error messages
        quiet: Whether to suppress output
    """
    if not quiet:
        print(f"❌ VXDF file '{file_path}' is invalid.")
        print(f"\n🚨 Found {len(errors)} error(s):")
        
        for i, error in enumerate(errors, 1):
            print(f"\n{i}. {error}")

def output_json_summary(summary: dict) -> None:
    """
    Output summary as JSON.
    
    Args:
        summary: Summary dictionary
    """
    import json
    print(json.dumps(summary, indent=2, default=str))

def main() -> int:
    """
    Main entry point for the CLI tool.
    
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Configure logging based on debug flag
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logging.getLogger('api.utils.vxdf_loader').setLevel(logging.DEBUG)
        
        # Validate arguments
        if not validate_arguments(args):
            return 2
        
        file_path = args.vxdf_file
        
        if not args.quiet:
            print(f"🔍 Processing VXDF file: {file_path}")
        
        # Load and validate the VXDF file
        try:
            vxdf_model, errors = load_and_validate_vxdf(file_path)
        except VXDFLoaderError as e:
            print(f"❌ VXDF Loader Error: {e}")
            return 1
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
            return 1
        
        # Check if validation was successful
        if errors:
            print_failure_message(file_path, errors, args.quiet)
            return 1
        
        # Success! Print confirmation and summary
        print_success_message(file_path, args.quiet)
        
        if vxdf_model and not args.quiet:
            # Generate and display summary
            summary = get_vxdf_summary(vxdf_model, args.verbose)
            
            if args.json:
                output_json_summary(summary)
            else:
                print_vxdf_summary(summary, args.verbose)
        
        return 0
        
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user.")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main()) 