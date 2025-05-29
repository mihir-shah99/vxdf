#!/usr/bin/env python3
"""
Schema Synchronization Script for CI/CD

This script ensures that the authoritative schema in docs/normative-schema.json
is always in sync with the Pydantic models by comparing it with the generated schema.

Usage:
    python scripts/sync_schema.py          # Check if schemas are in sync
    python scripts/sync_schema.py --update # Update docs/normative-schema.json
    python scripts/sync_schema.py --ci     # CI mode with strict checking
"""
import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any

def generate_current_schema() -> Dict[str, Any]:
    """Generate the current schema from Pydantic models."""
    try:
        # Run the schema generation script
        result = subprocess.run(
            [sys.executable, "generate_schema_script.py"],
            capture_output=True,
            text=True,
            cwd=Path.cwd()
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Schema generation failed: {result.stderr}")
        
        # Load the generated schema
        with open("generated_vxdf_schema.json", 'r') as f:
            return json.load(f)
    
    except Exception as e:
        raise RuntimeError(f"Failed to generate schema: {e}")

def load_normative_schema() -> Dict[str, Any]:
    """Load the current normative schema."""
    try:
        with open("docs/normative-schema.json", 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError("Normative schema not found at docs/normative-schema.json")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in normative schema: {e}")

def schemas_are_equal(schema1: Dict[str, Any], schema2: Dict[str, Any]) -> bool:
    """Check if two schemas are identical."""
    # Convert to JSON strings and compare for exact equality
    json1 = json.dumps(schema1, sort_keys=True, indent=2)
    json2 = json.dumps(schema2, sort_keys=True, indent=2)
    return json1 == json2

def update_normative_schema(generated_schema: Dict[str, Any]) -> None:
    """Update the normative schema with the generated schema."""
    try:
        with open("docs/normative-schema.json", 'w') as f:
            json.dump(generated_schema, f, indent=2)
        print("✅ Updated docs/normative-schema.json with generated schema")
    except Exception as e:
        raise RuntimeError(f"Failed to update normative schema: {e}")

def get_schema_diff(schema1: Dict[str, Any], schema2: Dict[str, Any]) -> str:
    """Get a summary of differences between schemas."""
    # Simple diff based on top-level properties
    diff_summary = []
    
    # Check root properties
    props1 = set(schema1.get("properties", {}).keys())
    props2 = set(schema2.get("properties", {}).keys())
    
    added = props2 - props1
    removed = props1 - props2
    
    if added:
        diff_summary.append(f"Added root properties: {', '.join(added)}")
    if removed:
        diff_summary.append(f"Removed root properties: {', '.join(removed)}")
    
    # Check required fields
    req1 = set(schema1.get("required", []))
    req2 = set(schema2.get("required", []))
    
    req_added = req2 - req1
    req_removed = req1 - req2
    
    if req_added:
        diff_summary.append(f"Added required fields: {', '.join(req_added)}")
    if req_removed:
        diff_summary.append(f"Removed required fields: {', '.join(req_removed)}")
    
    # Check definitions
    defs1 = set(schema1.get("$defs", {}).keys())
    defs2 = set(schema2.get("$defs", {}).keys())
    
    defs_added = defs2 - defs1
    defs_removed = defs1 - defs2
    
    if defs_added:
        diff_summary.append(f"Added model definitions: {', '.join(defs_added)}")
    if defs_removed:
        diff_summary.append(f"Removed model definitions: {', '.join(defs_removed)}")
    
    if not diff_summary:
        diff_summary.append("Schemas differ in details (same structure but different content)")
    
    return "\n".join(diff_summary)

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Check and sync VXDF schema with Pydantic models",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/sync_schema.py           # Check sync status
  python scripts/sync_schema.py --update  # Update normative schema
  python scripts/sync_schema.py --ci      # CI mode (fail if out of sync)
        """
    )
    
    parser.add_argument(
        '--update',
        action='store_true',
        help='Update docs/normative-schema.json with generated schema'
    )
    
    parser.add_argument(
        '--ci',
        action='store_true',
        help='CI mode: exit with error code if schemas are out of sync'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed information'
    )
    
    args = parser.parse_args()
    
    try:
        print("🔍 Checking schema synchronization...")
        
        # Generate current schema from Pydantic models
        if args.verbose:
            print("📋 Generating schema from Pydantic models...")
        generated_schema = generate_current_schema()
        
        # Load normative schema
        if args.verbose:
            print("📄 Loading normative schema...")
        try:
            normative_schema = load_normative_schema()
        except FileNotFoundError:
            print("⚠️  Normative schema not found, creating it...")
            update_normative_schema(generated_schema)
            print("✅ Created docs/normative-schema.json")
            return 0
        
        # Compare schemas
        if schemas_are_equal(generated_schema, normative_schema):
            print("✅ Schemas are in sync!")
            if args.verbose:
                props_count = len(generated_schema.get("properties", {}))
                defs_count = len(generated_schema.get("$defs", {}))
                print(f"   📊 Schema has {props_count} root properties and {defs_count} model definitions")
            return 0
        else:
            print("❌ Schemas are out of sync!")
            
            if args.verbose:
                print("\n📝 Differences:")
                diff = get_schema_diff(normative_schema, generated_schema)
                print(diff)
            
            if args.update:
                print("\n🔄 Updating normative schema...")
                update_normative_schema(generated_schema)
                print("✅ Normative schema updated successfully!")
                return 0
            elif args.ci:
                print("\n💥 CI mode: Failing due to schema mismatch")
                print("Run 'python scripts/sync_schema.py --update' to fix this")
                return 1
            else:
                print("\n💡 Run with --update to sync the schemas")
                return 1
    
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 