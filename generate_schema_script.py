#!/usr/bin/env python3
"""
Script to generate JSON schema from VXDF Pydantic models.
This script generates the machine-readable JSON schema file from the normative Pydantic models.
"""
import json
from api.models.vxdf import VXDFModel

def generate_schema():
    """Generate JSON schema from VXDFModel and save to file."""
    # Generate the schema
    schema = VXDFModel.model_json_schema()
    
    # Pretty print and save to file
    with open('generated_vxdf_schema.json', 'w', encoding='utf-8') as f:
        json.dump(schema, f, indent=2, ensure_ascii=False)
    
    print("Generated schema saved to: generated_vxdf_schema.json")
    print(f"Schema contains {len(schema.get('properties', {}))} root properties")
    if 'required' in schema:
        print(f"Required fields: {schema['required']}")

if __name__ == "__main__":
    generate_schema() 