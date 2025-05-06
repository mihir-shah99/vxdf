#!/usr/bin/env python3
"""
Database initialization script for VXDF Validate.
"""
import os
import sys
import json
import datetime
from pathlib import Path

# Add project root to Python path
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
sys.path.insert(0, str(project_root))

# Import database modules
from api.models.database import init_db, SessionLocal
from api.models.finding import Finding, Evidence

def create_sample_findings():
    """Create sample findings from the SARIF file."""
    db = SessionLocal()
    try:
        # Read sample SARIF file
        sarif_path = project_root / "test-data" / "sample-sarif.json"
        with open(sarif_path, 'r', encoding='utf-8') as f:
            sarif_data = json.load(f)
        
        # Get current UTC time
        now = datetime.datetime.now(datetime.UTC)
        
        # Process each result
        for result in sarif_data['runs'][0]['results']:
            # Map SARIF data to Finding model
            finding = Finding(
                source_id=result['ruleId'],
                source_type='sarif',
                vulnerability_type=result['properties']['category'],
                name=result['message']['text'],
                description=next(
                    (rule['fullDescription']['text'] 
                     for rule in sarif_data['runs'][0]['tool']['driver']['rules'] 
                     if rule['id'] == result['ruleId']),
                    None
                ),
                severity=result['properties']['severity'].upper(),
                file_path=result['locations'][0]['physicalLocation']['artifactLocation']['uri'],
                line_number=result['locations'][0]['physicalLocation']['region']['startLine'],
                column=result['locations'][0]['physicalLocation']['region']['startColumn'],
                raw_data=result,
                created_at=now,
                updated_at=now
            )
            
            # Add evidence from code flows
            if 'codeFlows' in result:
                for flow in result['codeFlows']:
                    for thread_flow in flow['threadFlows']:
                        for location in thread_flow['locations']:
                            evidence = Evidence(
                                evidence_type='code_flow',
                                description=location['location']['message']['text'],
                                content=json.dumps(location['location']['physicalLocation']),
                                created_at=now
                            )
                            finding.evidence.append(evidence)
            
            db.add(finding)
        
        db.commit()
        print("Sample findings created successfully.")
    
    except Exception as e:
        print(f"Error creating sample findings: {e}")
        db.rollback()
    finally:
        db.close()

def main():
    """Initialize the database."""
    print(f"Initializing database...")
    
    # Create database directory if it doesn't exist
    db_dir = project_root / "vxdf_validate.db"
    db_dir.parent.mkdir(parents=True, exist_ok=True)
    
    # Remove existing database if it exists
    if db_dir.exists():
        print("Removing existing database...")
        db_dir.unlink()
    
    # Create new database file
    db_dir.touch()
    
    # Initialize database schema
    init_db()
    
    # Create sample findings
    create_sample_findings()

if __name__ == "__main__":
    main() 