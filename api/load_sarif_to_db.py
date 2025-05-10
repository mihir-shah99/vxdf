import sys
import os
from pathlib import Path

# Ensure api/ is in sys.path for imports
sys.path.insert(0, str(Path(__file__).parent))

from api.models import init_db, SessionLocal
from api.parsers.sarif_parser import SarifParser
from api.models.finding import Finding
from api.core.engine import ValidationEngine

SARIF_PATH = str(Path(__file__).parent.parent / "test-data/sample-sarif.json")

def load_sarif_to_db(sarif_path=SARIF_PATH):
    print(f"Loading SARIF findings from: {sarif_path}")
    parser = SarifParser()
    findings = parser.parse_file(sarif_path)
    print(f"Parsed {len(findings)} findings from SARIF.")
    
    db = SessionLocal()
    inserted = 0
    try:
        for finding in findings:
            # Check for duplicate by source_id and source_type
            exists = db.query(Finding).filter_by(source_id=finding.source_id, source_type=finding.source_type).first()
            if not exists:
                db.add(finding)
                inserted += 1
        db.commit()
        print(f"Inserted {inserted} new findings into the database.")
    except Exception as e:
        db.rollback()
        print(f"Error inserting findings: {e}")
    finally:
        db.close()

def validate_all_findings():
    print("Validating all unvalidated findings...")
    db = SessionLocal()
    engine = ValidationEngine()
    try:
        unvalidated = db.query(Finding).filter_by(is_validated=False).all()
        print(f"Found {len(unvalidated)} unvalidated findings.")
        for finding in unvalidated:
            # Re-query in engine's session to avoid session conflict
            finding_in_engine = engine.db.query(Finding).get(finding.id)
            if finding_in_engine:
                engine.validate_finding(finding_in_engine)
        print("Validation complete.")
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
    load_sarif_to_db()
    validate_all_findings() 