import sys
import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add the project root to the Python path to make imports work
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent
sys.path.insert(0, str(project_root))

try:
    # Import models first to ensure proper registration
    from api.models.finding import Finding, Evidence
    from api.models.database import init_db, SessionLocal
    from api.parsers.sarif_parser import SarifParser
    from api.core.engine import ValidationEngine
except ImportError as e:
    logger.error(f"Error importing required modules: {e}")
    logger.error("Please ensure you're running this script from the project root directory")
    sys.exit(1)

SARIF_PATH = str(Path(__file__).parent.parent / "test-data/sample-sarif.json")

def load_sarif_to_db(sarif_path=SARIF_PATH):
    """
    Load SARIF findings into the database.
    
    Args:
        sarif_path: Path to the SARIF file
    """
    logger.info(f"Loading SARIF findings from: {sarif_path}")
    
    if not Path(sarif_path).exists():
        logger.error(f"SARIF file not found: {sarif_path}")
        return False
    
    try:
        parser = SarifParser()
        findings = parser.parse_file(sarif_path)
        logger.info(f"Parsed {len(findings)} findings from SARIF.")
        
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
            logger.info(f"Inserted {inserted} new findings into the database.")
            return True
        except Exception as e:
            db.rollback()
            logger.error(f"Error inserting findings: {e}")
            return False
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error parsing SARIF file: {e}")
        return False

def validate_all_findings():
    """
    Validate all unvalidated findings in the database.
    """
    logger.info("Validating all unvalidated findings...")
    db = SessionLocal()
    engine = ValidationEngine()
    validated = 0
    
    try:
        unvalidated = db.query(Finding).filter_by(is_validated=False).all()
        logger.info(f"Found {len(unvalidated)} unvalidated findings.")
        
        for finding in unvalidated:
            try:
                # Re-query in engine's session to avoid session conflict
                finding_in_engine = engine.db.query(Finding).get(finding.id)
                if finding_in_engine:
                    engine.validate_finding(finding_in_engine)
                    validated += 1
            except Exception as e:
                logger.error(f"Error validating finding {finding.id}: {e}")
        
        logger.info(f"Successfully validated {validated} findings.")
        return True
    except Exception as e:
        logger.error(f"Error during validation: {e}")
        return False
    finally:
        db.close()

if __name__ == "__main__":
    try:
        # Initialize the database first
        init_db()
        
        # Load SARIF data
        if not load_sarif_to_db():
            logger.error("Failed to load SARIF data")
            sys.exit(1)
        
        # Validate findings
        if not validate_all_findings():
            logger.error("Failed to validate findings")
            sys.exit(1)
            
        logger.info("SARIF data loaded and validated successfully")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1) 