"""
REAL Database Session Manager
This fixes the core session conflict issues that were breaking the entire validation system.
Uses session-per-operation pattern to eliminate SQLAlchemy session conflicts.
"""
import logging
import contextlib
import datetime
from typing import Generator, Optional, TypeVar, Type, List
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import event
from api.models.database import SessionLocal, engine
from api.models.finding import Finding, Evidence

logger = logging.getLogger(__name__)

T = TypeVar('T')

class RealSessionManager:
    """
    REAL Session Manager that eliminates session conflicts.
    
    Key Features:
    1. Session-per-operation pattern
    2. Proper session isolation 
    3. Automatic cleanup and rollback
    4. Context manager support
    5. Object refresh and merging
    """
    
    def __init__(self):
        """Initialize the session manager."""
        self.session_factory = SessionLocal
        
    @contextlib.contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """
        Get a properly managed database session.
        
        This context manager ensures:
        - Each operation gets its own session
        - Sessions are properly closed
        - Rollback on exceptions
        - No session conflicts
        
        Yields:
            Session: Isolated database session
        """
        session = self.session_factory()
        try:
            logger.debug("Created new database session")
            yield session
            session.commit()
            logger.debug("Session committed successfully")
        except Exception as e:
            logger.error(f"Session error, rolling back: {e}")
            session.rollback()
            raise
        finally:
            session.close()
            logger.debug("Session closed")
    
    def refresh_in_session(self, obj: T, session: Session) -> T:
        """
        Refresh an object in a specific session.
        
        This handles objects that might come from different sessions.
        
        Args:
            obj: Object to refresh
            session: Target session
            
        Returns:
            Refreshed object in the target session
        """
        if obj is None:
            return obj
        
        try:
            # If object is already in this session, just refresh it
            if obj in session:
                session.refresh(obj)
                return obj
            
            # If object has an ID, get it from the current session
            if hasattr(obj, 'id') and obj.id is not None:
                refreshed = session.get(type(obj), obj.id)
                if refreshed:
                    return refreshed
            
            # As a last resort, merge the object
            merged = session.merge(obj)
            session.flush()  # Ensure the merge is committed to the session
            return merged
            
        except Exception as e:
            logger.error(f"Error refreshing object {type(obj).__name__}: {e}")
            # Return original object as fallback
            return obj
    
    def get_finding_with_evidence(self, finding_id: str) -> Optional[Finding]:
        """
        Get a finding with all its evidence in a single session.
        
        Args:
            finding_id: ID of the finding to retrieve
            
        Returns:
            Finding with evidence, or None if not found
        """
        with self.get_session() as session:
            finding = session.query(Finding).filter_by(id=finding_id).first()
            if finding:
                # Force load evidence to avoid lazy loading issues
                _ = finding.evidence  # This triggers the relationship loading
                # Expunge from session so it can be used elsewhere
                session.expunge(finding)
                for evidence in finding.evidence:
                    session.expunge(evidence)
            return finding
    
    def save_finding(self, finding: Finding) -> Finding:
        """
        Save a finding in its own session.
        
        Args:
            finding: Finding to save
            
        Returns:
            Saved finding
        """
        with self.get_session() as session:
            # Merge the finding to handle session conflicts
            merged_finding = session.merge(finding)
            session.flush()  # Ensure it's saved
            
            # Copy back the updated fields
            finding.id = merged_finding.id
            finding.is_validated = merged_finding.is_validated
            finding.is_exploitable = merged_finding.is_exploitable
            finding.validation_date = merged_finding.validation_date
            finding.validation_message = merged_finding.validation_message
            finding.validation_attempts = merged_finding.validation_attempts
            
            logger.info(f"Finding {finding.id} saved successfully")
            return finding
    
    def save_evidence(self, evidence_list: List[Evidence]) -> List[Evidence]:
        """
        Save evidence items in their own session.
        
        Args:
            evidence_list: List of evidence to save
            
        Returns:
            List of saved evidence
        """
        if not evidence_list:
            return []
        
        with self.get_session() as session:
            saved_evidence = []
            for evidence in evidence_list:
                merged_evidence = session.merge(evidence)
                session.flush()
                saved_evidence.append(merged_evidence)
            
            logger.info(f"Saved {len(saved_evidence)} evidence items")
            return saved_evidence
    
    def update_finding_validation(self, finding_id: str, is_exploitable: Optional[bool], 
                                message: str, evidence_items: Optional[List[dict]] = None) -> Optional[Finding]:
        """
        Update finding validation results in a single transaction.
        
        Args:
            finding_id: ID of finding to update
            is_exploitable: Validation result
            message: Validation message
            evidence_items: Optional evidence to add
            
        Returns:
            Updated finding or None if not found
        """
        with self.get_session() as session:
            # Get the finding
            finding = session.query(Finding).filter_by(id=finding_id).first()
            if not finding:
                logger.error(f"Finding {finding_id} not found")
                return None
            
            # Update validation fields
            finding.is_validated = True
            finding.is_exploitable = is_exploitable
            finding.validation_date = datetime.datetime.now(datetime.timezone.utc)
            finding.validation_message = message
            finding.validation_attempts = (finding.validation_attempts or 0) + 1
            
            # Add evidence if provided
            if evidence_items:
                for evidence_data in evidence_items:
                    evidence = Evidence(
                        finding_id=finding.id,
                        evidence_type=evidence_data.get("type", "validation_evidence"),
                        description=evidence_data.get("description", "Validation evidence"),
                        content=evidence_data.get("content", "")
                    )
                    session.add(evidence)
            
            session.flush()  # Ensure changes are saved
            
            # Load evidence relationships before expunging
            evidence_list = list(finding.evidence)  # Force load the evidence
            
            # Expunge so it can be used elsewhere (only if they're in the session)
            if finding in session:
                session.expunge(finding)
            for evidence in evidence_list:
                if evidence in session:
                    session.expunge(evidence)
            
            logger.info(f"Updated validation for finding {finding_id}: exploitable={is_exploitable}")
            return finding
    
    def execute_in_session(self, operation):
        """
        Execute an operation within a managed session.
        
        Args:
            operation: Function that takes a session as parameter
            
        Returns:
            Result of the operation
        """
        with self.get_session() as session:
            return operation(session)

class SessionAwareValidationEngine:
    """
    Session-aware validation engine that eliminates session conflicts.
    
    This replaces the original ValidationEngine's session management.
    """
    
    def __init__(self):
        """Initialize with proper session management."""
        self.session_manager = RealSessionManager()
        
    def validate_finding_safe(self, finding_id: str) -> Optional[Finding]:
        """
        Safely validate a finding without session conflicts.
        
        Args:
            finding_id: ID of finding to validate
            
        Returns:
            Validated finding or None if error
        """
        logger.info(f"Starting safe validation for finding {finding_id}")
        
        try:
            # Get finding in its own session
            finding = self.session_manager.get_finding_with_evidence(finding_id)
            if not finding:
                logger.error(f"Finding {finding_id} not found")
                return None
            
            # Import here to avoid circular imports
            from api.core.validator_factory import ValidatorFactory
            
            # Get validator
            validator_factory = ValidatorFactory()
            validator = validator_factory.get_validator(finding.vulnerability_type)
            
            if not validator:
                # Update with no validator available
                return self.session_manager.update_finding_validation(
                    finding_id,
                    None,  # Unknown exploitability
                    f"No validator available for {finding.vulnerability_type}"
                )
            
            # Perform validation
            logger.info(f"Running validator for {finding.vulnerability_type}")
            validation_result = validator.validate(finding)
            
            # Update finding with results
            updated_finding = self.session_manager.update_finding_validation(
                finding_id,
                validation_result.is_exploitable,
                validation_result.message,
                validation_result.evidence if hasattr(validation_result, 'evidence') else None
            )
            
            logger.info(f"Validation completed for {finding_id}: exploitable={validation_result.is_exploitable}")
            return updated_finding
            
        except Exception as e:
            logger.error(f"Error in safe validation for {finding_id}: {e}", exc_info=True)
            
            # Try to save error state
            try:
                return self.session_manager.update_finding_validation(
                    finding_id,
                    None,  # Unknown due to error
                    f"Validation error: {str(e)}"
                )
            except Exception as save_error:
                logger.error(f"Failed to save error state for {finding_id}: {save_error}")
                return None

# Global session manager instance
session_manager = RealSessionManager()

@contextlib.contextmanager
def get_safe_session() -> Generator[Session, None, None]:
    """
    Get a safe database session.
    
    This is a convenience function for getting properly managed sessions.
    
    Yields:
        Session: Managed database session
    """
    with session_manager.get_session() as session:
        yield session

def refresh_object_safely(obj: T, session: Session) -> T:
    """
    Safely refresh an object in a session.
    
    Args:
        obj: Object to refresh
        session: Target session
        
    Returns:
        Refreshed object
    """
    return session_manager.refresh_in_session(obj, session) 