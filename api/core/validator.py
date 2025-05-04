"""
Base validator class and factory for different vulnerability types.
"""
import logging
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from api.models.finding import Finding

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """
    Result of a vulnerability validation attempt.
    """
    is_exploitable: bool
    message: str
    evidence: List[Dict[str, Any]] = None
    vxdf_data: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """
        Initialize default values.
        """
        if self.evidence is None:
            self.evidence = []
        if self.vxdf_data is None:
            self.vxdf_data = {}

class Validator:
    """
    Base class for vulnerability validators.
    """
    
    def __init__(self):
        """
        Initialize the validator.
        """
        self.name = "Base Validator"
    
    def validate(self, finding: Finding) -> ValidationResult:
        """
        Validate if a vulnerability is exploitable.
        
        Args:
            finding: The finding to validate
            
        Returns:
            ValidationResult with details of validation
        """
        # Base implementation - should be overridden by subclasses
        return ValidationResult(
            is_exploitable=False,
            message="Not implemented - base validator used"
        )
    
    def cleanup(self) -> None:
        """
        Clean up any resources used during validation.
        """
        pass

class DefaultValidator(Validator):
    """
    Default validator used when a specific validator is not available.
    """
    
    def validate(self, finding: Finding) -> ValidationResult:
        """
        Simple validation that marks the finding as 'unknown' exploitability.
        
        Args:
            finding: Finding to validate
            
        Returns:
            ValidationResult: Result indicating unknown exploitability
        """
        logger.warning(f"Using default validator for {finding.vulnerability_type}. Validation will be skipped.")
        
        return ValidationResult(
            is_exploitable=None,  # None indicates unknown
            message="Validation was skipped. The specific validator for this vulnerability type is not available.",
            evidence=[{
                "type": "validation_log",
                "description": "Validation skipped due to missing validator",
                "content": json.dumps({
                    "vulnerability_type": finding.vulnerability_type,
                    "status": "skipped",
                    "reason": "Validator not available"
                }, indent=2)
            }]
        )

class ValidatorFactory:
    """
    Factory for creating validators for different vulnerability types.
    """
    
    def __init__(self):
        """
        Initialize the validator factory.
        """
        self._validators = {}
    
    def get_validator(self, vulnerability_type: str) -> Optional[Validator]:
        """
        Get a validator for a specific vulnerability type.
        
        Args:
            vulnerability_type: Type of vulnerability to validate
            
        Returns:
            Validator instance or None if not supported
        """
        try:
            if vulnerability_type == 'sql_injection':
                # Attempt to import the validator
                try:
                    from api.validators.sql_injection import SQLInjectionValidator
                    return SQLInjectionValidator()
                except (SyntaxError, ImportError) as e:
                    logger.error(f"Error importing SQL Injection validator: {e}")
                    return DefaultValidator()
            
            elif vulnerability_type == 'xss':
                try:
                    from api.validators.xss import XSSValidator
                    return XSSValidator()
                except (SyntaxError, ImportError) as e:
                    logger.error(f"Error importing XSS validator: {e}")
                    return DefaultValidator()
            
            elif vulnerability_type == 'path_traversal':
                try:
                    from api.validators.path_traversal import PathTraversalValidator
                    return PathTraversalValidator()
                except (SyntaxError, ImportError) as e:
                    logger.error(f"Error importing Path Traversal validator: {e}")
                    return DefaultValidator()
            
            elif vulnerability_type == 'command_injection':
                try:
                    from api.validators.command_injection import CommandInjectionValidator
                    return CommandInjectionValidator()
                except (SyntaxError, ImportError) as e:
                    logger.error(f"Error importing Command Injection validator: {e}")
                    return DefaultValidator()
                
            # Fallback to default validator for unknown types
            logger.warning(f"Using default validator for: {vulnerability_type}")
            return DefaultValidator()
        
        except Exception as e:
            logger.error(f"Error getting validator for {vulnerability_type}: {e}")
            return DefaultValidator()
    
    def cleanup(self) -> None:
        """
        Clean up all validators.
        """
        for validator in self._validators.values():
            validator.cleanup()
        
        self._validators = {}
