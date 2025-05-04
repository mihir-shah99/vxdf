"""
Base validator class and factory for different vulnerability types.
"""
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from vxdf_validate.models.finding import Finding

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
        # Check if we already have an instance for this type
        if vulnerability_type in self._validators:
            return self._validators[vulnerability_type]
        
        # Create a new validator
        validator = None
        
        if vulnerability_type == 'sql_injection':
            from vxdf_validate.validators.sql_injection import SQLInjectionValidator
            validator = SQLInjectionValidator()
        
        elif vulnerability_type == 'xss':
            from vxdf_validate.validators.xss import XSSValidator
            validator = XSSValidator()
        
        elif vulnerability_type == 'path_traversal':
            from vxdf_validate.validators.path_traversal import PathTraversalValidator
            validator = PathTraversalValidator()
        
        elif vulnerability_type == 'command_injection':
            from vxdf_validate.validators.command_injection import CommandInjectionValidator
            validator = CommandInjectionValidator()
        
        # Cache and return the validator
        if validator:
            self._validators[vulnerability_type] = validator
        
        return validator
    
    def cleanup(self) -> None:
        """
        Clean up all validators.
        """
        for validator in self._validators.values():
            validator.cleanup()
        
        self._validators = {}
