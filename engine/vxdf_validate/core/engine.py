"""
Core validation engine that processes findings and coordinates validation.
"""
import logging
import datetime
import uuid
import time
from typing import List, Dict, Any, Optional, Union, Set

from sqlalchemy.orm import Session

from vxdf_validate.models.database import get_db, SessionLocal
from vxdf_validate.models.finding import Finding, Evidence
from vxdf_validate.models.vxdf import (
    VXDFDocument, VXDFMetadata, VXDFFlow, VXDFSummary, 
    CodeLocation, DataFlowStep, EvidenceItem, SeverityLevel
)
from vxdf_validate.core.validator import ValidatorFactory
from vxdf_validate import __version__
from vxdf_validate.config import SEVERITY_THRESHOLDS

logger = logging.getLogger(__name__)

class ValidationEngine:
    """
    Core engine for validating findings and generating VXDF documents.
    """
    
    def __init__(self):
        """
        Initialize the validation engine.
        """
        self.validator_factory = ValidatorFactory()
        self.db = SessionLocal()
    
    def __del__(self):
        """
        Clean up when the engine is destroyed.
        """
        if hasattr(self, 'db'):
            self.db.close()
    
    def filter_findings(self, findings: List[Finding], 
                      vuln_types: Optional[List[str]] = None,
                      min_severity: str = 'LOW',
                      max_count: Optional[int] = None) -> List[Finding]:
        """
        Filter findings based on criteria.
        
        Args:
            findings: List of findings to filter
            vuln_types: List of vulnerability types to include (None for all)
            min_severity: Minimum severity level to include
            max_count: Maximum number of findings to include
            
        Returns:
            Filtered list of findings
        """
        result = []
        severity_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
        min_severity_index = severity_levels.index(min_severity)
        
        for finding in findings:
            # Filter by vulnerability type
            if vuln_types and finding.vulnerability_type not in vuln_types:
                continue
            
            # Filter by severity
            if finding.severity:
                try:
                    severity_index = severity_levels.index(finding.severity)
                    if severity_index > min_severity_index:
                        continue
                except ValueError:
                    # Unknown severity, include it by default
                    pass
            
            result.append(finding)
            
            # Check max count
            if max_count and len(result) >= max_count:
                break
        
        return result
    
    def validate_finding(self, finding: Finding) -> Finding:
        """
        Validate a finding to determine if it's exploitable.
        
        Args:
            finding: Finding to validate
            
        Returns:
            Updated finding with validation results
        """
        logger.info(f"Validating finding: {finding.id} - {finding.name}")
        
        try:
            # Get validator for this vulnerability type
            validator = self.validator_factory.get_validator(finding.vulnerability_type)
            
            if not validator:
                logger.warning(f"No validator available for {finding.vulnerability_type}")
                finding.validation_message = f"No validator available for {finding.vulnerability_type}"
                finding.is_validated = True
                finding.is_exploitable = None  # Unknown
                self._save_finding(finding)
                return finding
            
            # Increment validation attempts
            finding.validation_attempts += 1
            
            # Perform validation
            validator_result = validator.validate(finding)
            
            # Update finding with validation results
            finding.is_validated = True
            finding.is_exploitable = validator_result.is_exploitable
            finding.validation_date = datetime.datetime.utcnow()
            finding.validation_message = validator_result.message
            finding.vxdf_data = validator_result.vxdf_data
            
            # Save evidence
            if validator_result.evidence:
                for evidence_item in validator_result.evidence:
                    evidence = Evidence(
                        finding_id=finding.id,
                        evidence_type=evidence_item.type,
                        description=evidence_item.description,
                        content=evidence_item.content
                    )
                    finding.evidence.append(evidence)
            
            # Save to database
            self._save_finding(finding)
            
            logger.info(f"Validation complete: {finding.id} - Exploitable: {finding.is_exploitable}")
            return finding
        
        except Exception as e:
            logger.error(f"Error validating finding {finding.id}: {e}", exc_info=True)
            finding.is_validated = True
            finding.is_exploitable = None  # Unknown
            finding.validation_date = datetime.datetime.utcnow()
            finding.validation_message = f"Error during validation: {str(e)}"
            self._save_finding(finding)
            return finding
    
    def _save_finding(self, finding: Finding) -> None:
        """
        Save a finding to the database.
        
        Args:
            finding: Finding to save
        """
        try:
            self.db.add(finding)
            self.db.commit()
        except Exception as e:
            logger.error(f"Error saving finding to database: {e}", exc_info=True)
            self.db.rollback()
    
    def generate_vxdf(self, findings: List[Finding], 
                     target_name: str = "Unknown Application",
                     target_version: Optional[str] = None) -> VXDFDocument:
        """
        Generate a VXDF document from validated findings.
        
        Args:
            findings: List of validated findings
            target_name: Name of the target application
            target_version: Version of the target application
            
        Returns:
            VXDF document
        """
        logger.info(f"Generating VXDF document for {len(findings)} findings")
        
        # Create metadata
        metadata = VXDFMetadata(
            generator_version=__version__,
            target_application=target_name,
            target_version=target_version
        )
        
        # Create flows from findings
        flows = []
        for finding in findings:
            if not finding.is_validated:
                logger.warning(f"Skipping unvalidated finding: {finding.id}")
                continue
            
            flow = self._create_flow_from_finding(finding)
            flows.append(flow)
        
        # Create VXDF document
        vxdf_doc = VXDFDocument(
            metadata=metadata,
            flows=flows
        )
        
        # Generate summary statistics
        vxdf_doc.generate_summary()
        
        return vxdf_doc
    
    def _create_flow_from_finding(self, finding: Finding) -> VXDFFlow:
        """
        Create a VXDF flow from a finding.
        
        Args:
            finding: Finding to convert
            
        Returns:
            VXDF flow
        """
        # Map severity
        try:
            severity = SeverityLevel(finding.severity)
        except ValueError:
            severity = SeverityLevel.MEDIUM
        
        # Create source location
        source = CodeLocation(
            file_path=finding.file_path or "Unknown",
            line_number=finding.line_number,
            column=finding.column
        )
        
        # Create sink location - for now, we use the same as source if not available
        # In a real-world scenario, we would extract this from data flow
        sink = source
        
        # Create evidence items
        evidence_items = []
        for evidence in finding.evidence:
            evidence_item = EvidenceItem(
                type=evidence.evidence_type,
                description=evidence.description,
                content=evidence.content
            )
            evidence_items.append(evidence_item)
        
        # Create data flow steps
        steps = []
        
        # If we have raw data with flow information, try to extract steps
        if finding.raw_data and isinstance(finding.raw_data, dict):
            # Extract from SARIF code flows if available
            if 'code_flows' in finding.raw_data:
                steps = self._extract_steps_from_sarif(finding.raw_data['code_flows'])
        
        # If no steps were extracted and we have source/sink, create simple flow
        if not steps and finding.file_path:
            # Add source step
            source_step = DataFlowStep(
                description="Source of untrusted data",
                location=source,
                step_type="source"
            )
            steps.append(source_step)
            
            # Add sink step
            sink_step = DataFlowStep(
                description="Sink where vulnerability is triggered",
                location=sink,
                step_type="sink"
            )
            steps.append(sink_step)
        
        # Create the VXDF flow
        flow = VXDFFlow(
            id=str(uuid.uuid4()),
            name=finding.name,
            description=finding.description or "No description available",
            vulnerability_type=finding.vulnerability_type,
            cwe_id=finding.cwe_id,
            severity=severity,
            cvss_score=finding.cvss_score,
            source=source,
            sink=sink,
            steps=steps,
            evidence=evidence_items,
            is_exploitable=finding.is_exploitable if finding.is_exploitable is not None else False,
            validation_date=finding.validation_date or datetime.datetime.utcnow(),
            validation_message=finding.validation_message,
            raw_finding_id=finding.source_id
        )
        
        return flow
    
    def _extract_steps_from_sarif(self, code_flows: List[Dict[str, Any]]) -> List[DataFlowStep]:
        """
        Extract data flow steps from SARIF code flows.
        
        Args:
            code_flows: SARIF code flows
            
        Returns:
            List of data flow steps
        """
        steps = []
        
        for flow in code_flows:
            if 'thread_flows' in flow:
                for thread_flow in flow['thread_flows']:
                    if 'locations' in thread_flow:
                        for i, loc in enumerate(thread_flow['locations']):
                            if 'physical_location' in loc:
                                phy_loc = loc['physical_location']
                                file_path = phy_loc.get('artifact_location', {}).get('uri', 'Unknown')
                                
                                region = phy_loc.get('region', {})
                                line_number = region.get('start_line')
                                column = region.get('start_column')
                                
                                message = loc.get('message', 'Unknown step')
                                
                                step_type = "intermediate"
                                if i == 0:
                                    step_type = "source"
                                elif i == len(thread_flow['locations']) - 1:
                                    step_type = "sink"
                                
                                code_loc = CodeLocation(
                                    file_path=file_path,
                                    line_number=line_number,
                                    column=column
                                )
                                
                                data_flow_step = DataFlowStep(
                                    description=message,
                                    location=code_loc,
                                    step_type=step_type
                                )
                                
                                steps.append(data_flow_step)
        
        return steps
