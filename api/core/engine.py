"""
Core validation engine that processes findings and coordinates validation.
"""
import logging
import datetime
import uuid
import time
from typing import List, Dict, Any, Optional, Union, Set

from sqlalchemy.orm import Session

from api.models.database import get_db, SessionLocal
from api.models.finding import Finding, Evidence
from api.models.vxdf import (
    VXDFModel, GeneratorToolInfo, ApplicationInfo, VulnerabilityDetailsModel,
    ExploitFlowModel, TraceStepModel, LocationModel, EvidenceModel, SeverityModel,
    SeverityLevelEnum, StatusEnum, LocationTypeEnum, StepTypeEnum, 
    ValidationMethodEnum, EvidenceTypeEnum, AffectedComponentModel,
    OtherEvidenceDataModel, ManualVerificationDataModel, 
    CodeSnippetDataModel, RuntimeLogEntryDataModel
)
from api.core.validator import ValidatorFactory
from api import __version__
from api.config import SEVERITY_THRESHOLDS

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
                     target_version: Optional[str] = None) -> VXDFModel:
        """
        Generate a VXDF document from validated findings using v1.0.0 schema.
        
        Args:
            findings: List of validated findings
            target_name: Name of the target application
            target_version: Version of the target application
            
        Returns:
            VXDF v1.0.0 compliant document
        """
        logger.info(f"Generating VXDF v1.0.0 document for {len(findings)} findings")
        
        # Create generator tool info
        generator_info = GeneratorToolInfo(
            name="VXDF Validate",
            version=__version__
        )
        
        # Create application info
        app_info = ApplicationInfo(
            name=target_name,
            version=target_version
        )
        
        # Create evidence pool
        evidence_pool = []
        
        # Create exploit flows from findings
        exploit_flows = []
        for finding in findings:
            if not finding.is_validated:
                logger.warning(f"Skipping unvalidated finding: {finding.id}")
                continue
            
            flow, flow_evidence = self._create_exploit_flow_from_finding(finding)
            exploit_flows.append(flow)
            evidence_pool.extend(flow_evidence)
        
        # If no exploit flows were created, create a default one
        if not exploit_flows:
            logger.info("No findings provided, creating default exploit flow")
            default_location = LocationModel(
                locationType=LocationTypeEnum.GENERIC_RESOURCE_IDENTIFIER,
                description="No specific location identified"
            )
            
            default_step = TraceStepModel(
                order=0,
                location=default_location,
                description="No validated vulnerabilities found",
                stepType=StepTypeEnum.SOURCE_INTERACTION
            )
            
            default_flow = ExploitFlowModel(
                description="No validated vulnerabilities found in this assessment",
                trace=[default_step],
                status=StatusEnum.FALSE_POSITIVE_AFTER_REVALIDATION
            )
            exploit_flows.append(default_flow)
        
        # Create severity assessment for the overall vulnerability
        # For now, use the highest severity from all flows
        max_severity = SeverityLevelEnum.INFORMATIONAL
        if findings:
            # Find the highest severity from findings
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'NONE']
            for finding in findings:
                if finding.severity and finding.severity in severity_order:
                    finding_severity_index = severity_order.index(finding.severity)
                    current_severity_index = severity_order.index(max_severity.value)
                    if finding_severity_index < current_severity_index:
                        max_severity = SeverityLevelEnum(finding.severity)
        
        severity_model = SeverityModel(
            level=max_severity,
            justification="Severity determined from validation results"
        )
        
        # Create vulnerability details
        vulnerability_details = VulnerabilityDetailsModel(
            vulnerabilityId=str(uuid.uuid4()),
            title=f"Security Assessment Results for {target_name}",
            description=f"Security assessment results for {target_name}. {len(findings)} findings processed.",
            severity=severity_model,
            exploitFlows=exploit_flows,
            affectedApplications=[app_info] if app_info else []
        )
        
        # Create VXDF document
        vxdf_doc = VXDFModel(
            generatorToolInfo=generator_info,
            vulnerability=vulnerability_details,
            evidencePool=evidence_pool
        )
        
        return vxdf_doc
    
    def _create_exploit_flow_from_finding(self, finding: Finding) -> tuple[ExploitFlowModel, List[EvidenceModel]]:
        """
        Create a VXDF v1.0.0 exploit flow from a finding.
        
        Args:
            finding: Finding to convert
            
        Returns:
            Tuple of (ExploitFlowModel, List of EvidenceModel)
        """
        # Create evidence items first
        evidence_items = []
        for evidence in finding.evidence:
            # Map evidence type to new enum
            evidence_type = EvidenceTypeEnum.OTHER_EVIDENCE
            try:
                evidence_type = EvidenceTypeEnum(evidence.evidence_type.upper())
            except ValueError:
                pass
            
            # Create appropriate data structure based on evidence type
            evidence_data = None
            if evidence_type == EvidenceTypeEnum.OTHER_EVIDENCE:
                evidence_data = OtherEvidenceDataModel(
                    dataTypeDescription="Legacy evidence data",
                    dataContent=str(evidence.content) if evidence.content else "No content"
                )
            elif evidence_type == EvidenceTypeEnum.MANUAL_VERIFICATION_NOTES:
                evidence_data = ManualVerificationDataModel(
                    verificationSteps="Manual verification performed",
                    observedOutcome=str(evidence.content) if evidence.content else "No outcome recorded"
                )
            elif evidence_type in [EvidenceTypeEnum.CODE_SNIPPET_SOURCE, EvidenceTypeEnum.CODE_SNIPPET_SINK, EvidenceTypeEnum.CODE_SNIPPET_CONTEXT]:
                evidence_data = CodeSnippetDataModel(
                    content=str(evidence.content) if evidence.content else "No code content",
                    filePath=finding.file_path
                )
            elif evidence_type in [EvidenceTypeEnum.RUNTIME_APPLICATION_LOG_ENTRY, EvidenceTypeEnum.RUNTIME_SYSTEM_LOG_ENTRY]:
                evidence_data = RuntimeLogEntryDataModel(
                    message=str(evidence.content) if evidence.content else "No log message"
                )
            else:
                # Default to other evidence for unknown types
                evidence_data = OtherEvidenceDataModel(
                    dataTypeDescription=f"Evidence of type {evidence_type.value}",
                    dataContent=str(evidence.content) if evidence.content else "No content"
                )
            
            evidence_item = EvidenceModel(
                evidenceType=evidence_type,
                description=evidence.description or f"Evidence for {finding.name}",
                data=evidence_data,
                validationMethod=ValidationMethodEnum.AUTOMATED_EXPLOIT_TOOL_CONFIRMATION
            )
            evidence_items.append(evidence_item)
        
        # Create source location
        source_location = LocationModel(
            locationType=LocationTypeEnum.SOURCE_CODE_UNIT,
            filePath=finding.file_path or "Unknown",
            startLine=finding.line_number,
            startColumn=finding.column,
            description="Source location of the vulnerability"
        )
        
        # Create trace steps
        trace_steps = []
        
        # Add source step
        source_step = TraceStepModel(
            order=0,
            location=source_location,
            description="Source of untrusted data",
            stepType=StepTypeEnum.SOURCE_INTERACTION,
            evidenceRefs={evidence.id for evidence in evidence_items}
        )
        trace_steps.append(source_step)
        
        # Add sink step (for now, same as source if no flow data available)
        sink_step = TraceStepModel(
            order=1,
            location=source_location,
            description="Sink where vulnerability is triggered",
            stepType=StepTypeEnum.SINK_INTERACTION,
            evidenceRefs={evidence.id for evidence in evidence_items}
        )
        trace_steps.append(sink_step)
        
        # Create the exploit flow
        flow = ExploitFlowModel(
            description=finding.description or f"Exploit flow for {finding.name}",
            trace=trace_steps,
            status=StatusEnum.OPEN if finding.is_exploitable else StatusEnum.FALSE_POSITIVE_AFTER_REVALIDATION
        )
        
        return flow, evidence_items
    
    def _extract_steps_from_sarif(self, code_flows: List[Dict[str, Any]]) -> List[TraceStepModel]:
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
                                
                                code_loc = LocationModel(
                                    file_path=file_path,
                                    line_number=line_number,
                                    column=column
                                )
                                
                                data_flow_step = TraceStepModel(
                                    description=message,
                                    location=code_loc,
                                    step_type=step_type
                                )
                                
                                steps.append(data_flow_step)
        
        return steps
