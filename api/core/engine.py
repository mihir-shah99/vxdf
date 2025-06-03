"""
Core validation engine that processes findings and coordinates validation.
"""
import logging
import datetime
import uuid
import time
import json
import re
import sys
import jsonschema
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, Set
from uuid import uuid4, UUID
from decimal import Decimal
from pydantic import ValidationError

from sqlalchemy.orm import Session

from api.models.database import get_db, SessionLocal
from api.models.finding import Finding, Evidence
from api.models.vxdf import (
    VXDFModel, GeneratorToolInfo, ApplicationInfo,
    ExploitFlowModel, TraceStepModel, LocationModel, EvidenceModel, SeverityModel,
    SeverityLevelEnum, StatusEnum, LocationTypeEnum, StepTypeEnum, 
    ValidationMethodEnum, EvidenceTypeEnum, AffectedComponentModel,
    # All evidence data models
    HttpRequestLogDataModel, HttpResponseLogDataModel, HttpHeaderModel,
    CodeSnippetDataModel, PocScriptDataModel, RuntimeLogEntryDataModel,
    ManualVerificationDataModel, TestPayloadDataModel, CommandExecutionOutputDataModel,
    ToolSpecificOutputDataModel, OtherEvidenceDataModel, StaticAnalysisPathDataModel,
    PathNodeModel, ScaOutputDataModel, ScaComponentIdentifierModel, ScaVulnerabilityIdentifierModel,
    HttpMethodEnum, HttpRequestBodyEncodingEnum, PayloadEncodingEnum, VulnerabilityIdSystemEnum
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
        Initialize the validation engine with proper session management.
        """
        self.validator_factory = ValidatorFactory()
        # Use the new session manager instead of creating our own session
        from api.core.session_manager import RealSessionManager
        self.session_manager = RealSessionManager()
        
        # Evidence type mapping from legacy strings to normative enums
        self.evidence_type_mapping = {
            'http_request': EvidenceTypeEnum.HTTP_REQUEST_LOG,
            'http_response': EvidenceTypeEnum.HTTP_RESPONSE_LOG,
            'code_snippet': EvidenceTypeEnum.CODE_SNIPPET_SOURCE,
            'code_snippet_source': EvidenceTypeEnum.CODE_SNIPPET_SOURCE,
            'code_snippet_sink': EvidenceTypeEnum.CODE_SNIPPET_SINK,
            'code_snippet_context': EvidenceTypeEnum.CODE_SNIPPET_CONTEXT,
            'poc_script': EvidenceTypeEnum.POC_SCRIPT,
            'runtime_log': EvidenceTypeEnum.RUNTIME_APPLICATION_LOG_ENTRY,
            'application_log': EvidenceTypeEnum.RUNTIME_APPLICATION_LOG_ENTRY,
            'system_log': EvidenceTypeEnum.RUNTIME_SYSTEM_LOG_ENTRY,
            'manual_verification': EvidenceTypeEnum.MANUAL_VERIFICATION_NOTES,
            'test_payload': EvidenceTypeEnum.TEST_PAYLOAD_USED,
            'command_execution': EvidenceTypeEnum.COMMAND_EXECUTION_OUTPUT,
            'tool_output': EvidenceTypeEnum.TOOL_SPECIFIC_OUTPUT_LOG,
            'static_analysis': EvidenceTypeEnum.STATIC_ANALYSIS_DATA_FLOW_PATH,
            'vulnerable_component': EvidenceTypeEnum.VULNERABLE_COMPONENT_SCAN_OUTPUT,
            'sca_output': EvidenceTypeEnum.VULNERABLE_COMPONENT_SCAN_OUTPUT,
            'other': EvidenceTypeEnum.OTHER_EVIDENCE
        }
    
    def __del__(self):
        """
        Clean up when the engine is destroyed.
        """
        # No need to clean up sessions - the session manager handles this
        pass
    
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
        Validate a finding to determine if it's exploitable using proper session management.
        
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
                # Use session manager to safely update the finding
                return self.session_manager.update_finding_validation(
                    finding.id,
                    None,  # Unknown exploitability
                    f"No validator available for {finding.vulnerability_type}"
                ) or finding
            
            # Perform validation using the validator
            logger.info(f"Running validation for {finding.vulnerability_type}")
            validator_result = validator.validate(finding)
            
            # Prepare evidence items for saving
            evidence_items = []
            if validator_result.evidence:
                logger.info(f"Processing {len(validator_result.evidence)} evidence items from validation")
                evidence_items = validator_result.evidence
            
            # Use session manager to safely update the finding and evidence
            updated_finding = self.session_manager.update_finding_validation(
                finding.id,
                validator_result.is_exploitable,
                validator_result.message,
                evidence_items
            )
            
            if updated_finding:
                logger.info(f"Validation complete: {finding.id} - Exploitable: {updated_finding.is_exploitable}")
                return updated_finding
            else:
                logger.error(f"Failed to update finding {finding.id}")
                return finding
            
        except Exception as e:
            logger.error(f"Error validating finding {finding.id}: {e}", exc_info=True)
            
            # Use session manager to safely save error state
            error_finding = self.session_manager.update_finding_validation(
                finding.id,
                None,  # Unknown due to error
                f"Error during validation: {str(e)}"
            )
            
            return error_finding or finding
    
    def _save_finding(self, finding: Finding) -> None:
        """
        Save a finding to the database using proper session management.
        
        Args:
            finding: Finding to save
        """
        try:
            self.session_manager.save_finding(finding)
        except Exception as e:
            logger.error(f"Error saving finding to database: {e}", exc_info=True)
    
    def generate_vxdf(self, findings: List[Finding], application_name: str, application_version: str = "1.0.0") -> VXDFModel:
        """
        Generate a VXDF document from security findings with intelligent correlation.
        
        Args:
            findings: List of security findings from various tools
            application_name: Name of the application being analyzed
            application_version: Version of the application
            
        Returns:
            VXDFModel: Complete VXDF document with correlated findings
        """
        logger.info(f"Generating VXDF document for {len(findings)} findings")
        
        # Step 1: Correlate findings intelligently
        correlated_groups = self._correlate_findings(findings)
        logger.info(f"Correlated {len(findings)} findings into {len(correlated_groups)} groups")
        
        # Step 2: Generate exploit flows from correlated groups
        exploit_flows = []
        for group in correlated_groups:
            flow = self._create_correlated_exploit_flow(group)
            if flow:
                exploit_flows.append(flow)
        
        # Handle the case where no security issues were found
        if not exploit_flows:
            logger.info("No security findings detected - creating summary flow")
            summary_flow = ExploitFlowModel(
                id=uuid.uuid4(),
                title="Security Analysis Summary - No Issues Found",
                description=f"Security analysis completed successfully. No vulnerabilities detected in {application_name}.",
                category="security_analysis_summary",
                severity=SeverityModel(
                    level=SeverityLevelEnum.INFORMATIONAL
                ),
                validatedAt=datetime.datetime.now(datetime.timezone.utc),
                evidence=[
                    EvidenceModel(
                        id=uuid.uuid4(),
                        evidenceType=EvidenceTypeEnum.OTHER_EVIDENCE,
                        description="Security scan completed with no findings",
                        validationMethod=ValidationMethodEnum.AUTOMATED_EXPLOIT_TOOL_CONFIRMATION,
                        data=OtherEvidenceDataModel(
                            dataTypeDescription="Security scan summary",
                            dataContent=f"Analysis completed for {application_name} - no security vulnerabilities detected"
                        )
                    )
                ]
            )
            exploit_flows.append(summary_flow)
        
        # Create VXDF document
        vxdf_doc = VXDFModel(
            id=uuid.uuid4(),
            vxdfVersion="1.0.0",
            generatedAt=datetime.datetime.now(datetime.timezone.utc),
            applicationInfo=ApplicationInfo(
                name=application_name,
                version=application_version
            ),
            exploitFlows=exploit_flows
        )
        
        logger.info(f"Generated VXDF document with {len(exploit_flows)} exploit flows")
        return vxdf_doc
    
    def _correlate_findings(self, findings: List[Finding]) -> List[List[Finding]]:
        """
        Intelligently correlate findings across tools.
        
        Args:
            findings: List of all findings
            
        Returns:
            List of correlated finding groups
        """
        correlated_groups = []
        processed_findings = set()
        
        for finding in findings:
            if id(finding) in processed_findings:
                continue
                
            # Start a new correlation group
            group = [finding]
            processed_findings.add(id(finding))
            
            # Find related findings
            for other_finding in findings:
                if id(other_finding) in processed_findings:
                    continue
                    
                if self._findings_are_related(finding, other_finding):
                    group.append(other_finding)
                    processed_findings.add(id(other_finding))
            
            correlated_groups.append(group)
        
        return correlated_groups
    
    def _findings_are_related(self, finding1: Finding, finding2: Finding) -> bool:
        """
        Determine if two findings are related and should be correlated.
        
        Args:
            finding1: First finding
            finding2: Second finding
            
        Returns:
            True if findings are related
        """
        # Same vulnerability type correlation
        if finding1.vulnerability_type == finding2.vulnerability_type:
            # Check for file/location proximity (SAST findings)
            if finding1.file_path and finding2.file_path:
                if finding1.file_path == finding2.file_path:
                    # Same file - check line proximity
                    if (finding1.line_number and finding2.line_number and 
                        abs(finding1.line_number - finding2.line_number) <= 10):
                        return True
            
            # Check for URL/endpoint correlation (DAST findings)
            if (finding1.raw_data and finding2.raw_data and 
                'url' in finding1.raw_data and 'url' in finding2.raw_data):
                url1 = finding1.raw_data['url']
                url2 = finding2.raw_data['url']
                if self._urls_are_related(url1, url2):
                    return True
        
        # Cross-tool correlation (SAST + DAST for same vulnerability type)
        if (finding1.vulnerability_type == finding2.vulnerability_type and
            finding1.source_type != finding2.source_type):
            # Different source types but same vulnerability - potential correlation
            if self._cross_tool_correlation_match(finding1, finding2):
                return True
        
        # Severity amplification correlation
        if (finding1.severity in ['CRITICAL', 'HIGH'] and 
            finding2.severity in ['CRITICAL', 'HIGH']):
            if self._severity_correlation_match(finding1, finding2):
                return True
        
        return False
    
    def _urls_are_related(self, url1: str, url2: str) -> bool:
        """Check if two URLs are related (same endpoint, similar paths)."""
        try:
            from urllib.parse import urlparse
            parsed1 = urlparse(str(url1))
            parsed2 = urlparse(str(url2))
            
            # Same host and similar path
            if parsed1.netloc == parsed2.netloc:
                path1_parts = parsed1.path.strip('/').split('/')
                path2_parts = parsed2.path.strip('/').split('/')
                
                # Same endpoint or nested paths
                if (len(path1_parts) > 0 and len(path2_parts) > 0 and
                    path1_parts[0] == path2_parts[0]):
                    return True
        except:
            pass
        return False
    
    def _cross_tool_correlation_match(self, finding1: Finding, finding2: Finding) -> bool:
        """Check if findings from different tools correlate to same vulnerability."""
        # SQL injection correlation across SAST/DAST
        if finding1.vulnerability_type == 'sql_injection':
            # Look for file/endpoint correlation
            if (finding1.file_path and finding2.raw_data and 'url' in finding2.raw_data):
                # Extract potential endpoint from file path
                if any(endpoint in finding1.file_path.lower() for endpoint in ['api', 'route', 'controller']):
                    return True
        
        # XSS correlation across tools
        if finding1.vulnerability_type == 'xss':
            if finding1.file_path and finding2.raw_data:
                return True
        
        return False
    
    def _severity_correlation_match(self, finding1: Finding, finding2: Finding) -> bool:
        """Check if high-severity findings should be correlated."""
        # Correlate critical dependency vulnerabilities with code vulnerabilities
        if (finding1.source_type == 'SCA' and finding2.source_type in ['SAST', 'DAST-ZAP']):
            return True
        return False
    
    def _create_correlated_exploit_flow(self, finding_group: List[Finding]) -> Optional[ExploitFlowModel]:
        """
        Create an exploit flow from a correlated group of findings.
        
        Args:
            finding_group: Group of correlated findings
            
        Returns:
            ExploitFlowModel with synthesized evidence
        """
        if not finding_group:
            return None
        
        # Use the most severe finding as the primary
        primary_finding = max(finding_group, key=lambda f: self._severity_score(f.severity))
        
        # Determine intelligent category based on correlation
        category = self._determine_intelligent_category(finding_group)
        
        # Create evidence from all findings in the group
        evidence_items = []
        for finding in finding_group:
            evidence = self._create_intelligent_evidence(finding)
            if evidence:
                evidence_items.append(evidence)
        
        # Determine correlation-aware severity
        correlated_severity = self._calculate_correlated_severity(finding_group)
        
        # Create exploit flow
        flow = ExploitFlowModel(
            id=uuid.uuid4(),
            title=self._create_correlated_title(finding_group),
            description=self._create_correlated_description(finding_group),
            category=category,
            severity=SeverityModel(
                level=SeverityLevelEnum(correlated_severity)
            ),
            validatedAt=datetime.datetime.now(datetime.timezone.utc),
            evidence=evidence_items
        )
        
        return flow
    
    def _determine_intelligent_category(self, finding_group: List[Finding]) -> str:
        """Determine category based on correlated findings."""
        vuln_types = [f.vulnerability_type for f in finding_group]
        source_types = [f.source_type for f in finding_group]
        
        # Multi-tool correlation categories
        if len(set(source_types)) > 1:
            if 'sql_injection' in vuln_types:
                return 'sql_injection_multi_tool'
            elif 'xss' in vuln_types:
                return 'xss_multi_tool'
            else:
                return 'multi_tool_correlation'
        
        # Single tool categories
        if vuln_types[0] == 'vulnerable_component':
            return 'vulnerable_component'
        elif vuln_types[0] == 'sql_injection':
            return 'sql_injection'
        elif vuln_types[0] == 'xss':
            return 'xss'
        else:
            return vuln_types[0] if vuln_types[0] else 'other'
    
    def _create_intelligent_evidence(self, finding: Finding) -> Optional[EvidenceModel]:
        """Create evidence with source-aware validation methods."""
        # Determine validation method based on source
        validation_method = self._get_source_aware_validation_method(finding)
        
        # Determine evidence type based on finding characteristics
        evidence_type = self._get_intelligent_evidence_type(finding)
        
        # Create appropriate data model based on evidence type
        evidence_data = self._create_evidence_data_model(finding, evidence_type)
        
        evidence = EvidenceModel(
            id=uuid.uuid4(),
            evidenceType=evidence_type,
            description=finding.description or f"Evidence from {finding.source_type}",
            validationMethod=validation_method,
            data=evidence_data
        )
        
        return evidence
    
    def _create_evidence_data_model(self, finding: Finding, evidence_type: EvidenceTypeEnum):
        """Create the appropriate data model based on evidence type."""
        if evidence_type == EvidenceTypeEnum.CODE_SNIPPET_SOURCE:
            return CodeSnippetDataModel(
                content=finding.description or f"Code finding: {finding.name}",
                language="javascript" if finding.file_path and ".js" in finding.file_path else None,
                filePath=finding.file_path,
                startLine=finding.line_number,
                endLine=finding.line_number
            )
        elif evidence_type == EvidenceTypeEnum.HTTP_REQUEST_LOG:
            # Extract URL from raw_data if available
            url = "http://localhost:3000/"
            if finding.raw_data and 'url' in finding.raw_data:
                url = finding.raw_data['url']
            
            return HttpRequestLogDataModel(
                method=HttpMethodEnum.GET,
                url=url,
                headers=[],
                body=None
            )
        elif evidence_type == EvidenceTypeEnum.VULNERABLE_COMPONENT_SCAN_OUTPUT:
            # Create SCA data model
            component_name = "unknown-component"
            component_version = "0.0.0"
            
            if finding.raw_data:
                if isinstance(finding.raw_data, dict):
                    component_name = finding.raw_data.get('name', component_name)
                    component_version = finding.raw_data.get('version', component_version)
            
            return ScaOutputDataModel(
                componentIdentifier=ScaComponentIdentifierModel(
                    name=component_name,
                    version=component_version
                ),
                vulnerabilityIdentifiers=[
                    ScaVulnerabilityIdentifierModel(
                        idSystem=VulnerabilityIdSystemEnum.OTHER,
                        idValue=f"vuln-{component_name}"
                    )
                ],
                toolName="SCA Scanner",
                vulnerabilitySeverity=finding.severity
            )
        else:
            # Default to OTHER_EVIDENCE
            content = self._create_evidence_content(finding)
            return OtherEvidenceDataModel(
                dataTypeDescription=f"Security finding from {finding.source_type}",
                dataContent=content
            )
    
    def _get_source_aware_validation_method(self, finding: Finding) -> ValidationMethodEnum:
        """Get validation method based on finding source."""
        if finding.source_type == 'SARIF' or 'SAST' in finding.source_type:
            return ValidationMethodEnum.STATIC_ANALYSIS_VALIDATION
        elif 'DAST' in finding.source_type or finding.source_type.startswith('DAST'):
            return ValidationMethodEnum.DYNAMIC_ANALYSIS_EXPLOIT
        elif finding.source_type == 'SCA':
            return ValidationMethodEnum.SOFTWARE_COMPOSITION_ANALYSIS_CONTEXTUAL_VALIDATION
        else:
            return ValidationMethodEnum.AUTOMATED_EXPLOIT_TOOL_CONFIRMATION
    
    def _get_intelligent_evidence_type(self, finding: Finding) -> EvidenceTypeEnum:
        """Get evidence type based on finding characteristics."""
        if finding.file_path and finding.line_number:
            return EvidenceTypeEnum.CODE_SNIPPET_SOURCE
        elif finding.raw_data and 'url' in str(finding.raw_data):
            return EvidenceTypeEnum.HTTP_REQUEST_LOG
        elif finding.vulnerability_type == 'vulnerable_component':
            return EvidenceTypeEnum.VULNERABLE_COMPONENT_SCAN_OUTPUT
        else:
            return EvidenceTypeEnum.OTHER_EVIDENCE
    
    def _create_correlated_title(self, finding_group: List[Finding]) -> str:
        """Create title that reflects correlation."""
        if len(finding_group) == 1:
            return finding_group[0].name
        
        vuln_types = set(f.vulnerability_type for f in finding_group)
        source_types = set(f.source_type for f in finding_group)
        
        if len(vuln_types) == 1:
            vuln_type = list(vuln_types)[0]
            if len(source_types) > 1:
                return f"{vuln_type.replace('_', ' ').title()} (Multi-Tool Correlation)"
            else:
                return f"{vuln_type.replace('_', ' ').title()} (Multiple Instances)"
        else:
            return f"Correlated Security Issues ({len(finding_group)} findings)"
    
    def _create_correlated_description(self, finding_group: List[Finding]) -> str:
        """Create description that explains correlation."""
        if len(finding_group) == 1:
            return finding_group[0].description or "Security vulnerability detected"
        
        source_types = [f.source_type for f in finding_group]
        vuln_types = [f.vulnerability_type for f in finding_group]
        
        desc = f"Correlated security findings from {len(set(source_types))} tool(s): "
        desc += ", ".join(set(source_types))
        desc += f". Vulnerability types: {', '.join(set(vuln_types))}"
        
        return desc
    
    def _calculate_correlated_severity(self, finding_group: List[Finding]) -> str:
        """Calculate severity based on correlation and amplification."""
        severities = [f.severity for f in finding_group]
        severity_scores = [self._severity_score(s) for s in severities]
        max_score = max(severity_scores)
        
        # Amplification logic - multiple findings increase severity
        if len(finding_group) > 1:
            source_types = set(f.source_type for f in finding_group)
            if len(source_types) > 1:  # Multi-tool correlation
                max_score = min(max_score + 1.0, 10.0)  # Amplify but cap at 10
        
        # Convert back to severity level
        if max_score >= 9.0:
            return 'CRITICAL'
        elif max_score >= 7.0:
            return 'HIGH'
        elif max_score >= 4.0:
            return 'MEDIUM'
        elif max_score >= 1.0:
            return 'LOW'
        else:
            return 'INFORMATIONAL'
    
    def _severity_score(self, severity: str) -> float:
        """Convert severity to numeric score."""
        severity_map = {
            'CRITICAL': 9.0,
            'HIGH': 7.0,
            'MEDIUM': 5.0,
            'LOW': 3.0,
            'INFORMATIONAL': 1.0
        }
        return severity_map.get(severity.upper(), 5.0)
    
    def _extract_steps_from_sarif(self, code_flows: List[Dict[str, Any]]) -> List[TraceStepModel]:
        """
        Extract data flow steps from SARIF code flows.
        
        Args:
            code_flows: SARIF code flows
            
        Returns:
            List of normative TraceStepModel objects
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
                                
                                message = loc.get('message', {})
                                if isinstance(message, dict):
                                    description = message.get('text', 'Unknown step')
                                else:
                                    description = str(message) if message else 'Unknown step'
                                
                                # Map step position to step type
                                step_type = StepTypeEnum.INTERMEDIATE_NODE
                                if i == 0:
                                    step_type = StepTypeEnum.SOURCE_INTERACTION
                                elif i == len(thread_flow['locations']) - 1:
                                    step_type = StepTypeEnum.SINK_INTERACTION
                                
                                # Create normative LocationModel
                                location = LocationModel(
                                    locationType=LocationTypeEnum.SOURCE_CODE_UNIT,
                                    filePath=file_path,
                                    startLine=line_number,
                                    startColumn=column,
                                    description=f"Location in {file_path}"
                                )
                                
                                # Create normative TraceStepModel
                                step = TraceStepModel(
                                    order=i,
                                    location=location,
                                    description=description,
                                    stepType=step_type
                                )
                                
                                steps.append(step)
        
        return steps
    
    def _map_evidence_type(self, evidence_type_str: str) -> EvidenceTypeEnum:
        """
        Map legacy evidence type strings to normative EvidenceTypeEnum values.
        
        Args:
            evidence_type_str: Legacy evidence type string from database
            
        Returns:
            Corresponding EvidenceTypeEnum value
        """
        # Normalize the input
        normalized_type = evidence_type_str.lower().replace('_', '_').replace('-', '_')
        
        # Try exact match first
        if normalized_type in self.evidence_type_mapping:
            return self.evidence_type_mapping[normalized_type]
        
        # Try partial matches for flexibility
        for key, enum_value in self.evidence_type_mapping.items():
            if key in normalized_type or normalized_type in key:
                return enum_value
        
        # Default to OTHER_EVIDENCE
        logger.warning(f"Unknown evidence type '{evidence_type_str}', defaulting to OTHER_EVIDENCE")
        return EvidenceTypeEnum.OTHER_EVIDENCE
    
    def _parse_evidence_content(self, evidence: Evidence) -> Any:
        """
        Parse evidence content based on evidence type into appropriate structured data model.
        
        Args:
            evidence: Evidence object from database
            
        Returns:
            Structured data model instance for the evidence
        """
        evidence_type = self._map_evidence_type(evidence.evidence_type)
        content = evidence.content or ""
        
        try:
            if evidence_type == EvidenceTypeEnum.HTTP_REQUEST_LOG:
                return self._parse_http_request_content(content)
            elif evidence_type == EvidenceTypeEnum.HTTP_RESPONSE_LOG:
                return self._parse_http_response_content(content)
            elif evidence_type in [EvidenceTypeEnum.CODE_SNIPPET_SOURCE, EvidenceTypeEnum.CODE_SNIPPET_SINK, EvidenceTypeEnum.CODE_SNIPPET_CONTEXT]:
                return self._parse_code_snippet_content(content, evidence)
            elif evidence_type == EvidenceTypeEnum.POC_SCRIPT:
                return self._parse_poc_script_content(content)
            elif evidence_type in [EvidenceTypeEnum.RUNTIME_APPLICATION_LOG_ENTRY, EvidenceTypeEnum.RUNTIME_SYSTEM_LOG_ENTRY]:
                return self._parse_runtime_log_content(content)
            elif evidence_type == EvidenceTypeEnum.MANUAL_VERIFICATION_NOTES:
                return self._parse_manual_verification_content(content)
            elif evidence_type == EvidenceTypeEnum.TEST_PAYLOAD_USED:
                return self._parse_test_payload_content(content)
            elif evidence_type == EvidenceTypeEnum.COMMAND_EXECUTION_OUTPUT:
                return self._parse_command_execution_content(content)
            elif evidence_type == EvidenceTypeEnum.TOOL_SPECIFIC_OUTPUT_LOG:
                return self._parse_tool_output_content(content)
            elif evidence_type == EvidenceTypeEnum.STATIC_ANALYSIS_DATA_FLOW_PATH:
                return self._parse_static_analysis_content(content)
            elif evidence_type == EvidenceTypeEnum.VULNERABLE_COMPONENT_SCAN_OUTPUT:
                return self._parse_sca_output_content(content)
            else:
                # Default to OTHER_EVIDENCE
                return self._parse_other_evidence_content(content, evidence_type)
        
        except Exception as e:
            logger.warning(f"Error parsing evidence content for type {evidence_type}: {e}")
            # Fallback to OTHER_EVIDENCE
            return self._parse_other_evidence_content(content, evidence_type)
    
    def _parse_http_request_content(self, content: str) -> HttpRequestLogDataModel:
        """Parse HTTP request content into structured data."""
        # Default values
        method = HttpMethodEnum.GET
        url = "unknown"
        headers = []
        body = None
        body_encoding = HttpRequestBodyEncodingEnum.PLAINTEXT
        
        try:
            # Try to parse structured HTTP request content
            lines = content.split('\n')
            
            # Look for request line
            for line in lines:
                if line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ', 'OPTIONS ')):
                    parts = line.split()
                    if len(parts) >= 2:
                        method_str = parts[0].upper()
                        if hasattr(HttpMethodEnum, method_str):
                            method = getattr(HttpMethodEnum, method_str)
                        url = parts[1]
                    break
            
            # Parse headers
            in_headers = False
            in_body = False
            body_lines = []
            
            for line in lines:
                if line.startswith('===== HTTP Request ====='):
                    in_headers = True
                    continue
                elif line.startswith('===== HTTP Response ====='):
                    break
                elif in_headers and line.strip() == '':
                    in_body = True
                    continue
                elif in_body:
                    body_lines.append(line)
                elif in_headers and ':' in line:
                    header_parts = line.split(':', 1)
                    if len(header_parts) == 2:
                        headers.append(HttpHeaderModel(
                            name=header_parts[0].strip(),
                            value=header_parts[1].strip()
                        ))
            
            if body_lines:
                body = '\n'.join(body_lines)
                # Try to detect body encoding
                if body.startswith('{') and body.endswith('}'):
                    body_encoding = HttpRequestBodyEncodingEnum.JSON
                elif '=' in body and '&' in body:
                    body_encoding = HttpRequestBodyEncodingEnum.FORM_URLENCODED
        
        except Exception as e:
            logger.warning(f"Error parsing HTTP request content: {e}")
        
        return HttpRequestLogDataModel(
            method=method,
            url=url,
            headers=headers,
            body=body,
            bodyEncoding=body_encoding
        )
    
    def _parse_http_response_content(self, content: str) -> HttpResponseLogDataModel:
        """Parse HTTP response content into structured data."""
        status_code = 200
        headers = []
        body = None
        body_encoding = HttpRequestBodyEncodingEnum.PLAINTEXT
        
        try:
            lines = content.split('\n')
            in_response = False
            in_body = False
            body_lines = []
            
            for line in lines:
                if line.startswith('===== HTTP Response ====='):
                    in_response = True
                    continue
                elif line.startswith('Status:'):
                    try:
                        status_code = int(line.split()[1])
                    except (IndexError, ValueError):
                        pass
                elif in_response and line.strip() == '':
                    in_body = True
                    continue
                elif in_body:
                    body_lines.append(line)
                elif in_response and ':' in line:
                    header_parts = line.split(':', 1)
                    if len(header_parts) == 2:
                        headers.append(HttpHeaderModel(
                            name=header_parts[0].strip(),
                            value=header_parts[1].strip()
                        ))
            
            if body_lines:
                body = '\n'.join(body_lines)
                # Detect content type from headers or content
                content_type = ""
                for header in headers:
                    if header.name.lower() == 'content-type':
                        content_type = header.value.lower()
                        break
                
                if 'json' in content_type or (body.strip().startswith('{') and body.strip().endswith('}')):
                    body_encoding = HttpRequestBodyEncodingEnum.JSON
                elif 'html' in content_type or body.strip().startswith('<'):
                    body_encoding = HttpRequestBodyEncodingEnum.XML  # Using XML for HTML
        
        except Exception as e:
            logger.warning(f"Error parsing HTTP response content: {e}")
        
        return HttpResponseLogDataModel(
            statusCode=status_code,
            headers=headers,
            body=body,
            bodyEncoding=body_encoding
        )
    
    def _parse_code_snippet_content(self, content: str, evidence: Evidence) -> CodeSnippetDataModel:
        """Parse code snippet content into structured data."""
        # Try to extract language from content or context
        language = None
        file_path = None
        
        # Check if finding has file path info
        finding = evidence.finding if hasattr(evidence, 'finding') else None
        if finding and finding.file_path:
            file_path = finding.file_path
            # Guess language from file extension
            if file_path.endswith('.py'):
                language = 'python'
            elif file_path.endswith(('.js', '.jsx')):
                language = 'javascript'
            elif file_path.endswith('.java'):
                language = 'java'
            elif file_path.endswith(('.c', '.cpp', '.cc')):
                language = 'c++'
            elif file_path.endswith('.php'):
                language = 'php'
            elif file_path.endswith('.go'):
                language = 'go'
        
        return CodeSnippetDataModel(
            content=content,
            language=language,
            filePath=file_path
        )
    
    def _parse_poc_script_content(self, content: str) -> PocScriptDataModel:
        """Parse POC script content into structured data."""
        # Try to detect script language
        language = "unknown"
        if content.startswith('#!/bin/bash') or 'bash' in content.lower():
            language = "bash"
        elif content.startswith('#!/usr/bin/python') or 'import ' in content:
            language = "python"
        elif 'curl ' in content:
            language = "bash"
        
        return PocScriptDataModel(
            scriptLanguage=language,
            scriptContent=content,
            expectedOutcome="Demonstration of vulnerability exploitation"
        )
    
    def _parse_runtime_log_content(self, content: str) -> RuntimeLogEntryDataModel:
        """Parse runtime log content into structured data."""
        return RuntimeLogEntryDataModel(
            message=content
        )
    
    def _parse_manual_verification_content(self, content: str) -> ManualVerificationDataModel:
        """Parse manual verification content into structured data."""
        return ManualVerificationDataModel(
            verificationSteps=content,
            observedOutcome="Manual validation performed"
        )
    
    def _parse_test_payload_content(self, content: str) -> TestPayloadDataModel:
        """Parse test payload content into structured data."""
        encoding = PayloadEncodingEnum.PLAINTEXT
        
        # Try to detect encoding
        if content.startswith('%') and '%20' in content:
            encoding = PayloadEncodingEnum.URLENCODED
        elif re.match(r'^[A-Fa-f0-9]+$', content.replace(' ', '')):
            encoding = PayloadEncodingEnum.HEX
        
        return TestPayloadDataModel(
            payloadContent=content,
            payloadEncoding=encoding
        )
    
    def _parse_command_execution_content(self, content: str) -> CommandExecutionOutputDataModel:
        """Parse command execution content into structured data."""
        # Try to extract command and output
        lines = content.split('\n', 1)
        command = lines[0] if lines else content
        output = lines[1] if len(lines) > 1 else ""
        
        return CommandExecutionOutputDataModel(
            command=command,
            output=output
        )
    
    def _parse_tool_output_content(self, content: str) -> ToolSpecificOutputDataModel:
        """Parse tool output content into structured data."""
        return ToolSpecificOutputDataModel(
            toolName="Unknown Tool",
            relevantLogSectionOrOutput=content
        )
    
    def _parse_static_analysis_content(self, content: str) -> StaticAnalysisPathDataModel:
        """Parse static analysis content into structured data."""
        # Create a simple path with one node
        location = LocationModel(
            locationType=LocationTypeEnum.SOURCE_CODE_UNIT,
            description="Static analysis location"
        )
        
        node = PathNodeModel(
            order=0,
            location=location,
            description=content[:200] if len(content) > 200 else content
        )
        
        return StaticAnalysisPathDataModel(
            pathNodes=[node]
        )
    
    def _parse_sca_output_content(self, content: str) -> ScaOutputDataModel:
        """Parse SCA output content into structured data."""
        # Try to parse as JSON first
        try:
            data = json.loads(content)
            component_name = data.get('component', 'Unknown Component')
            component_version = data.get('version', '1.0.0')
            vulnerability_ids = data.get('vulnerabilities', [])
        except json.JSONDecodeError:
            # Fallback to basic parsing
            component_name = "Unknown Component"
            component_version = "1.0.0"
            vulnerability_ids = []
        
        component = ScaComponentIdentifierModel(
            name=component_name,
            version=component_version
        )
        
        vuln_identifiers = []
        if vulnerability_ids:
            for vuln_id in vulnerability_ids:
                if isinstance(vuln_id, str) and vuln_id.startswith('CVE-'):
                    vuln_identifiers.append(ScaVulnerabilityIdentifierModel(
                        idSystem=VulnerabilityIdSystemEnum.CVE,
                        idValue=vuln_id
                    ))
        
        # If no vulnerability IDs found, create a generic one
        if not vuln_identifiers:
            vuln_identifiers.append(ScaVulnerabilityIdentifierModel(
                idSystem=VulnerabilityIdSystemEnum.OTHER,
                idValue="UNKNOWN-VULN"
            ))
        
        return ScaOutputDataModel(
            componentIdentifier=component,
            vulnerabilityIdentifiers=vuln_identifiers
        )
    
    def _parse_other_evidence_content(self, content: str, evidence_type: EvidenceTypeEnum) -> OtherEvidenceDataModel:
        """Parse content that doesn't fit other categories."""
        return OtherEvidenceDataModel(
            dataTypeDescription=f"Evidence of type {evidence_type.value}",
            dataContent=content
        )

    def process_file(self, file_path: str) -> VXDFModel:
        """
        Process a SARIF or JSON file and generate VXDF document.
        
        Args:
            file_path: Path to the input file
            
        Returns:
            Generated VXDF document
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # For now, generate a default VXDF document with empty findings
            # In a real implementation, this would parse SARIF data
            findings = []  # Empty findings list for this basic implementation
            
            return self.generate_vxdf(
                findings=findings,
                target_name="Processed Application",
                target_version="Unknown"
            )
            
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            # Return a minimal valid VXDF document
            return self.generate_vxdf(
                findings=[],
                target_name="Error Processing",
                target_version="Unknown"
            )

    def process_file_with_validation(self, file_path: str, strict_validation: bool = False) -> VXDFModel:
        """
        Process a file and generate VXDF with optional strict validation.
        
        Args:
            file_path: Path to the input file (SARIF or JSON)
            strict_validation: Whether to perform strict schema validation
            
        Returns:
            Generated VXDF document
            
        Raises:
            ValueError: If strict validation is enabled and validation fails
        """
        # Process the file normally
        vxdf_document = self.process_file(file_path)
        
        # If strict validation is enabled, validate against schema
        if strict_validation:
            try:
                self._validate_vxdf_document(vxdf_document)
                logger.info("✅ Strict validation passed")
            except Exception as e:
                logger.error(f"❌ Strict validation failed: {e}")
                raise ValueError(f"VXDF document failed strict validation: {e}")
        
        return vxdf_document
    
    def _validate_vxdf_document(self, vxdf_document: VXDFModel) -> None:
        """
        Validate a VXDF document against the authoritative schema.
        
        Args:
            vxdf_document: The VXDF document to validate
            
        Raises:
            Exception: If validation fails
        """
        try:
            # Load the normative schema
            schema_path = Path(__file__).parent.parent.parent / "docs" / "normative-schema.json"
            
            if not schema_path.exists():
                raise FileNotFoundError(f"Normative schema not found at {schema_path}")
            
            with open(schema_path, 'r', encoding='utf-8') as f:
                schema = json.load(f)
            
            # Convert VXDF document to dict for validation with proper serialization
            document_dict = json.loads(vxdf_document.model_dump_json())
            
            # Perform JSON schema validation
            jsonschema.validate(document_dict, schema)
            
            logger.info("VXDF document passed JSON schema validation")
            
        except jsonschema.ValidationError as e:
            error_path = " -> ".join(str(p) for p in e.absolute_path) if e.absolute_path else "(root)"
            raise Exception(f"Schema validation failed at {error_path}: {e.message}")
        except jsonschema.SchemaError as e:
            raise Exception(f"Invalid schema: {e}")
        except Exception as e:
            raise Exception(f"Validation error: {e}")
    
    def validate_existing_vxdf(self, vxdf_file_path: str) -> Dict[str, Any]:
        """
        Validate an existing VXDF file and return validation results.
        
        Args:
            vxdf_file_path: Path to the VXDF file to validate
            
        Returns:
            Dict containing validation results
        """
        try:
            # Load the VXDF file
            with open(vxdf_file_path, 'r', encoding='utf-8') as f:
                vxdf_data = json.load(f)
            
            # Load the normative schema
            schema_path = Path(__file__).parent.parent.parent / "docs" / "normative-schema.json"
            
            with open(schema_path, 'r', encoding='utf-8') as f:
                schema = json.load(f)
            
            # Perform validation
            jsonschema.validate(vxdf_data, schema)
            
            return {
                "is_valid": True,
                "file_path": vxdf_file_path,
                "message": "VXDF document is valid",
                "exploit_flows": len(vxdf_data.get("exploitFlows", [])),
                "evidence_count": sum(len(flow.get("evidence", [])) for flow in vxdf_data.get("exploitFlows", []))
            }
            
        except jsonschema.ValidationError as e:
            error_path = " -> ".join(str(p) for p in e.absolute_path) if e.absolute_path else "(root)"
            return {
                "is_valid": False,
                "file_path": vxdf_file_path,
                "error": f"Validation failed at {error_path}: {e.message}",
                "failed_value": str(e.instance)[:200] if hasattr(e, 'instance') else None
            }
        except Exception as e:
            return {
                "is_valid": False,
                "file_path": vxdf_file_path,
                "error": f"Validation error: {e}"
            }

    def setup_validation_container(self, finding: Finding) -> str:
        """
        Set up a Docker container for validating a finding.
        
        Args:
            finding: Finding to validate
            
        Returns:
            Container ID
        """
        logger.info(f"Setting up validation container for finding: {finding.id}")
        
        # For now, we'll just return a dummy container ID
        # In a real implementation, this would create and configure a Docker container
        return f"validation-container-{finding.id}"
    
    def cleanup_validation_container(self, container_id: str) -> None:
        """
        Clean up a validation container.
        
        Args:
            container_id: ID of the container to clean up
        """
        logger.info(f"Cleaning up validation container: {container_id}")
        
        # For now, this is a no-op
        # In a real implementation, this would stop and remove the Docker container
        pass
    
    def collect_evidence(self, finding: Finding, validation_result: Any) -> List[Dict[str, Any]]:
        """
        Collect evidence from a validation container.
        
        Args:
            finding: Finding being validated
            validation_result: Result of validation
            
        Returns:
            List of evidence items
        """
        logger.info(f"Collecting evidence for finding: {finding.id}")
        
        # For now, return the evidence from the validation result
        # In a real implementation, this would collect evidence from the container
        return validation_result.evidence if hasattr(validation_result, 'evidence') else []

    def _create_evidence_content(self, finding: Finding) -> str:
        """Create evidence content from finding data."""
        content_parts = []
        
        if finding.file_path:
            content_parts.append(f"File: {finding.file_path}")
        if finding.line_number:
            content_parts.append(f"Line: {finding.line_number}")
        if finding.raw_data:
            content_parts.append(f"Raw data: {str(finding.raw_data)[:200]}...")
        
        if finding.description:
            content_parts.append(f"Description: {finding.description}")
        
        return " | ".join(content_parts) if content_parts else f"Finding from {finding.source_type}"
