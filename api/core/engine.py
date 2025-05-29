"""
Core validation engine that processes findings and coordinates validation.
"""
import logging
import datetime
import uuid
import time
import json
import re
from typing import List, Dict, Any, Optional, Union, Set

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
        Initialize the validation engine.
        """
        self.validator_factory = ValidatorFactory()
        self.db = SessionLocal()
        
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
            finding.validation_date = datetime.datetime.now(datetime.UTC)
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
            finding.validation_date = datetime.datetime.now(datetime.UTC)
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
        
        # Create exploit flows from findings
        exploit_flows = []
        for finding in findings:
            # Process all findings, not just validated ones
            # Mark unvalidated findings appropriately
            if not finding.is_validated:
                logger.info(f"Processing unvalidated finding: {finding.id}")
                # Mark as unvalidated but still process
                finding.is_exploitable = None  # Unknown
            
            flow, flow_evidence = self._create_exploit_flow_from_finding(finding)
            exploit_flows.append(flow)
        
        # If no exploit flows were created, create a default one with required evidence
        if not exploit_flows:
            logger.info("No findings provided, creating default exploit flow")
            default_location = LocationModel(
                locationType=LocationTypeEnum.GENERIC_RESOURCE_IDENTIFIER,
                description="No specific location identified"
            )
            
            # Create required evidence for default flow
            default_evidence = EvidenceModel(
                evidenceType=EvidenceTypeEnum.OTHER_EVIDENCE,
                description="No vulnerabilities found in this assessment",
                data=OtherEvidenceDataModel(
                    dataTypeDescription="Assessment result",
                    dataContent="Security assessment completed with no validated vulnerabilities found"
                ),
                validationMethod=ValidationMethodEnum.OTHER_VALIDATION_METHOD
            )
            
            default_flow = ExploitFlowModel(
                id=uuid.uuid4(),
                title="No Validated Vulnerabilities Found",
                description="No validated vulnerabilities found in this assessment",
                severity=SeverityModel(
                    level=SeverityLevelEnum.INFORMATIONAL,
                    justification="No exploitable vulnerabilities identified"
                ),
                category="Assessment Result",
                evidence=[default_evidence],  # Always include at least one evidence item
                validatedAt=datetime.datetime.now(datetime.UTC),
                source=default_location,
                sink=default_location,
                status=StatusEnum.FALSE_POSITIVE_AFTER_REVALIDATION
            )
            exploit_flows.append(default_flow)
        
        # Create VXDF document with the new structure
        vxdf_doc = VXDFModel(
            vxdfVersion="1.0.0",
            id=uuid.uuid4(),
            generatedAt=datetime.datetime.now(datetime.UTC),
            generatorTool=generator_info,
            applicationInfo=app_info,
            exploitFlows=exploit_flows
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
        # Create evidence items using comprehensive parsing
        evidence_items = []
        for evidence in finding.evidence:
            try:
                # Map evidence type to normative enum
                evidence_type = self._map_evidence_type(evidence.evidence_type)
                
                # Parse content into structured data model
                evidence_data = self._parse_evidence_content(evidence)
                
                # Determine validation method based on evidence type and finding source
                validation_method = ValidationMethodEnum.OTHER_VALIDATION_METHOD
                if finding.source_type in ["DAST-ZAP", "DAST-Burp", "DAST-Generic"]:
                    validation_method = ValidationMethodEnum.DYNAMIC_ANALYSIS_EXPLOIT
                elif finding.source_type in ["SAST", "CodeQL", "SonarQube"]:
                    validation_method = ValidationMethodEnum.STATIC_ANALYSIS_VALIDATION
                elif evidence.evidence_type.lower() in ["manual_verification", "manual"]:
                    validation_method = ValidationMethodEnum.MANUAL_PENETRATION_TESTING_EXPLOIT
                elif evidence.evidence_type.lower() in ["poc_script", "exploit"]:
                    validation_method = ValidationMethodEnum.AUTOMATED_EXPLOIT_TOOL_CONFIRMATION
                
                # Create normative EvidenceModel
                evidence_item = EvidenceModel(
                    evidenceType=evidence_type,
                    description=evidence.description or f"Evidence for {finding.name}",
                    data=evidence_data,
                    validationMethod=validation_method,
                    timestamp=evidence.created_at if hasattr(evidence, 'created_at') else None
                )
                evidence_items.append(evidence_item)
                
            except Exception as e:
                logger.error(f"Error processing evidence {evidence.id}: {e}", exc_info=True)
                # Create fallback evidence
                fallback_evidence = EvidenceModel(
                    evidenceType=EvidenceTypeEnum.OTHER_EVIDENCE,
                    description=evidence.description or f"Fallback evidence for {finding.name}",
                    data=OtherEvidenceDataModel(
                        dataTypeDescription="Error processing original evidence",
                        dataContent=str(evidence.content) if evidence.content else "No content"
                    ),
                    validationMethod=ValidationMethodEnum.OTHER_VALIDATION_METHOD
                )
                evidence_items.append(fallback_evidence)
        
        # If no evidence items were created, create a default one
        if not evidence_items:
            default_evidence = EvidenceModel(
                evidenceType=EvidenceTypeEnum.OTHER_EVIDENCE,
                description=f"Default evidence for {finding.name}",
                data=OtherEvidenceDataModel(
                    dataTypeDescription="No specific evidence available",
                    dataContent="Vulnerability identified through automated scanning"
                ),
                validationMethod=ValidationMethodEnum.AUTOMATED_EXPLOIT_TOOL_CONFIRMATION
            )
            evidence_items.append(default_evidence)
        
        # Create source location
        source_location = LocationModel(
            locationType=LocationTypeEnum.SOURCE_CODE_UNIT,
            filePath=finding.file_path or "Unknown",
            startLine=finding.line_number,
            startColumn=finding.column,
            description="Source location of the vulnerability"
        )
        
        # Create sink location (for now, same as source if no flow data available)
        sink_location = LocationModel(
            locationType=LocationTypeEnum.SOURCE_CODE_UNIT,
            filePath=finding.file_path or "Unknown", 
            startLine=finding.line_number,
            startColumn=finding.column,
            description="Sink location where vulnerability is triggered"
        )
        
        # Create trace steps (optional)
        trace_steps = []
        
        # Add source step
        source_step = TraceStepModel(
            order=0,
            location=source_location,
            description="Source of untrusted data",
            stepType=StepTypeEnum.SOURCE_INTERACTION,
            evidenceRefs={evidence.id for evidence in evidence_items} if evidence_items else set()
        )
        trace_steps.append(source_step)
        
        # Add sink step
        sink_step = TraceStepModel(
            order=1,
            location=sink_location,
            description="Sink where vulnerability is triggered",
            stepType=StepTypeEnum.SINK_INTERACTION,
            evidenceRefs={evidence.id for evidence in evidence_items} if evidence_items else set()
        )
        trace_steps.append(sink_step)
        
        # Create the exploit flow with comprehensive severity mapping
        severity_level = SeverityLevelEnum.MEDIUM  # Default
        if finding.severity:
            severity_mapping = {
                'CRITICAL': SeverityLevelEnum.CRITICAL,
                'HIGH': SeverityLevelEnum.HIGH,
                'MEDIUM': SeverityLevelEnum.MEDIUM,
                'LOW': SeverityLevelEnum.LOW,
                'INFORMATIONAL': SeverityLevelEnum.INFORMATIONAL,
                'INFO': SeverityLevelEnum.INFORMATIONAL,
                'NONE': SeverityLevelEnum.NONE
            }
            severity_level = severity_mapping.get(finding.severity.upper(), SeverityLevelEnum.MEDIUM)
        
        severity_model = SeverityModel(
            level=severity_level,
            justification=f"Severity determined from {finding.source_type} scan results"
        )
        
        # Map vulnerability type to category with better defaults
        category = finding.vulnerability_type or "Unknown"
        if category.lower() in ['sql_injection', 'sqli']:
            category = "SQL Injection"
        elif category.lower() in ['xss', 'cross_site_scripting']:
            category = "Cross-Site Scripting"
        elif category.lower() in ['path_traversal', 'directory_traversal']:
            category = "Path Traversal"
        elif category.lower() in ['command_injection', 'code_injection']:
            category = "Command Injection"
        
        flow = ExploitFlowModel(
            id=uuid.uuid4(),
            title=finding.name or "Unnamed Vulnerability",
            description=finding.description or f"Exploit flow for {finding.name}",
            severity=severity_model,
            category=category,
            evidence=evidence_items,
            validatedAt=datetime.datetime.now(datetime.UTC),
            source=source_location,
            sink=sink_location,
            trace=trace_steps,
            status=StatusEnum.OPEN if finding.is_exploitable else StatusEnum.FALSE_POSITIVE_AFTER_REVALIDATION,
            cwes=set(),
            tags=set(),
            owaspTopTenCategories=set(),
            references=set()
        )
        
        return flow, evidence_items
    
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
