"""
Evidence ingestion utilities for the VXDF engine.

This module provides functionality to process external evidence submissions,
both as structured JSON data and individual file uploads, and link them
to existing findings using various matching strategies.
"""

import json
import base64
import re
import mimetypes
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, Tuple
from datetime import datetime

from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.models.finding import Finding, Evidence
from api.models.vxdf import (
    EvidenceTypeEnum, ValidationMethodEnum,
    HttpRequestLogDataModel, HttpResponseLogDataModel, CodeSnippetDataModel,
    PocScriptDataModel, RuntimeLogEntryDataModel, DebuggerOutputDataModel,
    ExceptionTraceDataModel, ScreenshotUrlDataModel, ScreenshotEmbeddedDataModel,
    TestPayloadDataModel, ManualVerificationDataModel, EnvironmentConfigDataModel,
    NetworkCaptureSummaryDataModel, StaticAnalysisPathDataModel, 
    StaticAnalysisGraphDataModel, ConfigFileSnippetDataModel, ScaOutputDataModel,
    MissingArtifactDataModel, ObservedBehaviorDataModel, DbStateChangeDataModel,
    FsChangeDataModel, CommandExecutionOutputDataModel, ExfiltratedDataSampleDataModel,
    SessionInfoLeakDataModel, DifferentialAnalysisDataModel, ToolSpecificOutputDataModel,
    ExternalInteractionProofDataModel, OtherEvidenceDataModel,
    HttpMethodEnum, ImageFormatEnum, PayloadEncodingEnum, HttpHeaderModel
)


class FindingMatcher:
    """Handles matching of external evidence to existing findings."""
    
    @staticmethod
    def match_finding(finding_matcher: Dict[str, Any], findings: List[Finding]) -> List[Finding]:
        """
        Match evidence to findings based on the provided matcher criteria.
        
        Args:
            finding_matcher: Dictionary containing matching criteria
            findings: List of Finding objects to match against
            
        Returns:
            List of matched Finding objects
        """
        matched_findings = []
        
        # Handle apply_to_all matcher
        if finding_matcher.get("apply_to_all", False):
            return findings
            
        # Handle rule_id_match
        if "rule_id_match" in finding_matcher:
            rule_id = finding_matcher["rule_id_match"]
            for finding in findings:
                if (finding.source_id and finding.source_id == rule_id) or \
                   (finding.raw_data and finding.raw_data.get("ruleId") == rule_id):
                    matched_findings.append(finding)
        
        # Handle cwe_match
        if "cwe_match" in finding_matcher:
            cwe_id = str(finding_matcher["cwe_match"])
            for finding in findings:
                if finding.cwe_id and (finding.cwe_id == cwe_id or finding.cwe_id == f"CWE-{cwe_id}"):
                    matched_findings.append(finding)
        
        # Handle name_pattern_match
        if "name_pattern_match" in finding_matcher:
            pattern = finding_matcher["name_pattern_match"]
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for finding in findings:
                    if finding.name and regex.search(finding.name):
                        matched_findings.append(finding)
            except re.error:
                # Fallback to substring match if regex is invalid
                for finding in findings:
                    if finding.name and pattern.lower() in finding.name.lower():
                        matched_findings.append(finding)
        
        # Handle location_match
        if "location_match" in finding_matcher:
            location = finding_matcher["location_match"]
            file_path = location.get("filePath")
            start_line = location.get("startLine")
            
            for finding in findings:
                if file_path and finding.file_path:
                    if finding.file_path == file_path or finding.file_path.endswith(file_path):
                        if start_line is None or finding.line_number == start_line:
                            matched_findings.append(finding)
        
        # Remove duplicates
        return list(set(matched_findings))


class EvidenceProcessor:
    """Processes different types of evidence data into normalized Pydantic models."""
    
    @staticmethod
    def validate_evidence_type(evidence_type_str: str) -> EvidenceTypeEnum:
        """Validate and convert evidence type string to enum."""
        try:
            return EvidenceTypeEnum(evidence_type_str)
        except ValueError:
            raise ValueError(f"Invalid evidence type: {evidence_type_str}")
    
    @staticmethod
    def validate_validation_method(validation_method_str: str) -> ValidationMethodEnum:
        """Validate and convert validation method string to enum."""
        try:
            return ValidationMethodEnum(validation_method_str)
        except ValueError:
            raise ValueError(f"Invalid validation method: {validation_method_str}")
    
    @staticmethod
    def process_structured_evidence_data(evidence_type: EvidenceTypeEnum, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process structured evidence data and validate it against the appropriate Pydantic model.
        
        Args:
            evidence_type: The type of evidence
            data: Raw evidence data dictionary
            
        Returns:
            Validated and serialized evidence data
        """
        try:
            # Map evidence types to their corresponding Pydantic models
            model_mapping = {
                EvidenceTypeEnum.HTTP_REQUEST_LOG: HttpRequestLogDataModel,
                EvidenceTypeEnum.HTTP_RESPONSE_LOG: HttpResponseLogDataModel,
                EvidenceTypeEnum.CODE_SNIPPET_SOURCE: CodeSnippetDataModel,
                EvidenceTypeEnum.CODE_SNIPPET_SINK: CodeSnippetDataModel,
                EvidenceTypeEnum.CODE_SNIPPET_CONTEXT: CodeSnippetDataModel,
                EvidenceTypeEnum.POC_SCRIPT: PocScriptDataModel,
                EvidenceTypeEnum.RUNTIME_APPLICATION_LOG_ENTRY: RuntimeLogEntryDataModel,
                EvidenceTypeEnum.RUNTIME_SYSTEM_LOG_ENTRY: RuntimeLogEntryDataModel,
                EvidenceTypeEnum.RUNTIME_WEB_SERVER_LOG_ENTRY: RuntimeLogEntryDataModel,
                EvidenceTypeEnum.RUNTIME_DATABASE_LOG_ENTRY: RuntimeLogEntryDataModel,
                EvidenceTypeEnum.RUNTIME_DEBUGGER_OUTPUT: DebuggerOutputDataModel,
                EvidenceTypeEnum.RUNTIME_EXCEPTION_TRACE: ExceptionTraceDataModel,
                EvidenceTypeEnum.SCREENSHOT_URL: ScreenshotUrlDataModel,
                EvidenceTypeEnum.SCREENSHOT_EMBEDDED_BASE64: ScreenshotEmbeddedDataModel,
                EvidenceTypeEnum.MANUAL_VERIFICATION_NOTES: ManualVerificationDataModel,
                EvidenceTypeEnum.TEST_PAYLOAD_USED: TestPayloadDataModel,
                EvidenceTypeEnum.ENVIRONMENT_CONFIGURATION_DETAILS: EnvironmentConfigDataModel,
                EvidenceTypeEnum.NETWORK_TRAFFIC_CAPTURE_SUMMARY: NetworkCaptureSummaryDataModel,
                EvidenceTypeEnum.STATIC_ANALYSIS_DATA_FLOW_PATH: StaticAnalysisPathDataModel,
                EvidenceTypeEnum.STATIC_ANALYSIS_CONTROL_FLOW_GRAPH: StaticAnalysisGraphDataModel,
                EvidenceTypeEnum.CONFIGURATION_FILE_SNIPPET: ConfigFileSnippetDataModel,
                EvidenceTypeEnum.VULNERABLE_COMPONENT_SCAN_OUTPUT: ScaOutputDataModel,
                EvidenceTypeEnum.MISSING_ARTIFACT_VERIFICATION: MissingArtifactDataModel,
                EvidenceTypeEnum.OBSERVED_BEHAVIORAL_CHANGE: ObservedBehaviorDataModel,
                EvidenceTypeEnum.DATABASE_STATE_CHANGE_PROOF: DbStateChangeDataModel,
                EvidenceTypeEnum.FILE_SYSTEM_CHANGE_PROOF: FsChangeDataModel,
                EvidenceTypeEnum.COMMAND_EXECUTION_OUTPUT: CommandExecutionOutputDataModel,
                EvidenceTypeEnum.EXFILTRATED_DATA_SAMPLE: ExfiltratedDataSampleDataModel,
                EvidenceTypeEnum.SESSION_INFORMATION_LEAK: SessionInfoLeakDataModel,
                EvidenceTypeEnum.DIFFERENTIAL_ANALYSIS_RESULT: DifferentialAnalysisDataModel,
                EvidenceTypeEnum.TOOL_SPECIFIC_OUTPUT_LOG: ToolSpecificOutputDataModel,
                EvidenceTypeEnum.EXTERNAL_INTERACTION_PROOF: ExternalInteractionProofDataModel,
                EvidenceTypeEnum.OTHER_EVIDENCE: OtherEvidenceDataModel,
            }
            
            model_class = model_mapping.get(evidence_type)
            if not model_class:
                raise ValueError(f"No model mapping found for evidence type: {evidence_type}")
            
            # Validate data against the model
            validated_model = model_class(**data)
            
            # Return serialized data
            return validated_model.model_dump()
            
        except ValidationError as e:
            raise ValueError(f"Evidence data validation failed for type {evidence_type}: {e}")
    
    @staticmethod
    def process_file_content(evidence_type: EvidenceTypeEnum, file_content: bytes, 
                           file_name: str, content_type: str, 
                           additional_params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process uploaded file content based on evidence type.
        
        Args:
            evidence_type: The type of evidence
            file_content: Raw file content as bytes
            file_name: Original filename
            content_type: MIME content type
            additional_params: Additional parameters from form data
            
        Returns:
            Processed evidence data dictionary
        """
        additional_params = additional_params or {}
        
        # Handle text-based evidence types
        text_based_types = {
            EvidenceTypeEnum.RUNTIME_APPLICATION_LOG_ENTRY,
            EvidenceTypeEnum.RUNTIME_SYSTEM_LOG_ENTRY,
            EvidenceTypeEnum.RUNTIME_WEB_SERVER_LOG_ENTRY,
            EvidenceTypeEnum.RUNTIME_DATABASE_LOG_ENTRY,
            EvidenceTypeEnum.CODE_SNIPPET_SOURCE,
            EvidenceTypeEnum.CODE_SNIPPET_SINK,
            EvidenceTypeEnum.CODE_SNIPPET_CONTEXT,
            EvidenceTypeEnum.POC_SCRIPT,
            EvidenceTypeEnum.CONFIGURATION_FILE_SNIPPET,
            EvidenceTypeEnum.COMMAND_EXECUTION_OUTPUT,
            EvidenceTypeEnum.TOOL_SPECIFIC_OUTPUT_LOG,
        }
        
        if evidence_type in text_based_types:
            try:
                text_content = file_content.decode('utf-8')
            except UnicodeDecodeError:
                text_content = file_content.decode('utf-8', errors='replace')
            
            return EvidenceProcessor._process_text_evidence(evidence_type, text_content, 
                                                          file_name, additional_params)
        
        # Handle image-based evidence types
        elif evidence_type == EvidenceTypeEnum.SCREENSHOT_EMBEDDED_BASE64:
            return EvidenceProcessor._process_image_evidence(file_content, file_name, 
                                                           content_type, additional_params)
        
        # Handle other file types - store as OtherEvidenceDataModel
        else:
            return EvidenceProcessor._process_other_evidence(file_content, file_name, 
                                                           content_type, additional_params)
    
    @staticmethod
    def _process_text_evidence(evidence_type: EvidenceTypeEnum, text_content: str, 
                             file_name: str, additional_params: Dict[str, Any]) -> Dict[str, Any]:
        """Process text-based evidence files."""
        if evidence_type in {EvidenceTypeEnum.RUNTIME_APPLICATION_LOG_ENTRY,
                           EvidenceTypeEnum.RUNTIME_SYSTEM_LOG_ENTRY,
                           EvidenceTypeEnum.RUNTIME_WEB_SERVER_LOG_ENTRY,
                           EvidenceTypeEnum.RUNTIME_DATABASE_LOG_ENTRY}:
            return {
                "message": text_content,
                "logSourceIdentifier": additional_params.get("log_source", file_name),
                "logLevel": additional_params.get("log_level"),
                "componentName": additional_params.get("component_name"),
            }
        
        elif evidence_type in {EvidenceTypeEnum.CODE_SNIPPET_SOURCE,
                             EvidenceTypeEnum.CODE_SNIPPET_SINK,
                             EvidenceTypeEnum.CODE_SNIPPET_CONTEXT}:
            return {
                "content": text_content,
                "language": additional_params.get("language", EvidenceProcessor._guess_language(file_name)),
                "filePath": additional_params.get("file_path", file_name),
                "startLine": additional_params.get("start_line"),
                "endLine": additional_params.get("end_line"),
            }
        
        elif evidence_type == EvidenceTypeEnum.POC_SCRIPT:
            return {
                "scriptLanguage": additional_params.get("script_language", EvidenceProcessor._guess_language(file_name)),
                "scriptContent": text_content,
                "scriptArguments": additional_params.get("script_arguments", []),
                "expectedOutcome": additional_params.get("expected_outcome"),
            }
        
        elif evidence_type == EvidenceTypeEnum.CONFIGURATION_FILE_SNIPPET:
            return {
                "filePath": additional_params.get("file_path", file_name),
                "snippet": text_content,
                "settingName": additional_params.get("setting_name"),
                "interpretation": additional_params.get("interpretation"),
            }
        
        elif evidence_type == EvidenceTypeEnum.COMMAND_EXECUTION_OUTPUT:
            return {
                "command": additional_params.get("command", ""),
                "output": text_content,
                "exitCode": additional_params.get("exit_code"),
                "executionContext": additional_params.get("execution_context"),
            }
        
        elif evidence_type == EvidenceTypeEnum.TOOL_SPECIFIC_OUTPUT_LOG:
            return {
                "toolName": additional_params.get("tool_name", ""),
                "relevantLogSectionOrOutput": text_content,
                "toolVersion": additional_params.get("tool_version"),
                "commandLineExecuted": additional_params.get("command_line"),
                "interpretationOfOutput": additional_params.get("interpretation"),
            }
        
        else:
            # Fallback to OtherEvidenceDataModel
            return {
                "dataTypeDescription": f"Text file: {file_name}",
                "dataContent": text_content,
                "encodingFormat": "plaintext",
            }
    
    @staticmethod
    def _process_image_evidence(file_content: bytes, file_name: str, 
                              content_type: str, additional_params: Dict[str, Any]) -> Dict[str, Any]:
        """Process image files for screenshot evidence."""
        # Base64 encode the image
        image_base64 = base64.b64encode(file_content).decode('utf-8')
        
        # Determine image format
        image_format = EvidenceProcessor._get_image_format(file_name, content_type)
        
        return {
            "imageDataBase64": image_base64,
            "imageFormat": image_format,
            "caption": additional_params.get("caption"),
        }
    
    @staticmethod
    def _process_other_evidence(file_content: bytes, file_name: str, 
                              content_type: str, additional_params: Dict[str, Any]) -> Dict[str, Any]:
        """Process other file types as generic evidence."""
        # Try to decode as text first
        try:
            text_content = file_content.decode('utf-8')
            encoding_format = "plaintext"
            data_content = text_content
        except UnicodeDecodeError:
            # If not text, base64 encode
            data_content = base64.b64encode(file_content).decode('utf-8')
            encoding_format = "base64"
        
        return {
            "dataTypeDescription": additional_params.get("data_type_description", f"File: {file_name} ({content_type})"),
            "dataContent": data_content,
            "encodingFormat": encoding_format,
        }
    
    @staticmethod
    def _guess_language(file_name: str) -> Optional[str]:
        """Guess programming language from file extension."""
        ext = Path(file_name).suffix.lower()
        language_mapping = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.h': 'c',
            '.hpp': 'cpp',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.rs': 'rust',
            '.sh': 'bash',
            '.ps1': 'powershell',
            '.sql': 'sql',
            '.html': 'html',
            '.css': 'css',
            '.xml': 'xml',
            '.json': 'json',
            '.yaml': 'yaml',
            '.yml': 'yaml',
        }
        return language_mapping.get(ext)
    
    @staticmethod
    def _get_image_format(file_name: str, content_type: str) -> ImageFormatEnum:
        """Determine image format from filename or content type."""
        # Try content type first
        if content_type:
            if 'png' in content_type.lower():
                return ImageFormatEnum.PNG
            elif 'jpeg' in content_type.lower() or 'jpg' in content_type.lower():
                return ImageFormatEnum.JPEG
            elif 'gif' in content_type.lower():
                return ImageFormatEnum.GIF
            elif 'bmp' in content_type.lower():
                return ImageFormatEnum.BMP
            elif 'webp' in content_type.lower():
                return ImageFormatEnum.WEBP
        
        # Fallback to file extension
        ext = Path(file_name).suffix.lower()
        format_mapping = {
            '.png': ImageFormatEnum.PNG,
            '.jpg': ImageFormatEnum.JPEG,
            '.jpeg': ImageFormatEnum.JPEG,
            '.gif': ImageFormatEnum.GIF,
            '.bmp': ImageFormatEnum.BMP,
            '.webp': ImageFormatEnum.WEBP,
        }
        return format_mapping.get(ext, ImageFormatEnum.PNG)  # Default to PNG


def create_evidence_from_structured_data(finding: Finding, evidence_data: Dict[str, Any], 
                                       db_session: Session) -> Evidence:
    """
    Create a new Evidence record from structured evidence data.
    
    Args:
        finding: The Finding to associate the evidence with
        evidence_data: Dictionary containing evidence information
        db_session: Database session
        
    Returns:
        Created Evidence object
    """
    # Validate required fields
    if not evidence_data.get("evidenceType"):
        raise ValueError("evidenceType is required")
    if not evidence_data.get("description"):
        raise ValueError("description is required")
    if not evidence_data.get("data"):
        raise ValueError("data is required")
    
    # Validate evidence type
    evidence_type = EvidenceProcessor.validate_evidence_type(evidence_data["evidenceType"])
    
    # Process and validate evidence data
    processed_data = EvidenceProcessor.process_structured_evidence_data(
        evidence_type, evidence_data["data"]
    )
    
    # Create Evidence record
    evidence = Evidence(
        finding_id=finding.id,
        evidence_type=evidence_data["evidenceType"],
        description=evidence_data["description"],
        content=json.dumps(processed_data)
    )
    
    db_session.add(evidence)
    return evidence


def create_evidence_from_file_upload(finding: Finding, file_content: bytes, file_name: str,
                                   evidence_type_str: str, description: str,
                                   validation_method_str: Optional[str] = None,
                                   timestamp_str: Optional[str] = None,
                                   additional_params: Dict[str, Any] = None,
                                   db_session: Session = None) -> Evidence:
    """
    Create a new Evidence record from file upload.
    
    Args:
        finding: The Finding to associate the evidence with
        file_content: Raw file content as bytes
        file_name: Original filename
        evidence_type_str: Evidence type as string
        description: Evidence description
        validation_method_str: Optional validation method
        timestamp_str: Optional timestamp as ISO string
        additional_params: Additional parameters for processing
        db_session: Database session
        
    Returns:
        Created Evidence object
    """
    # Validate evidence type
    evidence_type = EvidenceProcessor.validate_evidence_type(evidence_type_str)
    
    # Guess content type
    content_type, _ = mimetypes.guess_type(file_name)
    content_type = content_type or 'application/octet-stream'
    
    # Process file content
    processed_data = EvidenceProcessor.process_file_content(
        evidence_type, file_content, file_name, content_type, additional_params
    )
    
    # Create Evidence record
    evidence = Evidence(
        finding_id=finding.id,
        evidence_type=evidence_type_str,
        description=description,
        content=json.dumps(processed_data)
    )
    
    if db_session:
        db_session.add(evidence)
    
    return evidence 