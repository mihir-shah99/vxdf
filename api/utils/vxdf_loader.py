#!/usr/bin/env python3
"""
VXDF Loader Module

This module provides functionality to parse, validate, and load VXDF documents
into the normative Pydantic models while ensuring compliance with the authoritative schema.

Main Functions:
- load_and_validate_vxdf: Parse and validate a VXDF file
- get_vxdf_summary: Generate a summary of a VXDF document
- validate_against_schema: Validate against JSON schema
"""

import json
import logging
from pathlib import Path
from typing import Tuple, List, Optional, Dict, Any
from datetime import datetime

try:
    import jsonschema
    from jsonschema import ValidationError as JsonSchemaValidationError
except ImportError:
    raise ImportError("jsonschema library is required. Install with: pip install jsonschema")

from pydantic import ValidationError as PydanticValidationError

# Import the normative VXDF models
from api.models.vxdf import VXDFModel, ExploitFlowModel, EvidenceModel

logger = logging.getLogger(__name__)

class VXDFLoaderError(Exception):
    """Base exception for VXDF loader errors."""
    pass

class VXDFParsingError(VXDFLoaderError):
    """Raised when VXDF parsing fails."""
    pass

class VXDFValidationError(VXDFLoaderError):
    """Raised when VXDF validation fails."""
    pass

def load_and_validate_vxdf(file_path: str) -> Tuple[Optional[VXDFModel], List[str]]:
    """
    Load and validate a VXDF file against both Pydantic models and JSON schema.
    
    Args:
        file_path: Path to the .vxdf.json file
        
    Returns:
        Tuple of (parsed VXDFModel or None, list of error messages)
        If successful, returns (VXDFModel instance, [])
        If failed, returns (None, [error1, error2, ...])
    """
    errors = []
    vxdf_model = None
    
    try:
        # Step 1: Read and parse JSON file
        file_path_obj = Path(file_path)
        
        if not file_path_obj.exists():
            errors.append(f"File not found: {file_path}")
            return None, errors
        
        if not file_path_obj.suffix.lower().endswith('.json'):
            errors.append(f"File must have .json extension: {file_path}")
            return None, errors
        
        try:
            with open(file_path_obj, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON format: {e}")
            return None, errors
        except Exception as e:
            errors.append(f"Error reading file: {e}")
            return None, errors
        
        # Step 2: Validate against JSON schema first
        schema_errors = validate_against_schema(raw_data)
        if schema_errors:
            errors.extend([f"Schema validation: {err}" for err in schema_errors])
            # Continue with Pydantic validation anyway to get additional insights
        
        # Step 3: Parse into Pydantic model
        try:
            vxdf_model = VXDFModel.model_validate(raw_data)
        except PydanticValidationError as e:
            pydantic_errors = format_pydantic_errors(e)
            errors.extend([f"Pydantic validation: {err}" for err in pydantic_errors])
            return None, errors
        except Exception as e:
            errors.append(f"Unexpected Pydantic parsing error: {e}")
            return None, errors
        
        # Step 4: Additional consistency checks
        consistency_errors = perform_consistency_checks(vxdf_model)
        if consistency_errors:
            errors.extend([f"Consistency check: {err}" for err in consistency_errors])
        
        # If we have any errors, return failure
        if errors:
            return None, errors
        
        logger.info(f"Successfully loaded and validated VXDF file: {file_path}")
        return vxdf_model, []
        
    except Exception as e:
        errors.append(f"Unexpected error during VXDF loading: {e}")
        return None, errors

def validate_against_schema(data: Dict[str, Any]) -> List[str]:
    """
    Validate VXDF data against the authoritative JSON schema.
    
    Args:
        data: The JSON data to validate
        
    Returns:
        List of validation error messages (empty if valid)
    """
    errors = []
    
    try:
        # Load the normative schema
        schema_path = Path(__file__).parent.parent.parent / "docs" / "normative-schema.json"
        
        if not schema_path.exists():
            errors.append(f"Normative schema not found at: {schema_path}")
            return errors
        
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema = json.load(f)
        
        # Validate against schema
        try:
            jsonschema.validate(data, schema)
        except JsonSchemaValidationError as e:
            errors.append(format_jsonschema_error(e))
        except jsonschema.SchemaError as e:
            errors.append(f"Invalid schema file: {e}")
        
    except Exception as e:
        errors.append(f"Schema validation error: {e}")
    
    return errors

def format_jsonschema_error(error: JsonSchemaValidationError) -> str:
    """
    Format a JSON schema validation error into a human-readable message.
    
    Args:
        error: The ValidationError from jsonschema
        
    Returns:
        Formatted error message
    """
    path = " -> ".join(str(p) for p in error.absolute_path) if error.absolute_path else "(root)"
    
    # Get the specific value that failed validation
    failed_value = error.instance
    if isinstance(failed_value, (dict, list)) and len(str(failed_value)) > 100:
        failed_value = f"{type(failed_value).__name__} with {len(failed_value)} items"
    
    return f"At {path}: {error.message} (failed value: {failed_value})"

def format_pydantic_errors(error: PydanticValidationError) -> List[str]:
    """
    Format Pydantic validation errors into human-readable messages.
    
    Args:
        error: The ValidationError from Pydantic
        
    Returns:
        List of formatted error messages
    """
    errors = []
    
    for err in error.errors():
        location = " -> ".join(str(loc) for loc in err['loc']) if err['loc'] else "(root)"
        message = err['msg']
        error_type = err['type']
        
        # Add context for common error types
        if error_type == 'missing':
            message = f"Required field is missing: {message}"
        elif error_type == 'extra_forbidden':
            message = f"Extra field not allowed: {message}"
        elif error_type == 'value_error':
            message = f"Invalid value: {message}"
        
        errors.append(f"At {location}: {message}")
    
    return errors

def perform_consistency_checks(vxdf_model: VXDFModel) -> List[str]:
    """
    Perform additional consistency checks on the parsed VXDF model.
    
    Args:
        vxdf_model: The parsed VXDF model
        
    Returns:
        List of consistency error messages
    """
    errors = []
    
    try:
        # Check 1: Ensure all exploit flows have evidence
        for i, flow in enumerate(vxdf_model.exploitFlows):
            if not flow.evidence or len(flow.evidence) == 0:
                errors.append(f"Exploit flow {i} ({flow.title}) has no evidence")
        
        # Check 2: Validate evidence references in trace steps
        for i, flow in enumerate(vxdf_model.exploitFlows):
            if flow.trace:
                evidence_ids = {ev.id for ev in flow.evidence}
                for j, step in enumerate(flow.trace):
                    if step.evidenceRefs:
                        invalid_refs = step.evidenceRefs - evidence_ids
                        if invalid_refs:
                            errors.append(f"Exploit flow {i}, trace step {j} references non-existent evidence IDs: {invalid_refs}")
        
        # Check 3: Validate anyOf constraint for ExploitFlow locus (source/sink OR affectedComponents)
        for i, flow in enumerate(vxdf_model.exploitFlows):
            has_source_sink = flow.source is not None and flow.sink is not None
            has_affected_components = flow.affectedComponents and len(flow.affectedComponents) > 0
            
            if not (has_source_sink or has_affected_components):
                errors.append(f"Exploit flow {i} ({flow.title}) must have either (source AND sink) OR affectedComponents")
        
        # Check 4: Validate VXDF version
        if vxdf_model.vxdfVersion != "1.0.0":
            errors.append(f"Unsupported VXDF version: {vxdf_model.vxdfVersion}")
        
    except Exception as e:
        errors.append(f"Error during consistency checks: {e}")
    
    return errors

def get_vxdf_summary(vxdf_model: VXDFModel, verbose: bool = False) -> Dict[str, Any]:
    """
    Generate a summary of the VXDF document.
    
    Args:
        vxdf_model: The parsed VXDF model
        verbose: Whether to include detailed information
        
    Returns:
        Dictionary containing summary information
    """
    summary = {
        "document_id": str(vxdf_model.id),
        "vxdf_version": vxdf_model.vxdfVersion,
        "generated_at": vxdf_model.generatedAt.isoformat() if vxdf_model.generatedAt else None,
        "generator_tool": None,
        "application_info": None,
        "exploit_flows_count": len(vxdf_model.exploitFlows),
        "exploit_flows": [],
        "total_evidence_count": 0
    }
    
    # Generator tool information
    if vxdf_model.generatorTool:
        summary["generator_tool"] = {
            "name": vxdf_model.generatorTool.name,
            "version": getattr(vxdf_model.generatorTool, 'version', None)
        }
    
    # Application information
    if vxdf_model.applicationInfo:
        summary["application_info"] = {
            "name": vxdf_model.applicationInfo.name,
            "version": getattr(vxdf_model.applicationInfo, 'version', None)
        }
    
    # Exploit flows summary
    total_evidence = 0
    for flow in vxdf_model.exploitFlows:
        flow_summary = {
            "id": str(flow.id),
            "title": flow.title,
            "category": flow.category,
            "severity": flow.severity.level.value if flow.severity else "Unknown",
            "evidence_count": len(flow.evidence) if flow.evidence else 0,
            "status": flow.status.value if flow.status else "Unknown",
            "validated_at": flow.validatedAt.isoformat() if flow.validatedAt else None
        }
        
        if verbose:
            flow_summary.update({
                "description": flow.description,
                "discovery_date": flow.discoveryDate.isoformat() if flow.discoveryDate else None,
                "disclosure_date": flow.disclosureDate.isoformat() if flow.disclosureDate else None,
                "cwes": list(flow.cwes) if flow.cwes else [],
                "tags": list(flow.tags) if flow.tags else [],
                "has_source_sink": flow.source is not None and flow.sink is not None,
                "has_affected_components": bool(flow.affectedComponents and len(flow.affectedComponents) > 0),
                "trace_steps_count": len(flow.trace) if flow.trace else 0
            })
            
            # Evidence details
            if flow.evidence:
                flow_summary["evidence_details"] = [
                    {
                        "type": ev.evidenceType.value,
                        "description": ev.description,
                        "validation_method": ev.validationMethod.value if ev.validationMethod else None
                    }
                    for ev in flow.evidence
                ]
        
        summary["exploit_flows"].append(flow_summary)
        total_evidence += flow_summary["evidence_count"]
    
    summary["total_evidence_count"] = total_evidence
    
    return summary

def print_vxdf_summary(summary: Dict[str, Any], verbose: bool = False) -> None:
    """
    Print a formatted VXDF summary to stdout.
    
    Args:
        summary: Summary dictionary from get_vxdf_summary
        verbose: Whether to print detailed information
    """
    print(f"\n{'='*60}")
    print(f"VXDF DOCUMENT SUMMARY")
    print(f"{'='*60}")
    
    print(f"📄 Document ID: {summary['document_id']}")
    print(f"📋 VXDF Version: {summary['vxdf_version']}")
    print(f"🕒 Generated At: {summary['generated_at'] or 'Unknown'}")
    
    if summary['generator_tool']:
        tool = summary['generator_tool']
        version = f" v{tool['version']}" if tool['version'] else ""
        print(f"🔧 Generator Tool: {tool['name']}{version}")
    
    if summary['application_info']:
        app = summary['application_info']
        version = f" v{app['version']}" if app['version'] else ""
        print(f"🎯 Target Application: {app['name']}{version}")
    
    print(f"\n📊 EXPLOIT FLOWS: {summary['exploit_flows_count']}")
    print(f"📋 TOTAL EVIDENCE: {summary['total_evidence_count']}")
    
    if summary['exploit_flows']:
        print(f"\n🔍 EXPLOIT FLOW DETAILS:")
        for i, flow in enumerate(summary['exploit_flows'], 1):
            print(f"\n  {i}. {flow['title']}")
            print(f"     🆔 ID: {flow['id']}")
            print(f"     📂 Category: {flow['category']}")
            print(f"     ⚠️  Severity: {flow['severity']}")
            print(f"     📋 Evidence: {flow['evidence_count']} item(s)")
            print(f"     📅 Status: {flow['status']}")
            
            if verbose:
                if flow.get('description'):
                    print(f"     📝 Description: {flow['description']}")
                
                if flow.get('cwes'):
                    print(f"     🔍 CWEs: {', '.join(map(str, flow['cwes']))}")
                
                if flow.get('tags'):
                    print(f"     🏷️  Tags: {', '.join(flow['tags'])}")
                
                print(f"     🎯 Has Source/Sink: {flow.get('has_source_sink', False)}")
                print(f"     🔗 Has Affected Components: {flow.get('has_affected_components', False)}")
                
                if flow.get('trace_steps_count', 0) > 0:
                    print(f"     📍 Trace Steps: {flow['trace_steps_count']}")
                
                if flow.get('evidence_details'):
                    print(f"     📋 Evidence Details:")
                    for j, ev in enumerate(flow['evidence_details'], 1):
                        method = f" ({ev['validation_method']})" if ev['validation_method'] else ""
                        print(f"       {j}. {ev['type']}: {ev['description']}{method}")
    
    print(f"\n{'='*60}") 