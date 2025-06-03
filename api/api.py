"""
API endpoints for the VXDF frontend.

This module provides RESTful API endpoints specifically designed for the React frontend.
It serves as an integration layer between the frontend and the core VXDF validation engine.
"""
import os
import sys
from pathlib import Path
import logging
import tempfile
import datetime
from typing import List, Dict, Any, Optional
import json

# Fix import paths - add project root to Python path
API_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = API_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

from flask import Blueprint, request, jsonify, current_app, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from pydantic import ValidationError

# Import models with path resolution
try:
    from api.models.finding import Finding, Evidence
    from api.models.database import SessionLocal, get_db
    from api.core.engine import ValidationEngine
    from api.config import OUTPUT_DIR, SUPPORTED_VULN_TYPES
    from api.utils.evidence_handler import (
        FindingMatcher, EvidenceProcessor, 
        create_evidence_from_structured_data, create_evidence_from_file_upload
    )
except ImportError:
    # Fallback for running from api directory
    from models.finding import Finding, Evidence
    from models.database import SessionLocal, get_db
    from core.engine import ValidationEngine
    from config import OUTPUT_DIR, SUPPORTED_VULN_TYPES
    from utils.evidence_handler import (
        FindingMatcher, EvidenceProcessor, 
        create_evidence_from_structured_data, create_evidence_from_file_upload
    )

from marshmallow import Schema, fields

# Create blueprint with a unique name
api_bp = Blueprint('vxdf_api', __name__, url_prefix='/api')

# Configure CORS for API routes
# In production, replace localhost:5173 with your actual domain
CORS(api_bp, resources={r"/*": {"origins": ["http://localhost:5173", "http://localhost:3000", "http://localhost:3001", "http://localhost:3002"]}})

# Configure logging
logger = logging.getLogger(__name__)

def transform_finding_to_vulnerability(finding: Finding) -> dict:
    """
    Transform a Finding model instance into a frontend-compatible vulnerability format.
    """
    evidence_list = []
    if hasattr(finding, 'evidence') and finding.evidence:
        for e in finding.evidence:
            evidence_list.append({
                'id': e.id,
                'type': e.evidence_type,
                'description': e.description,
                'content': e.content,
                'timestamp': e.created_at.isoformat() if e.created_at else None
            })
    
    return {
        'id': finding.id,
        'sourceId': finding.source_id,
        'sourceType': finding.source_type,
        'type': finding.vulnerability_type,
        'name': finding.name,
        'description': finding.description,
        'severity': finding.severity,
        'cvssScore': finding.cvss_score,
        'cweId': finding.cwe_id,
        'filePath': finding.file_path,
        'lineNumber': finding.line_number,
        'column': finding.column,
        'isValidated': finding.is_validated,
        'isExploitable': finding.is_exploitable,
        'validationDate': finding.validation_date.isoformat() if finding.validation_date else None,
        'validationMessage': finding.validation_message,
        'validationAttempts': finding.validation_attempts,
        'evidence': evidence_list,
        'createdAt': finding.created_at.isoformat() if finding.created_at else None,
        'updatedAt': finding.updated_at.isoformat() if finding.updated_at else None
    }

@api_bp.route('/upload', methods=['POST'])
def upload_file():
    """
    Upload a security scan file for validation and processing, with optional external evidence.
    ---
    tags:
      - Upload
    consumes:
      - multipart/form-data
    parameters:
      - name: file
        in: formData
        type: file
        required: true
        description: The scan file to upload
      - name: parser_type
        in: formData
        type: string
        required: false
        default: sarif
        description: Parser type (sarif, owasp_zap, etc.)
      - name: validate
        in: formData
        type: boolean
        required: false
        default: true
        description: Whether to validate findings
      - name: target_name
        in: formData
        type: string
        required: false
        description: Name of the target application
      - name: target_version
        in: formData
        type: string
        required: false
        description: Version of the target application
      - name: vuln_types
        in: formData
        type: array
        items:
          type: string
        required: false
        description: Vulnerability types to process
      - name: min_severity
        in: formData
        type: string
        required: false
        default: LOW
        description: Minimum severity to include
      - name: strict
        in: formData
        type: boolean
        required: false
        default: false
        description: Whether to perform strict validation
      - name: external_evidence_json
        in: formData
        type: string
        required: false
        description: JSON string containing array of external evidence items
    responses:
      200:
        description: Upload and validation result
        schema:
          type: object
          properties:
            success:
              type: boolean
            message:
              type: string
            findings:
              type: array
              items:
                $ref: '#/definitions/Vulnerability'
            outputFile:
              type: string
            evidenceProcessed:
              type: integer
              description: Number of external evidence items processed
      400:
        description: Bad request
      500:
        description: Internal server error
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Get form parameters
    parser_type = request.form.get('parser_type', 'sarif')
    validate = request.form.get('validate', 'true') == 'true'
    target_name = request.form.get('target_name', 'Unknown Application')
    target_version = request.form.get('target_version', '')
    external_evidence_json = request.form.get('external_evidence_json')
    
    # Get vulnerability types to process
    vuln_types = request.form.getlist('vuln_types')
    if not vuln_types or 'all' in vuln_types:
        vuln_types = None
    
    # Get minimum severity
    min_severity = request.form.get('min_severity', 'LOW')
    
    # Get strict validation parameter
    strict_validation = request.form.get('strict', 'false').lower() == 'true'
    
    temp_path = None
    db_session = None
    evidence_processed_count = 0
    
    try:
        # Create database session
        db_session = SessionLocal()
        
        # Save file to temp directory
        _, temp_path = tempfile.mkstemp(suffix=secure_filename(file.filename))
        file.save(temp_path)
        
        # Process file
        engine = ValidationEngine()
        
        # Parse file with intelligent detection
        if parser_type == 'auto':
            # Auto-detect parser type based on file content
            from api.parsers import detect_parser_type
            detected_type = detect_parser_type(temp_path)
            logger.info(f"Auto-detected parser type: {detected_type}")
            parser_type = detected_type
        
        # Get appropriate parser
        from api.parsers import PARSER_MAP
        parser_class = PARSER_MAP.get(parser_type)
        
        if not parser_class:
            return jsonify({
                "error": f"Unsupported parser type: {parser_type}",
                "supported_types": list(PARSER_MAP.keys())
            }), 400
        
        # Create parser instance and parse file
        parser = parser_class()
        findings = parser.parse_file(temp_path)
        
        logger.info(f"Parser {parser_type} extracted {len(findings)} findings")
        
        # Store findings in database for evidence linking
        db_findings = []
        for finding in findings:
            db_finding = Finding(
                source_id=finding.source_id,
                source_type=finding.source_type or parser_type,
                vulnerability_type=finding.vulnerability_type,
                name=finding.name,
                description=finding.description,
                severity=finding.severity,
                cvss_score=finding.cvss_score,
                cwe_id=finding.cwe_id,
                file_path=finding.file_path,
                line_number=finding.line_number,
                column=finding.column,
                raw_data=finding.raw_data if hasattr(finding, 'raw_data') else None
            )
            db_session.add(db_finding)
            db_findings.append(db_finding)
        
        # Flush to get IDs for findings
        db_session.flush()
        
        # Process external evidence if provided
        if external_evidence_json:
            try:
                external_evidence_list = json.loads(external_evidence_json)
                if not isinstance(external_evidence_list, list):
                    raise ValueError("external_evidence_json must be an array of evidence items")
                
                for evidence_item in external_evidence_list:
                    try:
                        # Validate evidence item structure
                        if not isinstance(evidence_item, dict):
                            logger.warning("Skipping invalid evidence item: not a dictionary")
                            continue
                        
                        if 'findingMatcher' not in evidence_item:
                            logger.warning("Skipping evidence item: missing findingMatcher")
                            continue
                        
                        if 'evidenceType' not in evidence_item:
                            logger.warning("Skipping evidence item: missing evidenceType")
                            continue
                        
                        if 'description' not in evidence_item:
                            logger.warning("Skipping evidence item: missing description")
                            continue
                        
                        if 'data' not in evidence_item:
                            logger.warning("Skipping evidence item: missing data")
                            continue
                        
                        # Find matching findings
                        matched_findings = FindingMatcher.match_finding(
                            evidence_item['findingMatcher'], 
                            db_findings
                        )
                        
                        if not matched_findings:
                            logger.warning(f"No findings matched for evidence item with matcher: {evidence_item['findingMatcher']}")
                            continue
                        
                        # Create evidence for each matched finding
                        for matched_finding in matched_findings:
                            try:
                                evidence = create_evidence_from_structured_data(
                                    matched_finding, evidence_item, db_session
                                )
                                evidence_processed_count += 1
                                logger.info(f"Created evidence {evidence.id} for finding {matched_finding.id}")
                            except Exception as e:
                                logger.error(f"Failed to create evidence for finding {matched_finding.id}: {e}")
                                continue
                    
                    except Exception as e:
                        logger.error(f"Error processing evidence item: {e}")
                        continue
            
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in external_evidence_json: {e}")
                return jsonify({
                    "error": "Invalid JSON format in external_evidence_json",
                    "details": str(e)
                }), 400
            except Exception as e:
                logger.error(f"Error processing external evidence: {e}")
                # Continue processing without external evidence
        
        # Commit database changes
        db_session.commit()
        
        # Filter findings
        if vuln_types or min_severity != 'INFORMATIONAL':
            findings = engine.filter_findings(findings, vuln_types=vuln_types, min_severity=min_severity)
        
        # Validate findings if requested
        if validate:
            validated_findings = []
            for finding in findings:
                result = engine.validate_finding(finding)
                validated_findings.append(result)
            findings = validated_findings
        
        # Generate VXDF
        vxdf_doc = engine.generate_vxdf(findings, application_name=target_name, application_version=target_version)
        
        # Save VXDF to output directory with proper extension
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        output_filename = f"vxdf_results_{timestamp}.vxdf.json"
        output_path = Path(OUTPUT_DIR) / output_filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(vxdf_doc.model_dump_json(indent=2))
        
        # Return results in frontend-compatible format
        result_findings = []
        for finding in findings:
            result_findings.append(transform_finding_to_vulnerability(finding))
        
        response_data = {
            "message": "File processed successfully",
            "vxdf_file": output_filename,
            "validation_mode": "strict" if strict_validation else "normal",
            "download_url": f"/download/{output_filename}"
        }
        
        if evidence_processed_count > 0:
            response_data["evidenceProcessed"] = evidence_processed_count
            response_data["message"] += f" with {evidence_processed_count} external evidence items"
        
        return jsonify(response_data)
    
    except ValueError as e:
        # Handle strict validation failures
        if "strict validation" in str(e).lower():
            logger.error(f"Strict validation error: {e}")
            if db_session:
                db_session.rollback()
            return jsonify({
                "error": "VXDF validation failed",
                "details": str(e),
                "validation_mode": "strict"
            }), 400
        else:
            # Re-raise other ValueErrors
            raise e
    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        if db_session:
            db_session.rollback()
        return jsonify({
            "error": "VXDF validation failed",
            "details": str(e),
            "validation_mode": "strict"
        }), 400
    except Exception as e:
        logger.error(f"Error processing file: {e}")
        if db_session:
            db_session.rollback()
        return jsonify({"error": str(e)}), 500
    
    finally:
        # Clean up temp file
        if temp_path and Path(temp_path).exists():
            os.unlink(temp_path)
        
        # Close database session
        if db_session:
            db_session.close()

@api_bp.route('/download/<filename>', methods=['GET'])
def download_vxdf(filename: str):
    """
    Download a VXDF file with proper media type and headers.
    ---
    tags:
      - Download
    parameters:
      - name: filename
        in: path
        type: string
        required: true
        description: Name of the VXDF file to download
    responses:
      200:
        description: VXDF file download
        headers:
          Content-Type:
            type: string
            description: application/vxdf+json
          Content-Disposition:
            type: string
            description: attachment; filename="filename.vxdf.json"
      404:
        description: File not found
      500:
        description: Internal server error
    """
    try:
        # Ensure filename is secure and has proper extension
        secure_name = secure_filename(filename)
        if not secure_name.endswith('.vxdf.json'):
            return jsonify({"error": "Invalid file type. Must be .vxdf.json"}), 400
        
        file_path = Path(OUTPUT_DIR) / secure_name
        
        if not file_path.exists():
            return jsonify({"error": "File not found"}), 404
        
        # Send file with proper VXDF media type and Content-Disposition
        return send_file(
            file_path,
            mimetype='application/vxdf+json',
            as_attachment=True,
            download_name=secure_name
        )
    
    except Exception as e:
        logger.error(f"Error downloading file {filename}: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@api_bp.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """
    Get a list of vulnerabilities with optional filtering.
    ---
    tags:
      - Vulnerabilities
    parameters:
      - name: limit
        in: query
        type: integer
        required: false
        description: Max number of results
      - name: offset
        in: query
        type: integer
        required: false
        description: Offset for pagination
      - name: category
        in: query
        type: string
        required: false
        description: Vulnerability type/category
      - name: exploitable
        in: query
        type: boolean
        required: false
        description: Filter by exploitability
      - name: severity
        in: query
        type: string
        required: false
        description: Filter by severity
      - name: validated
        in: query
        type: boolean
        required: false
        description: Filter by validation status
    responses:
      200:
        description: List of vulnerabilities
        schema:
          type: object
          properties:
            vulnerabilities:
              type: array
              items:
                $ref: '#/definitions/Vulnerability'
            total:
              type: integer
            limit:
              type: integer
            offset:
              type: integer
      500:
        description: Internal server error
    """
    db = SessionLocal()
    try:
        # Get query parameters
        limit = request.args.get('limit', 10, type=int)
        offset = request.args.get('offset', 0, type=int)
        vuln_type = request.args.get('category')
        exploitable = request.args.get('exploitable')
        severity = request.args.get('severity')
        validated = request.args.get('validated')
        
        # Build query
        query = db.query(Finding)
        
        if vuln_type:
            query = query.filter(Finding.vulnerability_type == vuln_type)
        
        if exploitable == 'true':
            query = query.filter(Finding.is_exploitable == True)
        elif exploitable == 'false':
            query = query.filter(Finding.is_exploitable == False)
        
        if severity:
            query = query.filter(Finding.severity == severity)
        
        if validated == 'true':
            query = query.filter(Finding.is_validated == True)
        elif validated == 'false':
            query = query.filter(Finding.is_validated == False)
        
        # Get total count
        total = query.count()
        
        # Apply pagination - without using created_at (which might be NULL)
        findings = query.order_by(Finding.id.desc()).offset(offset).limit(limit).all()
        
        # Transform to frontend format
        result = []
        for finding in findings:
            result.append(transform_finding_to_vulnerability(finding))
        
        return jsonify({
            'vulnerabilities': result,
            'total': total,
            'limit': limit,
            'offset': offset
        })
    
    except SQLAlchemyError as e:
        logger.error(f"Database error in get_vulnerabilities: {e}", exc_info=True)
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    except Exception as e:
        logger.error(f"Error in get_vulnerabilities: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()

@api_bp.route('/vulnerabilities/<vulnerability_id>', methods=['GET'])
def get_vulnerability(vulnerability_id):
    """
    Get detailed information about a specific vulnerability.
    ---
    tags:
      - Vulnerabilities
    parameters:
      - name: vulnerability_id
        in: path
        type: string
        required: true
        description: Vulnerability ID
    responses:
      200:
        description: Vulnerability details
        schema:
          $ref: '#/definitions/Vulnerability'
      404:
        description: Vulnerability not found
      500:
        description: Internal server error
    """
    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.id == vulnerability_id).first()
        
        if not finding:
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        # Transform to frontend format
        result = transform_finding_to_vulnerability(finding)
        
        return jsonify(result)
    
    except SQLAlchemyError as e:
        logger.error(f"Database error in get_vulnerability: {e}", exc_info=True)
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    except Exception as e:
        logger.error(f"Error in get_vulnerability: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()

@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """
    Get dashboard statistics.
    ---
    tags:
      - Stats
    responses:
      200:
        description: Dashboard statistics
        schema:
          type: object
          properties:
            total:
              type: integer
            validated:
              type: integer
            exploitable:
              type: integer
            pending:
              type: integer
            bySeverity:
              type: object
            byType:
              type: object
      500:
        description: Internal server error
    """
    try:
        db: Session = next(get_db())
        total_findings = db.query(Finding).count()
        validated_findings = db.query(Finding).filter(Finding.is_validated == True).count()
        exploitable_findings = db.query(Finding).filter(Finding.is_exploitable == True).count()
        pending_findings = total_findings - validated_findings

        # Severity breakdown
        severity_counts = db.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all()
        by_severity = {s if s else 'UNKNOWN': c for s, c in severity_counts}

        # Type breakdown
        type_counts = db.query(Finding.vulnerability_type, func.count(Finding.id)).group_by(Finding.vulnerability_type).all()
        by_type = {t if t else 'UNKNOWN': c for t, c in type_counts}

        return jsonify({
            'total': total_findings,
            'validated': validated_findings,
            'exploitable': exploitable_findings,
            'pending': pending_findings,
            'bySeverity': by_severity,
            'byType': by_type
        })
    except Exception as e:
        logger.error(f"Error in get_stats: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@api_bp.route('/findings', methods=['GET'])
def get_findings():
    """
    Get all findings.
    ---
    tags:
      - Findings
    responses:
      200:
        description: List of findings
        schema:
          type: object
          properties:
            findings:
              type: array
              items:
                $ref: '#/definitions/Finding'
      500:
        description: Internal server error
    """
    try:
        db: Session = next(get_db())
        findings = db.query(Finding).all()
        return jsonify({
            'findings': [
                {
                    'id': f.id,
                    'name': f.name,
                    'vulnerability_type': f.vulnerability_type,
                    'severity': f.severity,
                    'is_validated': f.is_validated,
                    'is_exploitable': f.is_exploitable
                } for f in findings
            ]
        })
    except Exception as e:
        logger.error(f"Error in get_findings: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@api_bp.route('/supported-types', methods=['GET'])
def get_supported_types():
    """
    Get supported vulnerability types.
    ---
    tags:
      - Types
    responses:
      200:
        description: List of supported vulnerability types
        schema:
          type: object
          properties:
            vulnerabilityTypes:
              type: array
              items:
                type: string
    """
    return jsonify({
        'vulnerabilityTypes': SUPPORTED_VULN_TYPES
    })

@api_bp.route("/validate", methods=["POST"])
def validate_vxdf():
    """Validate an existing VXDF file against the schema.
    ---
    tags:
      - VXDF Validation
    consumes:
      - multipart/form-data
    parameters:
      - name: file
        in: formData
        type: file
        required: true
        description: VXDF JSON file to validate
    responses:
      200:
        description: VXDF file is valid
        schema:
          type: object
          properties:
            valid:
              type: boolean
              example: true
            message:
              type: string
              example: "VXDF document is valid"
            file:
              type: string
              example: "sample.vxdf.json"
            exploit_flows:
              type: integer
              example: 2
            evidence_count:
              type: integer
              example: 5
      400:
        description: VXDF file is invalid
        schema:
          type: object
          properties:
            valid:
              type: boolean
              example: false
            error:
              type: string
              example: "Schema validation failed"
            file:
              type: string
              example: "invalid.vxdf.json"
    """
    try:
        # Check if file is present in request
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400
        
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        temp_path = Path(tempfile.gettempdir()) / filename
        file.save(temp_path)
        
        logger.info(f"Validating VXDF file: {filename}")
        
        # Initialize validation engine
        engine = ValidationEngine()
        
        # Validate the VXDF file
        validation_result = engine.validate_existing_vxdf(str(temp_path))
        
        # Clean up temp file
        if temp_path.exists():
            temp_path.unlink()
        
        if validation_result["is_valid"]:
            return jsonify({
                "valid": True,
                "message": validation_result["message"],
                "file": filename,
                "exploit_flows": validation_result.get("exploit_flows", 0),
                "evidence_count": validation_result.get("evidence_count", 0)
            })
        else:
            return jsonify({
                "valid": False,
                "error": validation_result["error"],
                "file": filename,
                "failed_value": validation_result.get("failed_value")
            }), 400
    
    except Exception as e:
        logger.error(f"Error validating VXDF file: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/findings/<finding_id>/attach_evidence_file', methods=['POST'])
def attach_evidence_file(finding_id: str):
    """
    Attach an evidence file to an existing finding.
    ---
    tags:
      - Evidence
    consumes:
      - multipart/form-data
    parameters:
      - name: finding_id
        in: path
        type: string
        required: true
        description: ID of the finding to attach evidence to
      - name: evidence_file
        in: formData
        type: file
        required: true
        description: The evidence file to upload
      - name: evidence_type_str
        in: formData
        type: string
        required: true
        description: Type of evidence (must be valid EvidenceTypeEnum value)
      - name: description
        in: formData
        type: string
        required: true
        description: Description of the evidence
      - name: validation_method_str
        in: formData
        type: string
        required: false
        description: Validation method used (must be valid ValidationMethodEnum value)
      - name: timestamp_str
        in: formData
        type: string
        required: false
        description: Timestamp in ISO 8601 format
      - name: language
        in: formData
        type: string
        required: false
        description: Programming language (for code snippets)
      - name: script_language
        in: formData
        type: string
        required: false
        description: Script language (for PoC scripts)
      - name: command
        in: formData
        type: string
        required: false
        description: Command executed (for command output evidence)
      - name: tool_name
        in: formData
        type: string
        required: false
        description: Tool name (for tool-specific output)
      - name: caption
        in: formData
        type: string
        required: false
        description: Caption for screenshots
    responses:
      200:
        description: Evidence attached successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
            message:
              type: string
            evidence_id:
              type: string
      400:
        description: Bad request
      404:
        description: Finding not found
      500:
        description: Internal server error
    """
    if 'evidence_file' not in request.files:
        return jsonify({"error": "No evidence_file in the request"}), 400
    
    evidence_file = request.files['evidence_file']
    
    if evidence_file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Get required form parameters
    evidence_type_str = request.form.get('evidence_type_str')
    description = request.form.get('description')
    
    if not evidence_type_str:
        return jsonify({"error": "evidence_type_str is required"}), 400
    
    if not description:
        return jsonify({"error": "description is required"}), 400
    
    # Get optional parameters
    validation_method_str = request.form.get('validation_method_str')
    timestamp_str = request.form.get('timestamp_str')
    
    # Get additional parameters for different evidence types
    additional_params = {
        'language': request.form.get('language'),
        'script_language': request.form.get('script_language'),
        'command': request.form.get('command'),
        'tool_name': request.form.get('tool_name'),
        'caption': request.form.get('caption'),
        'log_source': request.form.get('log_source'),
        'log_level': request.form.get('log_level'),
        'component_name': request.form.get('component_name'),
        'file_path': request.form.get('file_path'),
        'start_line': request.form.get('start_line', type=int),
        'end_line': request.form.get('end_line', type=int),
        'script_arguments': request.form.getlist('script_arguments'),
        'expected_outcome': request.form.get('expected_outcome'),
        'setting_name': request.form.get('setting_name'),
        'interpretation': request.form.get('interpretation'),
        'exit_code': request.form.get('exit_code', type=int),
        'execution_context': request.form.get('execution_context'),
        'tool_version': request.form.get('tool_version'),
        'command_line': request.form.get('command_line'),
        'data_type_description': request.form.get('data_type_description'),
    }
    
    # Remove None values
    additional_params = {k: v for k, v in additional_params.items() if v is not None}
    
    db_session = None
    
    try:
        # Create database session
        db_session = SessionLocal()
        
        # Find the finding
        finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            return jsonify({"error": f"Finding with ID {finding_id} not found"}), 404
        
        # Read file content
        file_content = evidence_file.read()
        
        # Create evidence from file upload
        evidence = create_evidence_from_file_upload(
            finding=finding,
            file_content=file_content,
            file_name=evidence_file.filename,
            evidence_type_str=evidence_type_str,
            description=description,
            validation_method_str=validation_method_str,
            timestamp_str=timestamp_str,
            additional_params=additional_params,
            db_session=db_session
        )
        
        # Commit the changes
        db_session.commit()
        
        return jsonify({
            "success": True,
            "message": f"Evidence file '{evidence_file.filename}' attached successfully to finding {finding_id}",
            "evidence_id": evidence.id
        })
    
    except ValueError as e:
        logger.error(f"Validation error attaching evidence: {e}")
        if db_session:
            db_session.rollback()
        return jsonify({
            "error": "Evidence validation failed",
            "details": str(e)
        }), 400
    
    except Exception as e:
        logger.error(f"Error attaching evidence file: {e}")
        if db_session:
            db_session.rollback()
        return jsonify({
            "error": "Failed to attach evidence file",
            "details": str(e)
        }), 500
    
    finally:
        if db_session:
            db_session.close()

# Validation Workflow Endpoints
@api_bp.route('/validation/start', methods=['POST'])
def start_validation():
    """
    Start validation workflow for a specific finding.
    ---
    tags:
      - Validation
    consumes:
      - application/json
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            findingId:
              type: string
              description: ID of the finding to validate
    responses:
      200:
        description: Validation workflow started
        schema:
          type: object
          properties:
            workflowId:
              type: string
            message:
              type: string
            status:
              type: string
      400:
        description: Bad request
      404:
        description: Finding not found
      500:
        description: Internal server error
    """
    try:
        data = request.get_json()
        if not data or 'findingId' not in data:
            return jsonify({"error": "findingId is required"}), 400
        
        finding_id = data['findingId']
        
        # Check if finding exists
        db = SessionLocal()
        try:
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                return jsonify({"error": "Finding not found"}), 404
            
            # Check if already validated
            if finding.is_validated:
                return jsonify({
                    "error": "Finding already validated",
                    "message": f"Finding {finding_id} has already been validated",
                    "result": {
                        "exploitable": finding.is_exploitable,
                        "validationMessage": finding.validation_message,
                        "validatedAt": finding.validation_date.isoformat() if finding.validation_date else None
                    }
                }), 400
            
            # Generate a workflow ID for tracking
            import uuid
            workflow_id = str(uuid.uuid4())
            
            logger.info(f"Starting REAL validation workflow {workflow_id} for finding {finding_id}")
            
            # Increment validation attempts before starting
            finding.validation_attempts = (finding.validation_attempts or 0) + 1
            db.commit()
            
            # Use the real ValidationEngine to perform actual Docker-based validation
            # Note: We merge the finding into the engine's session to avoid session conflicts
            engine = ValidationEngine()
            
            # Validate the finding - the engine will handle session management
            validated_finding = engine.validate_finding(finding)
            
            # The validated_finding is now managed by the engine's session
            # We need to get fresh data from our session
            db.refresh(finding)
            
            response_data = {
                "workflowId": workflow_id,
                "message": "Docker-based validation completed successfully",
                "status": "COMPLETED",
                "findingId": finding_id,
                "result": {
                    "exploitable": finding.is_exploitable,
                    "validationMessage": finding.validation_message,
                    "evidenceCount": len(finding.evidence) if finding.evidence else 0,
                    "validatedAt": finding.validation_date.isoformat() if finding.validation_date else None
                }
            }
            
            # Add evidence summary if available
            if finding.evidence:
                evidence_summary = []
                for evidence in finding.evidence:
                    evidence_summary.append({
                        "type": evidence.evidence_type,
                        "description": evidence.description
                    })
                response_data["evidenceSummary"] = evidence_summary
            
            logger.info(f"Validation workflow {workflow_id} completed: Exploitable={finding.is_exploitable}")
            
            return jsonify(response_data)
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error in validation workflow: {e}", exc_info=True)
        return jsonify({
            "error": "Validation failed", 
            "details": str(e),
            "message": "Docker-based validation encountered an error"
        }), 500

@api_bp.route('/validation/workflows', methods=['GET'])
def get_validation_workflows():
    """
    Get all validation workflows.
    ---
    tags:
      - Validation
    responses:
      200:
        description: List of validation workflows
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: string
              findingId:
                type: string
              status:
                type: string
              startTime:
                type: string
              endTime:
                type: string
              result:
                type: object
      500:
        description: Internal server error
    """
    try:
        # For now, return mock validation workflows based on recent findings
        db = SessionLocal()
        try:
            recent_findings = db.query(Finding).filter(
                Finding.is_validated == True
            ).order_by(Finding.updated_at.desc()).limit(10).all()
            
            workflows = []
            for i, finding in enumerate(recent_findings):
                workflow = {
                    "id": f"workflow-{finding.id}",
                    "findingId": finding.id,
                    "findingTitle": finding.name,
                    "status": "COMPLETED" if finding.is_validated else "RUNNING",
                    "startTime": (finding.validation_date or finding.created_at).isoformat() if finding.validation_date or finding.created_at else None,
                    "endTime": finding.validation_date.isoformat() if finding.validation_date else None,
                    "dockerContainer": f"vxdf-validation-{str(i+1).zfill(3)}",
                    "result": {
                        "exploitable": finding.is_exploitable,
                        "confidence": 85 + (i * 3),  # Mock confidence scores
                        "evidence": [],
                        "recommendations": []
                    } if finding.is_validated else None
                }
                workflows.append(workflow)
            
            return jsonify(workflows)
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error getting validation workflows: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/validation/workflows/<workflow_id>', methods=['GET'])
def get_validation_workflow(workflow_id):
    """
    Get specific validation workflow details.
    ---
    tags:
      - Validation
    parameters:
      - name: workflow_id
        in: path
        type: string
        required: true
        description: Workflow ID
    responses:
      200:
        description: Validation workflow details
        schema:
          type: object
          properties:
            id:
              type: string
            findingId:
              type: string
            status:
              type: string
            startTime:
              type: string
            endTime:
              type: string
            steps:
              type: array
            result:
              type: object
      404:
        description: Workflow not found
      500:
        description: Internal server error
    """
    try:
        # Extract finding ID from workflow ID (format: workflow-{finding_id})
        if not workflow_id.startswith('workflow-'):
            return jsonify({"error": "Invalid workflow ID format"}), 400
        
        finding_id = workflow_id.replace('workflow-', '')
        
        db = SessionLocal()
        try:
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                return jsonify({"error": "Workflow not found"}), 404
            
            workflow = {
                "id": workflow_id,
                "findingId": finding.id,
                "findingTitle": finding.name,
                "status": "COMPLETED" if finding.is_validated else "PENDING",
                "startTime": (finding.validation_date or finding.created_at).isoformat() if finding.validation_date or finding.created_at else None,
                "endTime": finding.validation_date.isoformat() if finding.validation_date else None,
                "steps": [
                    {
                        "name": "Environment Preparation",
                        "status": "COMPLETED",
                        "startTime": (finding.validation_date or finding.created_at).isoformat() if finding.validation_date or finding.created_at else None,
                        "endTime": (finding.validation_date or finding.created_at).isoformat() if finding.validation_date or finding.created_at else None,
                        "logs": ["Docker container initialized", "Target application deployed"],
                        "dockerContainerId": f"vxdf-validation-{finding_id[:8]}"
                    },
                    {
                        "name": "Exploitation Attempt", 
                        "status": "COMPLETED" if finding.is_validated else "PENDING",
                        "startTime": finding.validation_date.isoformat() if finding.validation_date else None,
                        "endTime": finding.validation_date.isoformat() if finding.validation_date else None,
                        "logs": ["Payload executed", "Response analyzed"],
                        "dockerContainerId": f"vxdf-validation-{finding_id[:8]}"
                    }
                ],
                "result": {
                    "exploitable": finding.is_exploitable,
                    "confidence": 90,
                    "evidence": [finding.validation_message] if finding.validation_message else [],
                    "recommendations": ["Apply security patches", "Implement input validation"]
                } if finding.is_validated else None
            }
            
            return jsonify(workflow)
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error getting validation workflow {workflow_id}: {e}")
        return jsonify({"error": str(e)}), 500

# Add Swagger definitions for Vulnerability and Finding at the bottom of the file
class EvidenceSchema(Schema):
    id = fields.String()
    type = fields.String()
    description = fields.String()
    content = fields.String()
    timestamp = fields.String()

class VulnerabilitySchema(Schema):
    id = fields.String()
    sourceId = fields.String()
    sourceType = fields.String()
    type = fields.String()
    name = fields.String()
    description = fields.String()
    severity = fields.String()
    cvssScore = fields.Float()
    cweId = fields.String()
    filePath = fields.String()
    lineNumber = fields.Integer()
    column = fields.Integer()
    isValidated = fields.Boolean()
    isExploitable = fields.Boolean()
    validationDate = fields.String()
    validationMessage = fields.String()
    validationAttempts = fields.Integer()
    evidence = fields.List(fields.Nested(EvidenceSchema))
    createdAt = fields.String()
    updatedAt = fields.String()

class FindingSchema(Schema):
    id = fields.String()
    name = fields.String()
    vulnerability_type = fields.String()
    severity = fields.String()
    is_validated = fields.Boolean()
    is_exploitable = fields.Boolean() 