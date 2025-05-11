"""
API endpoints for the VXDF frontend.

This module provides RESTful API endpoints specifically designed for the React frontend.
It serves as an integration layer between the frontend and the core VXDF validation engine.
"""
import os
from pathlib import Path
import logging
import tempfile
import datetime
from typing import List, Dict, Any, Optional

from flask import Blueprint, request, jsonify, current_app
from flask_cors import CORS
from werkzeug.utils import secure_filename
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

# Ensure models are imported first to get registered with declarative base
from api.models.finding import Finding, Evidence
from api.models.database import SessionLocal, get_db
from api.parsers import ParserType, get_parser
from api.core.engine import ValidationEngine
from api.config import OUTPUT_DIR, SUPPORTED_VULN_TYPES

# Create blueprint with a unique name
api_bp = Blueprint('vxdf_api', __name__, url_prefix='/api')

# Configure CORS for API routes
# In production, replace localhost:5173 with your actual domain
CORS(api_bp, resources={r"/*": {"origins": ["http://localhost:5173", "http://localhost:3000"]}})

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
    Upload a security scan file for validation and processing.
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
    
    # Get vulnerability types to process
    vuln_types = request.form.getlist('vuln_types')
    if not vuln_types or 'all' in vuln_types:
        vuln_types = None
    
    # Get minimum severity
    min_severity = request.form.get('min_severity', 'LOW')
    
    try:
        # Save file to temp directory
        _, temp_path = tempfile.mkstemp(suffix=secure_filename(file.filename))
        file.save(temp_path)
        
        # Process file
        engine = ValidationEngine()
        
        # Parse file
        parser = get_parser(ParserType(parser_type))
        findings = parser.parse_file(temp_path)
        
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
        vxdf_doc = engine.generate_vxdf(findings, target_name=target_name, target_version=target_version)
        
        # Save VXDF to output directory
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        output_filename = f"vxdf_results_{timestamp}.json"
        output_path = Path(OUTPUT_DIR) / output_filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(vxdf_doc.to_json(pretty=True))
        
        # Return results in frontend-compatible format
        result_findings = []
        for finding in findings:
            result_findings.append(transform_finding_to_vulnerability(finding))
        
        return jsonify({
            "success": True,
            "message": f"Processed {len(findings)} findings",
            "findings": result_findings,
            "outputFile": output_filename
        })
    
    except Exception as e:
        logger.error(f"Error processing upload: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    
    finally:
        # Clean up temp file
        if Path(temp_path).exists():
            os.unlink(temp_path)

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

# Add Swagger definitions for Vulnerability and Finding at the bottom of the file
from marshmallow import Schema, fields

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