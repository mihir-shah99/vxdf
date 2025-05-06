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

from api.models.database import SessionLocal, get_db
from api.models.finding import Finding, Evidence
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
    if finding.evidence:
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
    Handle file upload for validation from the frontend.
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
    """
    db = SessionLocal()
    try:
        # Get query parameters
        limit = request.args.get('limit', 10, type=int)
        offset = request.args.get('offset', 0, type=int)
        vuln_type = request.args.get('category')
        exploitable = request.args.get('exploitable')
        severity = request.args.get('severity')
        
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
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        findings = query.order_by(Finding.created_at.desc()).offset(offset).limit(limit).all()
        
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
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        logger.error(f"Error in get_vulnerabilities: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()

@api_bp.route('/vulnerabilities/<vulnerability_id>', methods=['GET'])
def get_vulnerability(vulnerability_id):
    """
    Get detailed information about a specific vulnerability.
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
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        logger.error(f"Error in get_vulnerability: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()

@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics."""
    try:
        db: Session = next(get_db())
        total_findings = db.query(Finding).count()
        validated_findings = db.query(Finding).filter(Finding.is_validated == True).count()
        exploitable_findings = db.query(Finding).filter(Finding.is_exploitable == True).count()
        
        return jsonify({
            'total_findings': total_findings,
            'validated_findings': validated_findings,
            'exploitable_findings': exploitable_findings
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/findings', methods=['GET'])
def get_findings():
    """Get all findings."""
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
        return jsonify({'error': str(e)}), 500

@api_bp.route('/supported-types', methods=['GET'])
def get_supported_types():
    """Get supported vulnerability types."""
    return jsonify({
        'vulnerabilityTypes': SUPPORTED_VULN_TYPES
    }) 