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

from api.models.database import SessionLocal
from api.models.finding import Finding
from api.parsers import ParserType, get_parser
from api.core.engine import ValidationEngine
from api.config import OUTPUT_DIR, SUPPORTED_VULN_TYPES

# Create Blueprint for API routes
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Configure CORS for API routes
# In production, replace localhost:5173 with your actual domain
CORS(api_bp, resources={r"/*": {"origins": ["http://localhost:5173", "http://localhost:3000"]}})

# Configure logging
logger = logging.getLogger(__name__)

def transform_finding_to_vulnerability(finding: Finding) -> dict:
    """
    Transform a Finding database model to the frontend Vulnerability format.
    
    Args:
        finding: Finding model instance
        
    Returns:
        dict: Vulnerability data in frontend-compatible format
    """
    evidence_list = []
    for ev in finding.evidence:
        evidence_list.append({
            "description": ev.description,
            "method": ev.evidence_type,
            "timestamp": ev.created_at.isoformat() if ev.created_at else None,
            "content": ev.content
        })
    
    # Extract source and sink information from VXDF data if available
    source = {"file": finding.file_path, "line": finding.line_number}
    sink = {"file": finding.file_path, "line": finding.line_number}
    
    if finding.vxdf_data and 'source' in finding.vxdf_data:
        source = {
            "file": finding.vxdf_data['source'].get('file_path', finding.file_path),
            "line": finding.vxdf_data['source'].get('line_number', finding.line_number),
            "snippet": finding.vxdf_data['source'].get('code_snippet', '')
        }
    
    if finding.vxdf_data and 'sink' in finding.vxdf_data:
        sink = {
            "file": finding.vxdf_data['sink'].get('file_path', finding.file_path),
            "line": finding.vxdf_data['sink'].get('line_number', finding.line_number),
            "snippet": finding.vxdf_data['sink'].get('code_snippet', '')
        }
    
    # Extract data flow steps if available
    steps = []
    if finding.vxdf_data and 'steps' in finding.vxdf_data:
        for step in finding.vxdf_data['steps']:
            steps.append({
                "file": step.get('file_path', ''),
                "line": step.get('line_number', 0),
                "snippet": step.get('code_snippet', ''),
                "note": step.get('description', '')
            })
    
    return {
        "id": finding.id,
        "title": finding.name,
        "description": finding.description,
        "severity": finding.severity,
        "category": finding.vulnerability_type,
        "cwe": finding.cwe_id,
        "source": source,
        "sink": sink,
        "steps": steps,
        "exploitable": finding.is_exploitable,
        "validated": finding.is_validated,
        "validationDate": finding.validation_date.isoformat() if finding.validation_date else None,
        "validationMessage": finding.validation_message,
        "evidence": evidence_list,
        "createdAt": finding.created_at.isoformat() if finding.created_at else None
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
    try:
        db = SessionLocal()
        
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
    
    except Exception as e:
        logger.error(f"Error in API: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    
    finally:
        db.close()

@api_bp.route('/vulnerabilities/<vulnerability_id>', methods=['GET'])
def get_vulnerability(vulnerability_id):
    """
    Get detailed information about a specific vulnerability.
    """
    try:
        db = SessionLocal()
        
        finding = db.query(Finding).filter(Finding.id == vulnerability_id).first()
        
        if not finding:
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        # Transform to frontend format
        result = transform_finding_to_vulnerability(finding)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error in API: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    
    finally:
        db.close()

@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """
    Get statistics about findings in the database.
    """
    db = SessionLocal()
    try:
        # Default stats in case we can't query the database
        stats = {
            'total_findings': 0,
            'validated_findings': 0,
            'exploitable_findings': 0,
            'by_type': {},
            'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFORMATIONAL': 0}
        }
        
        try:
            # Get basic stats
            total_findings = db.query(Finding.id).count()
            validated_findings = db.query(Finding.id).filter(Finding.is_validated == True).count()
            exploitable_findings = db.query(Finding.id).filter(Finding.is_exploitable == True).count()
            
            # Update stats dictionary
            stats['total_findings'] = total_findings
            stats['validated_findings'] = validated_findings
            stats['exploitable_findings'] = exploitable_findings
            
            # Get findings by type
            for vuln_type in SUPPORTED_VULN_TYPES:
                count = db.query(Finding.id).filter(Finding.vulnerability_type == vuln_type).count()
                stats['by_type'][vuln_type] = count
            
            # Get findings by severity
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']:
                count = db.query(Finding.id).filter(Finding.severity == severity).count()
                stats['by_severity'][severity] = count
        except Exception as e:
            # Log the error but continue with default stats
            logger.error(f"Database query error in stats API: {e}")
        
        return jsonify(stats)
    
    except Exception as e:
        logger.error(f"Error in stats API: {e}", exc_info=True)
        return jsonify({
            'error': str(e),
            'total_findings': 0,
            'validated_findings': 0,
            'exploitable_findings': 0
        }), 500
    
    finally:
        db.close()

@api_bp.route('/supported-types', methods=['GET'])
def get_supported_types():
    """
    Get list of supported vulnerability types.
    """
    return jsonify(SUPPORTED_VULN_TYPES) 