"""
Flask web server for VXDF Validate.
"""
import os
import logging
import tempfile
import json
import uuid
import datetime
from typing import List, Dict, Any, Optional

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from werkzeug.utils import secure_filename

# Import version
try:
    # When imported as a module from outside
    from api import __version__
except ImportError:
    # When imported directly within api directory
    try:
        from __init__ import __version__
    except ImportError:
        __version__ = "1.0.0"

# Import models and parsers with relative imports when possible
try:
    # Try relative imports first (when run within api directory)
    from models.database import init_db, SessionLocal
    from models.finding import Finding
    from parsers import ParserType, get_parser
    from core.engine import ValidationEngine
    from api import api_bp  # Import the API blueprint
except ImportError:
    # Fall back to absolute imports (when imported as a module)
    from api.models.database import init_db, SessionLocal
    from api.models.finding import Finding
    from api.parsers import ParserType, get_parser
    from api.core.engine import ValidationEngine
    from api.api import api_bp  # Import the API blueprint

# Import config with fallback
try:
    from config import (
        TEMPLATE_DIR, STATIC_DIR, OUTPUT_DIR, SUPPORTED_VULN_TYPES,
        LOG_DIR, TEMP_DIR, DB_PATH, PROJECT_ROOT
    )
except ImportError:
    try:
        from api.config import (
            TEMPLATE_DIR, STATIC_DIR, OUTPUT_DIR, SUPPORTED_VULN_TYPES,
            LOG_DIR, TEMP_DIR, DB_PATH, PROJECT_ROOT
        )
    except ImportError:
        # Default fallbacks if config can't be imported
        from pathlib import Path
        API_DIR = Path(__file__).resolve().parent
        PROJECT_ROOT = API_DIR.parent
        TEMPLATE_DIR = PROJECT_ROOT / "templates"
        STATIC_DIR = PROJECT_ROOT / "static"
        OUTPUT_DIR = PROJECT_ROOT / "output"
        LOG_DIR = PROJECT_ROOT / "logs"
        TEMP_DIR = PROJECT_ROOT / "temp"
        DB_PATH = PROJECT_ROOT / "vxdf_validate.db"
        SUPPORTED_VULN_TYPES = []

# Initialize Flask app
app = Flask(
    __name__,
    template_folder=str(TEMPLATE_DIR),
    static_folder=str(STATIC_DIR)
)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24))

# Register the API blueprint
app.register_blueprint(api_bp)

# Configure logging
logger = logging.getLogger(__name__)

# Initialize database
init_db()

@app.route('/')
def index():
    """
    Render the home page.
    """
    # Get some stats for the dashboard
    db = SessionLocal()
    try:
        total_findings = db.query(Finding).count()
        validated_findings = db.query(Finding).filter(Finding.is_validated == True).count()
        exploitable_findings = db.query(Finding).filter(Finding.is_exploitable == True).count()
        non_exploitable_findings = db.query(Finding).filter(Finding.is_exploitable == False).count()
        
        # Get recent findings
        recent_findings = db.query(Finding).order_by(Finding.created_at.desc()).limit(5).all()
        
        return render_template('index.html', 
                              version=__version__,
                              total_findings=total_findings,
                              validated_findings=validated_findings,
                              exploitable_findings=exploitable_findings,
                              non_exploitable_findings=non_exploitable_findings,
                              recent_findings=recent_findings,
                              supported_vuln_types=SUPPORTED_VULN_TYPES)
    finally:
        db.close()

@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Handle file upload for validation.
    """
    if 'file' not in request.files:
        flash('No file part in the request', 'danger')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('index'))
    
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
        output_path = OUTPUT_DIR / output_filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(vxdf_doc.to_json(pretty=True))
        
        # Redirect to results page
        return redirect(url_for('results', filename=output_filename))
    
    except Exception as e:
        logger.error(f"Error processing upload: {e}", exc_info=True)
        flash(f"Error processing file: {str(e)}", 'danger')
        return redirect(url_for('index'))
    
    finally:
        # Clean up temp file
        if Path(temp_path).exists():
            os.unlink(temp_path)

@app.route('/results')
def results():
    """
    Display validation results.
    """
    filename = request.args.get('filename')
    
    if not filename:
        flash('No results file specified', 'danger')
        return redirect(url_for('index'))
    
    # Ensure filename is secure
    filename = secure_filename(filename)
    filepath = OUTPUT_DIR / filename
    
    if not filepath.exists():
        flash('Results file not found', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Load VXDF document
        from api.models.vxdf import VXDFDocument
        
        with open(filepath, 'r', encoding='utf-8') as f:
            vxdf_content = f.read()
        
        vxdf_doc = VXDFDocument.from_json(vxdf_content)
        
        return render_template('results.html', 
                              version=__version__,
                              vxdf=vxdf_doc,
                              filename=filename)
    
    except Exception as e:
        logger.error(f"Error displaying results: {e}", exc_info=True)
        flash(f"Error displaying results: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_results(filename):
    """
    Download VXDF results file.
    """
    # Ensure filename is secure
    filename = secure_filename(filename)
    filepath = OUTPUT_DIR / filename
    
    if not filepath.exists():
        flash('Results file not found', 'danger')
        return redirect(url_for('index'))
    
    return send_file(filepath, as_attachment=True, download_name=filename)

@app.route('/api/findings')
def api_findings():
    """
    API endpoint to get findings.
    """
    try:
        db = SessionLocal()
        
        # Get query parameters
        limit = request.args.get('limit', 10, type=int)
        offset = request.args.get('offset', 0, type=int)
        vuln_type = request.args.get('vuln_type')
        exploitable = request.args.get('exploitable')
        
        # Build query
        query = db.query(Finding)
        
        if vuln_type:
            query = query.filter(Finding.vulnerability_type == vuln_type)
        
        if exploitable == 'true':
            query = query.filter(Finding.is_exploitable == True)
        elif exploitable == 'false':
            query = query.filter(Finding.is_exploitable == False)
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        findings = query.order_by(Finding.created_at.desc()).offset(offset).limit(limit).all()
        
        # Convert to JSON-serializable format
        result = []
        for finding in findings:
            result.append({
                'id': finding.id,
                'name': finding.name,
                'vulnerability_type': finding.vulnerability_type,
                'severity': finding.severity,
                'is_validated': finding.is_validated,
                'is_exploitable': finding.is_exploitable,
                'created_at': finding.created_at.isoformat() if finding.created_at else None
            })
        
        return jsonify({
            'findings': result,
            'total': total,
            'limit': limit,
            'offset': offset
        })
    
    except Exception as e:
        logger.error(f"Error in API: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    
    finally:
        db.close()

@app.route('/api/finding/<finding_id>')
def api_finding(finding_id):
    """
    API endpoint to get a specific finding.
    """
    try:
        db = SessionLocal()
        
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        
        if not finding:
            return jsonify({'error': 'Finding not found'}), 404
        
        # Get evidence
        evidence_list = []
        for evidence in finding.evidence:
            evidence_list.append({
                'id': evidence.id,
                'evidence_type': evidence.evidence_type,
                'description': evidence.description,
                'content': evidence.content,
                'created_at': evidence.created_at.isoformat() if evidence.created_at else None
            })
        
        result = {
            'id': finding.id,
            'source_id': finding.source_id,
            'source_type': finding.source_type,
            'vulnerability_type': finding.vulnerability_type,
            'name': finding.name,
            'description': finding.description,
            'severity': finding.severity,
            'cvss_score': finding.cvss_score,
            'cwe_id': finding.cwe_id,
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'column': finding.column,
            'is_validated': finding.is_validated,
            'is_exploitable': finding.is_exploitable,
            'validation_date': finding.validation_date.isoformat() if finding.validation_date else None,
            'validation_message': finding.validation_message,
            'validation_attempts': finding.validation_attempts,
            'created_at': finding.created_at.isoformat() if finding.created_at else None,
            'updated_at': finding.updated_at.isoformat() if finding.updated_at else None,
            'evidence': evidence_list
        }
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error in API: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    
    finally:
        db.close()

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('404.html', version=__version__), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    return render_template('500.html', version=__version__), 500

# Initialize app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
