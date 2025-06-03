"""
Parser modules for various security tool outputs.
"""
from enum import Enum
import logging

from .sarif_parser import SarifParser
from .dast_parser import DastParser
from .sca_parser import ScaParser
# from .cyclonedx_parser import CycloneDXParser  # Requires cyclonedx dependency

logger = logging.getLogger(__name__)

class ParserType(str, Enum):
    """Types of security tool output parsers."""
    SARIF = "sarif"
    DAST = "dast"
    ZAP = "zap"
    BURP = "burp"
    SCA = "sca"
    NPM_AUDIT = "npm_audit"
    PIP_AUDIT = "pip_audit"
    OWASP_ZAP = "owasp_zap"
    SEMGREP = "semgrep"
    SNYK = "snyk"

def get_parser(parser_type: ParserType, **kwargs):
    """Factory function to get the appropriate parser."""
    if parser_type in [ParserType.SARIF, ParserType.SEMGREP]:
        return SarifParser(**kwargs)
    elif parser_type in [ParserType.DAST, ParserType.ZAP, ParserType.BURP, ParserType.OWASP_ZAP]:
        return DastParser(**kwargs)
    elif parser_type in [ParserType.SCA, ParserType.NPM_AUDIT, ParserType.PIP_AUDIT, ParserType.SNYK]:
        return ScaParser(**kwargs)
    else:
        logger.warning(f"Parser type {parser_type} not implemented yet")
        return None

def detect_parser_type(file_path: str) -> str:
    """
    Detect parser type based on file content.
    
    Args:
        file_path: Path to the file to analyze
        
    Returns:
        Detected parser type string
    """
    import json
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # SARIF detection
        if isinstance(data, dict):
            if 'version' in data and 'runs' in data:
                return 'sarif'
            
            # ZAP detection
            if '@version' in data and 'site' in data:
                return 'zap'
            
            # npm audit detection
            if 'auditReportVersion' in data and 'vulnerabilities' in data:
                return 'npm_audit'
            
            # CycloneDX detection
            if 'bomFormat' in data and data.get('bomFormat') == 'CycloneDX':
                return 'sca'
            
            # Burp detection
            if 'issue_events' in data or ('issues' in data and 'scan_information' in data):
                return 'burp'
            
            # pip-audit detection
            if 'vulnerabilities' in data and isinstance(data['vulnerabilities'], list):
                if any('package' in vuln and 'id' in vuln for vuln in data['vulnerabilities'] if isinstance(vuln, dict)):
                    return 'pip_audit'
        
        # Default to sarif for unknown formats
        logger.warning(f"Could not detect parser type for {file_path}, defaulting to SARIF")
        return 'sarif'
        
    except Exception as e:
        logger.error(f"Error detecting parser type for {file_path}: {e}")
        return 'sarif'

__all__ = [
    'SarifParser',
    'DastParser', 
    'ScaParser',
    'ParserType',
    'get_parser',
    'detect_parser_type'
    # 'CycloneDXParser'
]

# Parser mapping for easy access
PARSER_MAP = {
    'sarif': SarifParser,
    'sast': SarifParser,  # SAST tools typically output SARIF
    'dast': DastParser,
    'zap': DastParser,
    'burp': DastParser,
    'sca': ScaParser,
    'npm_audit': ScaParser,
    'pip_audit': ScaParser,
    # 'cyclonedx': CycloneDXParser,
    # 'sbom': CycloneDXParser,  # Software Bill of Materials
}
