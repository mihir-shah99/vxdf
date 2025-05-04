"""
VXDF Validate parsers for various input formats.
"""
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class ParserType(str, Enum):
    """Types of security tool output parsers."""
    SARIF = "sarif"
    OWASP_ZAP = "owasp_zap"
    SEMGREP = "semgrep"
    SNYK = "snyk"

def get_parser(parser_type: ParserType, **kwargs):
    """Factory function to get the appropriate parser."""
    if parser_type == ParserType.SARIF:
        return SarifParser(**kwargs)
    else:
        logger.warning(f"Parser type {parser_type} not implemented yet")
        return None
