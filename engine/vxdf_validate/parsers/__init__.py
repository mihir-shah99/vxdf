"""
Parsers for different security tool outputs.
"""
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class ParserType(str, Enum):
    """
    Types of parsers supported by the tool.
    """
    SARIF = "sarif"
    CYCLONEDX = "cyclonedx"
    DAST = "dast"

def get_parser(parser_type: ParserType, **kwargs):
    """
    Factory function to get the appropriate parser based on the type.
    
    Args:
        parser_type: Type of parser to use
        **kwargs: Additional arguments to pass to the parser
        
    Returns:
        Parser instance for the specified type
    """
    if parser_type == ParserType.SARIF:
        from vxdf_validate.parsers.sarif_parser import SarifParser
        return SarifParser(**kwargs)
    
    elif parser_type == ParserType.CYCLONEDX:
        from vxdf_validate.parsers.cyclonedx_parser import CycloneDXParser
        return CycloneDXParser(**kwargs)
    
    elif parser_type == ParserType.DAST:
        from vxdf_validate.parsers.dast_parser import DastParser
        return DastParser(**kwargs)
    
    else:
        logger.error(f"Unsupported parser type: {parser_type}")
        raise ValueError(f"Unsupported parser type: {parser_type}")
