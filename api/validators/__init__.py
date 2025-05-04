"""
VXDF Validate validators.
"""
from enum import Enum

class ValidatorType(str, Enum):
    DEFAULT = "default"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
