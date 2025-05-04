"""
Validators for different vulnerability types.
"""
from enum import Enum

class ValidatorType(str, Enum):
    """
    Types of vulnerability validators.
    """
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
