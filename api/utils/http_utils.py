"""
HTTP utilities for making and validating requests.
"""
import logging
import json
import re
from typing import Dict, Any, Optional, Tuple, Union
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

def make_request(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    json_data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    timeout: int = 10,
    verify_ssl: bool = True,
    allow_redirects: bool = True,
    auth: Optional[Tuple[str, str]] = None
) -> requests.Response:
    """
    Make an HTTP request with error handling.
    
    Args:
        url: URL to request
        method: HTTP method (GET, POST, etc.)
        params: Query parameters
        data: Form data
        json_data: JSON data
        headers: HTTP headers
        cookies: Cookies
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        allow_redirects: Whether to follow redirects
        auth: Basic auth credentials (username, password)
        
    Returns:
        Response object
        
    Raises:
        RequestException: If an error occurs during the request
    """
    try:
        logger.debug(f"Making {method} request to {url}")
        
        # Default headers if none provided
        if headers is None:
            headers = {
                "User-Agent": "VXDF-Validate/0.1.0"
            }
        
        response = requests.request(
            method=method.upper(),
            url=url,
            params=params,
            data=data,
            json=json_data,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=allow_redirects,
            auth=auth
        )
        
        logger.debug(f"Received response: {response.status_code}")
        return response
    
    except Exception as e:
        logger.error(f"Error making request to {url}: {e}", exc_info=True)
        raise

def inject_payload_in_params(url: str, payload: str, param_name: Optional[str] = None) -> str:
    """
    Inject a payload into URL parameters.
    
    Args:
        url: URL to inject into
        payload: Payload to inject
        param_name: Name of parameter to inject into. If None, inject into all parameters.
        
    Returns:
        URL with injected payload
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query, keep_blank_values=True)
    
    # If no parameters exist, add one
    if not query_params:
        if param_name:
            query_params = {param_name: [payload]}
        else:
            query_params = {"id": [payload]}  # Default parameter name
    else:
        # Inject into specific parameter or all parameters
        if param_name:
            if param_name in query_params:
                query_params[param_name] = [payload]
            else:
                query_params[param_name] = [payload]
        else:
            # Inject into all parameters
            for key in query_params:
                query_params[key] = [payload]
    
    # Rebuild query string
    # We need to convert the lists to single values for urlencode
    flat_params = {}
    for key, values in query_params.items():
        flat_params[key] = values[0]
    
    new_query = urlencode(flat_params)
    
    # Rebuild URL
    new_url = urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        new_query,
        parsed_url.fragment
    ))
    
    return new_url

def inject_payload_in_body(data: Union[Dict[str, Any], str], payload: str, param_name: Optional[str] = None) -> Union[Dict[str, Any], str]:
    """
    Inject a payload into request body data.
    
    Args:
        data: Request body data (dict or string)
        payload: Payload to inject
        param_name: Name of parameter to inject into. If None, inject into all parameters.
        
    Returns:
        Data with injected payload
    """
    # Handle JSON data (dict)
    if isinstance(data, dict):
        if param_name:
            # Inject into specific parameter
            if param_name in data:
                data[param_name] = payload
            else:
                data[param_name] = payload  # Add parameter if it doesn't exist
        else:
            # Inject into all string values
            for key in data:
                if isinstance(data[key], str):
                    data[key] = payload
        
        return data
    
    # Handle form data (string)
    elif isinstance(data, str):
        # Parse as form data
        form_params = {}
        for param in data.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                form_params[key] = value
            else:
                form_params[param] = ""
        
        # Inject payload
        if param_name:
            if param_name in form_params:
                form_params[param_name] = payload
            else:
                form_params[param_name] = payload
        else:
            for key in form_params:
                form_params[key] = payload
        
        # Rebuild form data
        return urlencode(form_params)
    
    # If not a recognized format, return as is
    return data

def detect_xss_reflection(response: requests.Response, payload: str) -> bool:
    """
    Detect if an XSS payload is reflected in the response.
    
    Args:
        response: HTTP response
        payload: XSS payload to check for
        
    Returns:
        True if the payload is reflected, False otherwise
    """
    try:
        # Check in raw response
        if payload in response.text:
            logger.debug(f"XSS payload found directly in response: {payload}")
            return True
        
        # Check in parsed HTML to handle encoding
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for script tags
        for script in soup.find_all('script'):
            if script.string and payload in script.string:
                logger.debug(f"XSS payload found in script tag: {payload}")
                return True
        
        # Check for event handlers
        for tag in soup.find_all(True):
            for attr in tag.attrs:
                if isinstance(tag.attrs[attr], str) and attr.startswith('on') and payload in tag.attrs[attr]:
                    logger.debug(f"XSS payload found in event handler: {payload}")
                    return True
        
        # Check for payload in attributes
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and payload in value:
                    logger.debug(f"XSS payload found in attribute: {attr}={value}")
                    return True
        
        return False
    
    except Exception as e:
        logger.error(f"Error detecting XSS reflection: {e}", exc_info=True)
        return False

def detect_sql_error(response: requests.Response) -> bool:
    """
    Detect common SQL error messages in a response.
    
    Args:
        response: HTTP response
        
    Returns:
        True if SQL error is detected, False otherwise
    """
    error_patterns = [
        r'SQL syntax.*?MySQL',
        r'Warning.*?SQLite3::query',
        r'SQLite/JDBCDriver',
        r'SQLite\.Exception',
        r'System\.Data\.SQLite\.SQLiteException',
        r'Warning.*?mysql_',
        r'MySqlException',
        r'valid MySQL result',
        r'check the manual that corresponds to your (MySQL|MariaDB) server version',
        r'ORA-[0-9][0-9][0-9][0-9]',
        r'Oracle error',
        r'Oracle.*?Driver',
        r'Warning.*?pg_',
        r'valid PostgreSQL result',
        r'Npgsql\.',
        r'PG::SyntaxError:',
        r'org\.postgresql\.util\.PSQLException',
        r'ERROR:\s+syntax error at or near',
        r'ERROR: parser: parse error at or near',
        r'PostgreSQL.*?ERROR',
        r'Microsoft OLE DB Provider for SQL Server',
        r'ODBC SQL Server Driver',
        r'ODBC Driver \d+ for SQL Server',
        r'SQLServer JDBC Driver',
        r'macromedia\.jdbc\.sqlserver',
        r'com\.jnetdirect\.jsql',
        r'SQLServerException',
        r'Unclosed quotation mark after the character string',
        r'DB2 SQL error',
        r'SQLCODE',
        r'CLI Driver.*?DB2',
        r'DB2 SQL error',
        r'\bSQL Server\b.*?\bError\b',
        r'Data source rejected establishment of connection',
        r'You have an error in your SQL syntax',
        r'SQLite3::query',
        r'System\.Data\.SqlClient\.SqlException',
        r'Unclosed quotation mark after the character string',
        r'java\.sql\.SQLException',
        r'Syntax error or access violation',
        r'Unexpected end of command in statement',
        r'unterminated quoted string at or near',
        r'error in your SQL syntax',
        r'unexpected EOF while parsing'
    ]
    
    for pattern in error_patterns:
        if re.search(pattern, response.text, re.IGNORECASE):
            logger.debug(f"SQL error detected with pattern: {pattern}")
            return True
    
    return False

def detect_path_traversal_success(response: requests.Response, target_content: Optional[str] = None) -> bool:
    """
    Detect successful path traversal attack.
    
    Args:
        response: HTTP response
        target_content: Optional content to look for in the response
        
    Returns:
        True if path traversal appears successful, False otherwise
    """
    # Common file content patterns
    unix_patterns = [
        r'root:.*?:0:0:',  # /etc/passwd
        r'# User Database',
        r'nobody:.*?:99:99:',
        r'# /etc/hosts',
        r'127\.0\.0\.1\s+localhost',
        r'::1\s+localhost',
        r'# /etc/shadow',
        r'root:.*?:\d+:\d+:',
        r'\[boot loader\]',  # Windows boot.ini
        r'operating systems',
        r'timeout=\d+'
    ]
    
    # If specific content is provided, check for it
    if target_content:
        if target_content in response.text:
            logger.debug(f"Path traversal successful, found target content: {target_content[:50]}")
            return True
    
    # Check for common file content patterns
    for pattern in unix_patterns:
        if re.search(pattern, response.text):
            logger.debug(f"Path traversal successful, matched pattern: {pattern}")
            return True
    
    # Check for suspiciously successful responses
    if (response.status_code == 200 and 
        (len(response.text) > 0) and
        ('file not found' not in response.text.lower()) and
        ('not found' not in response.text.lower()) and
        ('error' not in response.text.lower())):
        # This is a heuristic - a 200 response with content that doesn't contain error messages
        # might indicate success, but could also be a false positive
        return True
    
    return False

def detect_command_injection_success(response: requests.Response, payload: str) -> bool:
    """
    Detect successful command injection attack.
    
    Args:
        response: HTTP response
        payload: Command injection payload
        
    Returns:
        True if command injection appears successful, False otherwise
    """
    # Check for specific command output patterns based on the payload
    if ';id' in payload or '|id' in payload or '$(id)' in payload or '`id`' in payload:
        if re.search(r'uid=\d+\(.*?\) gid=\d+\(.*?\)', response.text):
            logger.debug("Command injection successful, found id command output")
            return True
    
    if ';whoami' in payload or '|whoami' in payload or '$(whoami)' in payload or '`whoami`' in payload:
        # Look for a username on a line by itself
        if re.search(r'^[a-z_][a-z0-9_-]{0,31}$', response.text, re.MULTILINE):
            logger.debug("Command injection successful, found whoami command output")
            return True
    
    if ';ls' in payload or '|ls' in payload or '$(ls)' in payload or '`ls`' in payload:
        # Look for directory listing patterns
        if re.search(r'total \d+', response.text) or re.search(r'drwx', response.text):
            logger.debug("Command injection successful, found ls command output")
            return True
    
    if ';echo' in payload:
        # Extract the echo string and check for it
        match = re.search(r';echo\s+([^\s;|&]+)', payload)
        if match and match.group(1) in response.text:
            logger.debug(f"Command injection successful, found echo output: {match.group(1)}")
            return True
    
    if '|echo' in payload:
        # Extract the echo string and check for it
        match = re.search(r'\|echo\s+([^\s;|&]+)', payload)
        if match and match.group(1) in response.text:
            logger.debug(f"Command injection successful, found echo output: {match.group(1)}")
            return True
    
    # Check for evidence of command joining
    if ';' in payload or '|' in payload or '&&' in payload:
        # If we see a dramatic change in response compared to normal
        # This is a heuristic and may need refinement
        if len(response.text) > 0 and response.status_code == 200:
            return True
    
    return False

def format_request_response(request: Optional[requests.PreparedRequest] = None, 
                           response: Optional[requests.Response] = None) -> str:
    """
    Format a request and response for logging or evidence.
    
    Args:
        request: HTTP request
        response: HTTP response
        
    Returns:
        Formatted request/response string
    """
    output = []
    
    # Add request information if available
    if request:
        output.append("===== HTTP Request =====")
        output.append(f"{request.method} {request.url}")
        for header, value in request.headers.items():
            output.append(f"{header}: {value}")
        
        if request.body:
            output.append("")
            if isinstance(request.body, bytes):
                try:
                    body = request.body.decode('utf-8')
                except UnicodeDecodeError:
                    body = f"[Binary data, {len(request.body)} bytes]"
            else:
                body = request.body
            
            output.append(body)
    
    # Add response information if available
    if response:
        output.append("\n===== HTTP Response =====")
        output.append(f"Status: {response.status_code} {response.reason}")
        for header, value in response.headers.items():
            output.append(f"{header}: {value}")
        
        output.append("")
        
        # Try to format JSON responses
        if 'application/json' in response.headers.get('Content-Type', ''):
            try:
                json_data = response.json()
                output.append(json.dumps(json_data, indent=2))
            except Exception:
                output.append(response.text[:2000])  # Limit large responses
        else:
            # Limit large responses to prevent memory issues
            if len(response.text) > 2000:
                output.append(response.text[:2000] + "... [truncated]")
            else:
                output.append(response.text)
    
    return "\n".join(output)
