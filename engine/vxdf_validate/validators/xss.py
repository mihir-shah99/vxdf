"""
Validator for Cross-Site Scripting (XSS) vulnerabilities.
"""
import logging
import json
import uuid
import re
import tempfile
import os
from typing import List, Dict, Any, Optional, Tuple

from vxdf_validate.core.validator import Validator, ValidationResult
from vxdf_validate.models.finding import Finding
from vxdf_validate.utils.docker_utils import DockerEnvironment
from vxdf_validate.utils.http_utils import (
    make_request, inject_payload_in_params, 
    inject_payload_in_body, detect_xss_reflection,
    format_request_response
)

logger = logging.getLogger(__name__)

class XSSValidator(Validator):
    """
    Validator for Cross-Site Scripting (XSS) vulnerabilities.
    """
    
    def __init__(self):
        """
        Initialize the XSS validator.
        """
        super().__init__()
        self.name = "XSS Validator"
        self.payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "<div style=\"background-image: url(javascript:alert(1))\">",
            "<iframe src=\"javascript:alert(1)\"></iframe>",
            "<input type=\"text\" onfocus=\"alert(1)\" autofocus>",
            "<a href=\"javascript:alert(1)\">Click me</a>",
            "'-alert(1)-'",
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>"
        ]
        self.docker_env = None
    
    def validate(self, finding: Finding) -> ValidationResult:
        """
        Validate XSS vulnerability.
        
        Args:
            finding: The finding to validate
            
        Returns:
            ValidationResult with details of validation
        """
        logger.info(f"Validating XSS vulnerability: {finding.id}")
        
        # Strategy depends on finding type (SAST, DAST, etc.)
        if finding.source_type == "DAST-ZAP" or finding.source_type == "DAST-Burp" or finding.source_type == "DAST-Generic":
            return self._validate_dast_finding(finding)
        else:
            # Default to SAST validation
            return self._validate_sast_finding(finding)
    
    def _validate_dast_finding(self, finding: Finding) -> ValidationResult:
        """
        Validate XSS from DAST findings by replaying requests.
        
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
                message="Could not extract URL from finding to validate XSS"
            )
        
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
                    
                    # Check if payload is reflected in response
                    if detect_xss_reflection(response, payload):
                        successful_payloads.append(payload)
                        
                        # Create evidence
                        evidence_item = {
                            "type": "http_request",
                            "description": f"XSS payload reflection: {payload}",
                            "content": format_request_response(response.request, response)
                        }
                        evidence.append(evidence_item)
                
                except Exception as e:
                    logger.warning(f"Error testing XSS payload: {e}")
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
                    
                    # Check if payload is reflected in response
                    if detect_xss_reflection(response, payload):
                        successful_payloads.append(payload)
                        
                        # Create evidence
                        evidence_item = {
                            "type": "http_request",
                            "description": f"XSS payload reflection: {payload}",
                            "content": format_request_response(response.request, response)
                        }
                        evidence.append(evidence_item)
                
                except Exception as e:
                    logger.warning(f"Error testing XSS payload: {e}")
                    continue
        
        # Determine if exploitable
        is_exploitable = len(successful_payloads) > 0
        
        if is_exploitable:
            message = f"Confirmed XSS vulnerability. {len(successful_payloads)} payloads were successfully reflected: {', '.join(successful_payloads[:3])}"
        else:
            message = "Could not confirm XSS vulnerability. No test payloads were reflected in the response."
        
        return ValidationResult(
            is_exploitable=is_exploitable,
            message=message,
            evidence=evidence
        )
    
    def _validate_sast_finding(self, finding: Finding) -> ValidationResult:
        """
        Validate XSS from SAST findings using Docker.
        
        Args:
            finding: The finding to validate
            
        Returns:
            ValidationResult with details of validation
        """
        # For SAST findings of XSS, we need to simulate a web application environment
        # This is a simplified approach - in a real-world scenario, we would set up a more sophisticated test
        
        # First check if we have file path and code to analyze
        if not finding.file_path:
            return ValidationResult(
                is_exploitable=False,
                message="No file path available in finding to validate XSS"
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
            self.docker_env.create_container(name_prefix="xss_validator_", ports={8080: 8080})
            
            # Install necessary packages
            self.docker_env.install_python_package("flask")
            self.docker_env.install_python_package("requests")
            self.docker_env.install_python_package("beautifulsoup4")
            
            # Create a test application based on the finding
            test_app_path = self._create_test_app(finding)
            
            if not test_app_path:
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to create test application for XSS validation"
                )
            
            # Copy the test app to the container
            if not self.docker_env.copy_to_container(test_app_path, "/tmp/test_xss_app.py"):
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to copy test application to Docker container"
                )
            
            # Create a test script to check for XSS
            test_script_path = self._create_test_script()
            
            if not test_script_path:
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to create test script for XSS validation"
                )
            
            # Copy the test script to the container
            if not self.docker_env.copy_to_container(test_script_path, "/tmp/test_xss.py"):
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to copy test script to Docker container"
                )
            
            # Start the test app in the background
            self.docker_env.execute_command("nohup python /tmp/test_xss_app.py > /tmp/app.log 2>&1 &")
            
            # Wait for the app to start
            self.docker_env.execute_command("sleep 2")
            
            # Execute the test script
            exit_code, stdout, stderr = self.docker_env.execute_command("python /tmp/test_xss.py")
            
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
                        "type": "xss_test",
                        "description": f"XSS test with payload: {test['payload']}",
                        "content": json.dumps(test, indent=2)
                    }
                    evidence.append(evidence_item)
                
                if is_exploitable:
                    message = f"Confirmed XSS vulnerability. {len(successful_payloads)} payloads were successfully reflected: {', '.join(successful_payloads[:3])}"
                else:
                    message = "Could not confirm XSS vulnerability. No test payloads were reflected in the response."
                
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
        Create a Flask application for testing XSS.
        
        Args:
            finding: The finding to validate
            
        Returns:
            Path to the created application, or None if failed
        """
        try:
            # Create a temporary file
            fd, path = tempfile.mkstemp(suffix=".py", prefix="xss_test_app_")
            
            # Generate application code
            code = """
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    return '''
        <html>
            <head><title>XSS Test</title></head>
            <body>
                <h1>XSS Test Application</h1>
                <form action="/echo" method="GET">
                    <input type="text" name="input" placeholder="Enter some text">
                    <button type="submit">Submit</button>
                </form>
                <form action="/echo_post" method="POST">
                    <input type="text" name="input" placeholder="Enter some text">
                    <button type="submit">Submit (POST)</button>
                </form>
            </body>
        </html>
    '''

@app.route('/echo')
def echo():
    # Vulnerable to XSS - directly echoes user input
    user_input = request.args.get('input', '')
    return '''
        <html>
            <head><title>XSS Test</title></head>
            <body>
                <h1>Echo Result</h1>
                <div>You entered: %s</div>
                <a href="/">Back</a>
            </body>
        </html>
    ''' % user_input

@app.route('/echo_post', methods=['POST'])
def echo_post():
    # Also vulnerable to XSS
    user_input = request.form.get('input', '')
    return '''
        <html>
            <head><title>XSS Test</title></head>
            <body>
                <h1>Echo Result (POST)</h1>
                <div>You entered: %s</div>
                <a href="/">Back</a>
            </body>
        </html>
    ''' % user_input

@app.route('/safe')
def safe():
    # Safe version - escapes user input
    user_input = request.args.get('input', '')
    # Escape HTML special characters
    user_input = user_input.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return '''
        <html>
            <head><title>XSS Test</title></head>
            <body>
                <h1>Safe Echo Result</h1>
                <div>You entered: %s</div>
                <a href="/">Back</a>
            </body>
        </html>
    ''' % user_input

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
        Create a Python script to test for XSS.
        
        Returns:
            Path to the created script, or None if failed
        """
        try:
            # Create a temporary file
            fd, path = tempfile.mkstemp(suffix=".py", prefix="xss_test_")
            
            # Generate test code
            code = """
import requests
import json
import re
from bs4 import BeautifulSoup

# Test server
SERVER_URL = "http://localhost:8080"

# Payloads to test
PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "<div style=\\"background-image: url(javascript:alert(1))\\">",
    "<iframe src=\\"javascript:alert(1)\\"></iframe>",
    "<input type=\\"text\\" onfocus=\\"alert(1)\\" autofocus>",
    "<a href=\\"javascript:alert(1)\\">Click me</a>",
    "'-alert(1)-'",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script>alert(String.fromCharCode(88,83,83))</script>"
]

def detect_xss_reflection(response_text, payload):
    """Detect if a payload is reflected in the response."""
    # Check in raw response
    if payload in response_text:
        return True
    
    # Check in parsed HTML
    soup = BeautifulSoup(response_text, 'html.parser')
    
    # Check for script tags
    for script in soup.find_all('script'):
        if script.string and payload in script.string:
            return True
    
    # Check for event handlers
    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if isinstance(tag.attrs[attr], str) and attr.startswith('on') and payload in tag.attrs[attr]:
                return True
    
    # Check for payload in attributes
    for tag in soup.find_all(True):
        for attr, value in tag.attrs.items():
            if isinstance(value, str) and payload in value:
                return True
    
    return False

def test_xss():
    """Test XSS payloads."""
    results = {
        "is_exploitable": False,
        "successful_payloads": [],
        "tests": []
    }
    
    # Endpoints to test
    endpoints = [
        # Vulnerable endpoint (GET)
        {"url": SERVER_URL + "/echo", "method": "GET", "param": "input"},
        # Vulnerable endpoint (POST)
        {"url": SERVER_URL + "/echo_post", "method": "POST", "param": "input"},
        # Safe endpoint
        {"url": SERVER_URL + "/safe", "method": "GET", "param": "input"}
    ]
    
    for endpoint in endpoints:
        url = endpoint["url"]
        method = endpoint["method"]
        param = endpoint["param"]
        
        # First test with safe value
        safe_value = "Hello World"
        safe_params = {param: safe_value} if method == "GET" else None
        safe_data = {param: safe_value} if method == "POST" else None
        
        try:
            safe_response = requests.request(method, url, params=safe_params, data=safe_data, timeout=5)
            safe_reflected = safe_value in safe_response.text
            
            safe_test = {
                "endpoint": url,
                "method": method,
                "parameter": param,
                "payload": safe_value,
                "reflected": safe_reflected,
                "status_code": safe_response.status_code
            }
            
            results["tests"].append(safe_test)
            
            # Now test with XSS payloads
            for payload in PAYLOADS:
                xss_params = {param: payload} if method == "GET" else None
                xss_data = {param: payload} if method == "POST" else None
                
                try:
                    xss_response = requests.request(method, url, params=xss_params, data=xss_data, timeout=5)
                    is_reflected = detect_xss_reflection(xss_response.text, payload)
                    
                    test_result = {
                        "endpoint": url,
                        "method": method,
                        "parameter": param,
                        "payload": payload,
                        "reflected": is_reflected,
                        "status_code": xss_response.status_code
                    }
                    
                    results["tests"].append(test_result)
                    
                    # If reflected, mark as exploitable
                    if is_reflected and not url.endswith("/safe"):  # Exclude the safe endpoint
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
    results = test_xss()
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
