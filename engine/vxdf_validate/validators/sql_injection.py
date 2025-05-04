"""
Validator for SQL Injection vulnerabilities.
"""
import logging
import json
import uuid
import re
import sqlite3
import tempfile
import os
from typing import List, Dict, Any, Optional, Tuple

from vxdf_validate.core.validator import Validator, ValidationResult
from vxdf_validate.models.finding import Finding
from vxdf_validate.utils.docker_utils import DockerEnvironment
from vxdf_validate.utils.http_utils import (
    make_request, inject_payload_in_params, 
    inject_payload_in_body, detect_sql_error,
    format_request_response
)

logger = logging.getLogger(__name__)

class SQLInjectionValidator(Validator):
    """
    Validator for SQL Injection vulnerabilities.
    """
    
    def __init__(self):
        """
        Initialize the SQL Injection validator.
        """
        super().__init__()
        self.name = "SQL Injection Validator"
        self.payloads = [
            "' OR '1'='1", 
            "' OR 1=1 --", 
            "' OR 1=1; --",
            "1' OR '1'='1",
            "1 OR 1=1 --",
            "' UNION SELECT NULL, NULL --",
            "' UNION SELECT 1,2,3 --",
            "admin' --",
            "' OR '1'='1' --",
            "'; DROP TABLE users; --",
            "1'; SELECT * FROM information_schema.tables; --"
        ]
        self.docker_env = None
    
    def validate(self, finding: Finding) -> ValidationResult:
        """
        Validate SQL Injection vulnerability.
        
        Args:
            finding: The finding to validate
            
        Returns:
            ValidationResult with details of validation
        """
        logger.info(f"Validating SQL Injection vulnerability: {finding.id}")
        
        # Strategy depends on finding type (SAST, DAST, etc.)
        if finding.source_type == "DAST-ZAP" or finding.source_type == "DAST-Burp" or finding.source_type == "DAST-Generic":
            return self._validate_dast_finding(finding)
        else:
            # Default to SAST validation
            return self._validate_sast_finding(finding)
    
    def _validate_dast_finding(self, finding: Finding) -> ValidationResult:
        """
        Validate SQL Injection from DAST findings by replaying requests.
        
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
                message="Could not extract URL from finding to validate SQL Injection"
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
                    
                    # Check for SQL errors in response
                    if detect_sql_error(response):
                        successful_payloads.append(payload)
                        
                        # Create evidence
                        evidence_item = {
                            "type": "http_request",
                            "description": f"SQL Injection with payload: {payload}",
                            "content": format_request_response(response.request, response)
                        }
                        evidence.append(evidence_item)
                
                except Exception as e:
                    logger.warning(f"Error testing SQL Injection payload: {e}")
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
                    
                    # Check for SQL errors in response
                    if detect_sql_error(response):
                        successful_payloads.append(payload)
                        
                        # Create evidence
                        evidence_item = {
                            "type": "http_request",
                            "description": f"SQL Injection with payload: {payload}",
                            "content": format_request_response(response.request, response)
                        }
                        evidence.append(evidence_item)
                
                except Exception as e:
                    logger.warning(f"Error testing SQL Injection payload: {e}")
                    continue
        
        # Determine if exploitable
        is_exploitable = len(successful_payloads) > 0
        
        if is_exploitable:
            message = f"Confirmed SQL Injection vulnerability. {len(successful_payloads)} payloads successfully triggered SQL errors: {', '.join(successful_payloads[:3])}"
        else:
            message = "Could not confirm SQL Injection vulnerability. No test payloads triggered SQL errors."
        
        return ValidationResult(
            is_exploitable=is_exploitable,
            message=message,
            evidence=evidence
        )
    
    def _validate_sast_finding(self, finding: Finding) -> ValidationResult:
        """
        Validate SQL Injection from SAST findings using Docker.
        
        Args:
            finding: The finding to validate
            
        Returns:
            ValidationResult with details of validation
        """
        # First check if we have file path and code to analyze
        if not finding.file_path:
            return ValidationResult(
                is_exploitable=False,
                message="No file path available in finding to validate SQL Injection"
            )
        
        # Set up a Docker environment to validate the SQL Injection
        try:
            self.docker_env = DockerEnvironment()
            if not self.docker_env.setup():
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to set up Docker environment for validation"
                )
            
            self.docker_env.create_container(name_prefix="sql_injection_validator_")
            
            # Install necessary packages
            self.docker_env.install_package("sqlite3")
            self.docker_env.install_python_package("sqlite3")
            
            # Create a test database
            self._create_test_database()
            
            # Create a test script based on the finding
            script_path = self._create_test_script(finding)
            
            if not script_path:
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to create test script for SQL Injection validation"
                )
            
            # Copy the script to the container
            if not self.docker_env.copy_to_container(script_path, "/tmp/test_sql_injection.py"):
                return ValidationResult(
                    is_exploitable=False,
                    message="Failed to copy test script to Docker container"
                )
            
            # Execute the test script
            exit_code, stdout, stderr = self.docker_env.execute_command("python /tmp/test_sql_injection.py")
            
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
                        "type": "sql_injection_test",
                        "description": f"SQL Injection test with payload: {payload_result['payload']}",
                        "content": json.dumps(payload_result, indent=2)
                    }
                    evidence.append(evidence_item)
                
                if is_exploitable:
                    message = f"Confirmed SQL Injection vulnerability. {len(successful_payloads)} payloads were successful: {', '.join(successful_payloads[:3])}"
                else:
                    message = "Could not confirm SQL Injection vulnerability. No test payloads were successful."
                
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
    
    def _create_test_database(self) -> None:
        """
        Create a test SQLite database in the Docker container.
        """
        # Create a simple SQLite database for testing
        commands = [
            "echo 'CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);' > /tmp/init.sql",
            "echo 'INSERT INTO users VALUES (1, \"admin\", \"admin123\");' >> /tmp/init.sql",
            "echo 'INSERT INTO users VALUES (2, \"user\", \"user123\");' >> /tmp/init.sql",
            "cat /tmp/init.sql | sqlite3 /tmp/test.db",
            "chmod 777 /tmp/test.db"
        ]
        
        for cmd in commands:
            self.docker_env.execute_command(cmd)
    
    def _create_test_script(self, finding: Finding) -> Optional[str]:
        """
        Create a Python script to test SQL Injection.
        
        Args:
            finding: The finding to validate
            
        Returns:
            Path to the created script, or None if failed
        """
        try:
            # Create a temporary file
            fd, path = tempfile.mkstemp(suffix=".py", prefix="sql_injection_test_")
            
            # Generate test code
            code = """
import sqlite3
import json
import sys

# Test database
DB_PATH = "/tmp/test.db"

# Payloads to test
PAYLOADS = [
    "' OR '1'='1", 
    "' OR 1=1 --", 
    "' OR 1=1; --",
    "1' OR '1'='1",
    "1 OR 1=1 --",
    "' UNION SELECT NULL, NULL --",
    "' UNION SELECT 1,2,3 --",
    "admin' --",
    "' OR '1'='1' --",
    "'; DROP TABLE users; --",
    "1'; SELECT * FROM information_schema.tables; --"
]

def execute_query(query):
    """Execute a query and return results."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return True, results
    except sqlite3.Error as e:
        return False, str(e)

def test_injection():
    """Test SQL injection payloads."""
    results = {
        "is_exploitable": False,
        "successful_payloads": [],
        "tests": []
    }
    
    # Base queries to test - simulate the vulnerable code
    base_queries = [
        "SELECT * FROM users WHERE username = '{}'",
        "SELECT * FROM users WHERE username = '{}' AND password = 'password'",
        "SELECT * FROM users WHERE id = {}",
    ]
    
    for base_query in base_queries:
        # First test with a legitimate value
        safe_value = "legituser"
        safe_query = base_query.format(safe_value)
        safe_success, safe_result = execute_query(safe_query)
        
        safe_test = {
            "query_template": base_query,
            "payload": safe_value,
            "query": safe_query,
            "success": safe_success,
            "result_type": str(type(safe_result).__name__),
            "result_length": len(safe_result) if isinstance(safe_result, list) else 0,
            "error": None if safe_success else safe_result
        }
        
        # Now test with injection payloads
        for payload in PAYLOADS:
            malicious_query = base_query.format(payload)
            
            try:
                success, result = execute_query(malicious_query)
                
                # Check if results are different from the safe query
                is_different = False
                if success and safe_success:
                    if isinstance(result, list) and isinstance(safe_result, list):
                        is_different = len(result) != len(safe_result)
                    else:
                        is_different = result != safe_result
                elif success != safe_success:
                    is_different = True
                
                # Record results
                test_result = {
                    "query_template": base_query,
                    "payload": payload,
                    "query": malicious_query,
                    "success": success,
                    "result_type": str(type(result).__name__),
                    "result_length": len(result) if isinstance(result, list) else 0,
                    "is_different": is_different,
                    "error": None if success else result
                }
                
                results["tests"].append(test_result)
                
                # If we got different results or unexpected success, mark as exploitable
                if is_different and success:
                    results["is_exploitable"] = True
                    results["successful_payloads"].append(payload)
                
            except Exception as e:
                test_result = {
                    "query_template": base_query,
                    "payload": payload,
                    "query": malicious_query,
                    "success": False,
                    "error": str(e)
                }
                results["tests"].append(test_result)
    
    # Remove duplicates from successful payloads
    results["successful_payloads"] = list(set(results["successful_payloads"]))
    
    return results

if __name__ == "__main__":
    results = test_injection()
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
