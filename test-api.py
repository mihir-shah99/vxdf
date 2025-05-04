#!/usr/bin/env python3
"""
Test script for the VXDF API endpoints.
This script tests the integration between the frontend and backend by directly
calling the API endpoints and verifying the responses.
"""
import os
import sys
import json
import requests
from datetime import datetime


# Configuration
API_BASE_URL = "http://localhost:5001/api"
TEST_DATA_DIR = "test-data"


class Colors:
    """Terminal colors for test output."""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    BLUE = "\033[94m"


def print_section(title):
    """Print a section title."""
    print(f"\n{Colors.BLUE}{'=' * 80}")
    print(f" {title}")
    print(f"{'=' * 80}{Colors.RESET}\n")


def print_test(name, passed):
    """Print a test result."""
    status = f"{Colors.GREEN}PASSED{Colors.RESET}" if passed else f"{Colors.RED}FAILED{Colors.RESET}"
    print(f"  [TEST] {name}: {status}")


def print_warning(message):
    """Print a warning message."""
    print(f"  {Colors.YELLOW}[WARNING] {message}{Colors.RESET}")


def print_info(message):
    """Print an info message."""
    print(f"  [INFO] {message}")


def test_server_running():
    """Test if the server is running."""
    try:
        response = requests.get(f"{API_BASE_URL}/stats", timeout=5)
        return response.status_code == 200
    except requests.exceptions.ConnectionError:
        return False


def test_stats_endpoint():
    """Test the stats endpoint."""
    print_section("Testing Stats Endpoint")
    
    try:
        response = requests.get(f"{API_BASE_URL}/stats")
        response.raise_for_status()
        data = response.json()
        
        # Check if all required fields are present
        required_fields = ["total", "validated", "exploitable", "nonExploitable", "inProgress", 
                           "bySeverity", "byType", "recentFindings"]
        
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            print_test("Stats response format", False)
            print_warning(f"Missing fields in response: {', '.join(missing_fields)}")
        else:
            print_test("Stats response format", True)
            print_info(f"Total findings: {data['total']}")
            print_info(f"Validated findings: {data['validated']}")
            print_info(f"Exploitable findings: {data['exploitable']}")
            
        # Check severity breakdown
        if "bySeverity" in data:
            print_test("Severity breakdown present", True)
            for severity, count in data["bySeverity"].items():
                print_info(f"Severity {severity}: {count} findings")
        else:
            print_test("Severity breakdown present", False)
        
        # Check vulnerability type breakdown
        if "byType" in data:
            print_test("Vulnerability type breakdown present", True)
            for vuln_type, count in data["byType"].items():
                print_info(f"Type {vuln_type}: {count} findings")
        else:
            print_test("Vulnerability type breakdown present", False)
        
        # Check recent findings
        if "recentFindings" in data and isinstance(data["recentFindings"], list):
            print_test("Recent findings present", True)
            print_info(f"Found {len(data['recentFindings'])} recent findings")
        else:
            print_test("Recent findings present", False)
            
        return True
            
    except requests.exceptions.RequestException as e:
        print_test("Stats endpoint accessible", False)
        print_warning(f"Error: {str(e)}")
        return False


def test_vulnerabilities_endpoint():
    """Test the vulnerabilities endpoint."""
    print_section("Testing Vulnerabilities Endpoint")
    
    try:
        # Test basic endpoint
        response = requests.get(f"{API_BASE_URL}/vulnerabilities")
        response.raise_for_status()
        data = response.json()
        
        if "vulnerabilities" in data and "total" in data:
            print_test("Vulnerabilities response format", True)
            print_info(f"Total vulnerabilities: {data['total']}")
            print_info(f"Returned vulnerabilities: {len(data['vulnerabilities'])}")
        else:
            print_test("Vulnerabilities response format", False)
            return False
        
        # Test pagination
        if data["total"] > 0:
            response = requests.get(f"{API_BASE_URL}/vulnerabilities?limit=1")
            response.raise_for_status()
            data = response.json()
            
            if len(data["vulnerabilities"]) <= 1:
                print_test("Pagination limit parameter", True)
            else:
                print_test("Pagination limit parameter", False)
                print_warning(f"Expected at most 1 vulnerability, got {len(data['vulnerabilities'])}")
            
            # Test offset
            if data["total"] > 1:
                response = requests.get(f"{API_BASE_URL}/vulnerabilities?offset=1&limit=1")
                response.raise_for_status()
                data_offset = response.json()
                
                if data_offset["vulnerabilities"] and data_offset["vulnerabilities"] != data["vulnerabilities"]:
                    print_test("Pagination offset parameter", True)
                else:
                    print_test("Pagination offset parameter", False)
                    print_warning("Offset parameter did not change results")
        else:
            print_warning("Cannot test pagination parameters because there are no vulnerabilities")
        
        # Test filtering by category/type (if we have data)
        if data["total"] > 0 and data["vulnerabilities"]:
            category = data["vulnerabilities"][0].get("category")
            if category:
                response = requests.get(f"{API_BASE_URL}/vulnerabilities?category={category}")
                response.raise_for_status()
                data_filtered = response.json()
                
                if all(v.get("category") == category for v in data_filtered["vulnerabilities"]):
                    print_test("Category filtering", True)
                else:
                    print_test("Category filtering", False)
                    print_warning("Category filtering returned incorrect results")
            else:
                print_warning("Cannot test category filtering because category is not present in vulnerabilities")
        
        return True
        
    except requests.exceptions.RequestException as e:
        print_test("Vulnerabilities endpoint accessible", False)
        print_warning(f"Error: {str(e)}")
        return False


def test_vulnerability_details_endpoint():
    """Test the vulnerability details endpoint."""
    print_section("Testing Vulnerability Details Endpoint")
    
    try:
        # First get a list of vulnerabilities
        response = requests.get(f"{API_BASE_URL}/vulnerabilities")
        response.raise_for_status()
        data = response.json()
        
        if not data["vulnerabilities"]:
            print_warning("No vulnerabilities found to test details endpoint")
            return True
        
        # Get the first vulnerability ID
        vuln_id = data["vulnerabilities"][0]["id"]
        print_info(f"Testing details for vulnerability ID: {vuln_id}")
        
        # Get the vulnerability details
        response = requests.get(f"{API_BASE_URL}/vulnerabilities/{vuln_id}")
        response.raise_for_status()
        vuln_data = response.json()
        
        # Check if all required fields are present
        required_fields = ["id", "title", "category", "severity", "source", "sink"]
        missing_fields = [field for field in required_fields if field not in vuln_data]
        
        if missing_fields:
            print_test("Vulnerability details format", False)
            print_warning(f"Missing fields in response: {', '.join(missing_fields)}")
        else:
            print_test("Vulnerability details format", True)
        
        # Check source and sink
        if "source" in vuln_data and "file" in vuln_data["source"] and "line" in vuln_data["source"]:
            print_test("Source information present", True)
        else:
            print_test("Source information present", False)
            
        if "sink" in vuln_data and "file" in vuln_data["sink"] and "line" in vuln_data["sink"]:
            print_test("Sink information present", True)
        else:
            print_test("Sink information present", False)
        
        # Check evidence if available
        if "evidence" in vuln_data and vuln_data["evidence"]:
            print_test("Evidence information present", True)
            print_info(f"Found {len(vuln_data['evidence'])} evidence items")
        else:
            print_warning("No evidence information found")
        
        # Test non-existent vulnerability ID
        fake_id = "nonexistent-" + str(datetime.now().timestamp()).replace(".", "")
        response = requests.get(f"{API_BASE_URL}/vulnerabilities/{fake_id}")
        if response.status_code == 404:
            print_test("Non-existent vulnerability handling", True)
        else:
            print_test("Non-existent vulnerability handling", False)
            print_warning(f"Expected 404 status code, got {response.status_code}")
        
        return True
        
    except requests.exceptions.RequestException as e:
        print_test("Vulnerability details endpoint accessible", False)
        print_warning(f"Error: {str(e)}")
        return False


def test_supported_types_endpoint():
    """Test the supported types endpoint."""
    print_section("Testing Supported Types Endpoint")
    
    try:
        response = requests.get(f"{API_BASE_URL}/supported-types")
        response.raise_for_status()
        data = response.json()
        
        if "vulnerabilityTypes" in data and isinstance(data["vulnerabilityTypes"], list):
            print_test("Supported types response format", True)
            print_info(f"Supported vulnerability types: {', '.join(data['vulnerabilityTypes'])}")
            return True
        else:
            print_test("Supported types response format", False)
            print_warning("Response does not contain vulnerabilityTypes list")
            return False
        
    except requests.exceptions.RequestException as e:
        print_test("Supported types endpoint accessible", False)
        print_warning(f"Error: {str(e)}")
        return False


def test_file_upload_endpoint():
    """Test the file upload endpoint."""
    print_section("Testing File Upload Endpoint")
    
    sarif_file = os.path.join(TEST_DATA_DIR, "sample-sarif.json")
    
    if not os.path.exists(sarif_file):
        print_warning(f"Test file not found: {sarif_file}")
        return False
    
    try:
        print_info(f"Uploading test file: {sarif_file}")
        
        with open(sarif_file, "rb") as f:
            files = {"file": (os.path.basename(sarif_file), f, "application/json")}
            
            form_data = {
                "parser_type": "sarif",
                "validate": "true",
                "target_name": "Test Application",
                "min_severity": "LOW"
            }
            
            response = requests.post(
                f"{API_BASE_URL}/upload",
                files=files,
                data=form_data
            )
            
            response.raise_for_status()
            upload_result = response.json()
            
            if "success" in upload_result and upload_result["success"]:
                print_test("File upload successful", True)
                print_info(f"Message: {upload_result.get('message', 'No message')}")
                
                if "findings" in upload_result:
                    print_test("Findings in response", True)
                    print_info(f"Found {len(upload_result['findings'])} findings")
                    
                    # Print some details about the findings
                    for i, finding in enumerate(upload_result["findings"]):
                        print_info(f"Finding {i+1}: {finding.get('title', 'No title')} "
                                  f"({finding.get('severity', 'Unknown severity')})")
                else:
                    print_test("Findings in response", False)
                
                if "outputFile" in upload_result:
                    print_test("Output file generated", True)
                    print_info(f"Output file: {upload_result['outputFile']}")
                else:
                    print_test("Output file generated", False)
                
                return True
            else:
                print_test("File upload successful", False)
                print_warning(f"Upload failed: {upload_result.get('error', 'Unknown error')}")
                return False
            
    except requests.exceptions.RequestException as e:
        print_test("File upload endpoint accessible", False)
        print_warning(f"Error: {str(e)}")
        return False
    except Exception as e:
        print_test("File upload test", False)
        print_warning(f"Unexpected error: {str(e)}")
        return False


def main():
    """Main function to run all tests."""
    print_section("VXDF API Testing")
    
    # Make sure test data directory exists
    if not os.path.exists(TEST_DATA_DIR):
        os.makedirs(TEST_DATA_DIR)
        print_warning(f"Created test data directory: {TEST_DATA_DIR}")
    
    # Test if server is running
    if not test_server_running():
        print(f"{Colors.RED}ERROR: Server is not running at {API_BASE_URL}{Colors.RESET}")
        print("Please start the server before running this test script.")
        sys.exit(1)
    
    print(f"{Colors.GREEN}Server is running at {API_BASE_URL}{Colors.RESET}")
    
    # Run all tests
    tests_passed = 0
    tests_failed = 0
    
    test_funcs = [
        test_stats_endpoint,
        test_vulnerabilities_endpoint,
        test_vulnerability_details_endpoint,
        test_supported_types_endpoint,
        test_file_upload_endpoint
    ]
    
    for test_func in test_funcs:
        if test_func():
            tests_passed += 1
        else:
            tests_failed += 1
    
    # Print summary
    print_section("Test Summary")
    print(f"Tests passed: {Colors.GREEN}{tests_passed}{Colors.RESET}")
    print(f"Tests failed: {Colors.RED}{tests_failed}{Colors.RESET}")
    print(f"Total tests:  {tests_passed + tests_failed}")
    
    if tests_failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main() 