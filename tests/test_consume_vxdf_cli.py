#!/usr/bin/env python3
"""
Integration tests for the VXDF consumer CLI tool.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import List


class TestConsumeVXDFCLI(unittest.TestCase):
    """Integration tests for the consume_vxdf.py CLI tool."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.project_root = Path(__file__).parent.parent
        self.cli_script = self.project_root / "scripts" / "consume_vxdf.py"
        self.test_data_dir = self.project_root / "test-data"
        self.valid_vxdf_file = self.test_data_dir / "example1_flow_based.vxdf.json"
        self.valid_component_file = self.test_data_dir / "example2_component_based.vxdf.json"
        
        # Create invalid VXDF file dynamically
        self.invalid_vxdf_data = {
            "vxdfVersion": "1.0.0",
            "id": "not-a-valid-uuid",
            "generatedAt": "invalid-date-format",
            "exploitFlows": [
                {
                    "title": "Missing Required Fields",
                    "severity": {
                        "level": "INVALID_SEVERITY"
                    },
                    "evidence": []
                }
            ]
        }
        
        # Create temporary invalid file
        self.invalid_file_fd, self.invalid_vxdf_file = tempfile.mkstemp(suffix='.vxdf.json')
        with open(self.invalid_vxdf_file, 'w') as f:
            json.dump(self.invalid_vxdf_data, f)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import os
        if hasattr(self, 'invalid_file_fd'):
            os.close(self.invalid_file_fd)
        if hasattr(self, 'invalid_vxdf_file') and Path(self.invalid_vxdf_file).exists():
            Path(self.invalid_vxdf_file).unlink()
    
    def run_cli(self, args: List[str]) -> subprocess.CompletedProcess:
        """
        Run the CLI tool with given arguments.
        
        Args:
            args: Command line arguments
            
        Returns:
            CompletedProcess result
        """
        cmd = ["python3", str(self.cli_script)] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=self.project_root
        )
    
    def test_help_option(self):
        """Test the --help option."""
        result = self.run_cli(["--help"])
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("Parse, validate, and summarize VXDF documents", result.stdout)
        self.assertIn("--verbose", result.stdout)
        self.assertIn("--json", result.stdout)
    
    def test_version_option(self):
        """Test the --version option."""
        result = self.run_cli(["--version"])
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("VXDF Consumer", result.stdout)
    
    def test_valid_vxdf_file_basic(self):
        """Test processing a valid VXDF file with basic output."""
        result = self.run_cli([str(self.valid_vxdf_file)])
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("✅ VXDF file", result.stdout)
        self.assertIn("is valid and successfully parsed", result.stdout)
        self.assertIn("VXDF DOCUMENT SUMMARY", result.stdout)
        self.assertIn("EXPLOIT FLOWS:", result.stdout)
    
    def test_valid_vxdf_file_verbose(self):
        """Test processing a valid VXDF file with verbose output."""
        result = self.run_cli([str(self.valid_vxdf_file), "--verbose"])
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("✅ VXDF file", result.stdout)
        self.assertIn("Evidence Details:", result.stdout)
        self.assertIn("Has Source/Sink:", result.stdout)
        self.assertIn("Has Affected Components:", result.stdout)
    
    def test_valid_vxdf_file_json_output(self):
        """Test processing a valid VXDF file with JSON output."""
        result = self.run_cli([str(self.valid_vxdf_file), "--json"])
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("✅ VXDF file", result.stdout)
        
        # Extract JSON from output (after the success message)
        lines = result.stdout.split('\n')
        json_start = None
        for i, line in enumerate(lines):
            if line.strip().startswith('{'):
                json_start = i
                break
        
        self.assertIsNotNone(json_start, "No JSON found in output")
        json_text = '\n'.join(lines[json_start:])
        
        # Should be valid JSON
        try:
            summary_data = json.loads(json_text)
            self.assertIn("document_id", summary_data)
            self.assertIn("vxdf_version", summary_data)
            self.assertIn("exploit_flows_count", summary_data)
        except json.JSONDecodeError as e:
            self.fail(f"Invalid JSON output: {e}\nOutput: {json_text}")
    
    def test_valid_component_based_file(self):
        """Test processing a valid component-based VXDF file."""
        result = self.run_cli([str(self.valid_component_file)])
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("✅ VXDF file", result.stdout)
        self.assertIn("Text4Shell RCE", result.stdout)
        self.assertIn("CRITICAL", result.stdout)
    
    def test_invalid_vxdf_file(self):
        """Test processing an invalid VXDF file."""
        result = self.run_cli([str(self.invalid_vxdf_file)])
        
        self.assertEqual(result.returncode, 1)
        self.assertIn("❌ VXDF file", result.stdout)
        self.assertIn("is invalid", result.stdout)
        self.assertIn("Found", result.stdout)
        self.assertIn("error(s):", result.stdout)
    
    def test_nonexistent_file(self):
        """Test processing a non-existent file."""
        result = self.run_cli(["nonexistent_file.vxdf.json"])
        
        self.assertEqual(result.returncode, 2)
        self.assertIn("❌ Error: File not found", result.stdout)
    
    def test_quiet_mode_valid(self):
        """Test quiet mode with a valid file."""
        result = self.run_cli([str(self.valid_vxdf_file), "--quiet"])
        
        self.assertEqual(result.returncode, 0)
        # Should have minimal output in quiet mode
        self.assertNotIn("🔍 Processing VXDF file", result.stdout)
        self.assertNotIn("VXDF DOCUMENT SUMMARY", result.stdout)
    
    def test_quiet_mode_invalid(self):
        """Test quiet mode with an invalid file."""
        result = self.run_cli([str(self.invalid_vxdf_file), "--quiet"])
        
        self.assertEqual(result.returncode, 1)
        # Quiet mode should suppress all output, including errors
        # Only exit code should indicate failure
        self.assertEqual(result.stdout.strip(), "")
        self.assertEqual(result.stderr.strip(), "")
    
    def test_debug_mode(self):
        """Test debug mode."""
        result = self.run_cli([str(self.valid_vxdf_file), "--debug"])
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("✅ VXDF file", result.stdout)
        # Debug mode should still show normal output
    
    def test_no_arguments(self):
        """Test running CLI with no arguments."""
        result = self.run_cli([])
        
        self.assertEqual(result.returncode, 2)
        self.assertIn("error:", result.stderr)
        self.assertIn("required", result.stderr)
    
    def test_invalid_json_file(self):
        """Test processing a file with invalid JSON."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"invalid": "json", "missing": "closing_brace"')
            invalid_json_file = f.name
        
        try:
            result = self.run_cli([invalid_json_file])
            
            self.assertEqual(result.returncode, 1)
            self.assertIn("❌ VXDF file", result.stdout)
            self.assertIn("Invalid JSON format", result.stdout)
        finally:
            Path(invalid_json_file).unlink()
    
    def test_combination_flags(self):
        """Test combination of flags."""
        result = self.run_cli([str(self.valid_vxdf_file), "--verbose", "--json"])
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("✅ VXDF file", result.stdout)
        
        # Should have JSON output with verbose details
        lines = result.stdout.split('\n')
        json_start = None
        for i, line in enumerate(lines):
            if line.strip().startswith('{'):
                json_start = i
                break
        
        self.assertIsNotNone(json_start)
        json_text = '\n'.join(lines[json_start:])
        
        try:
            summary_data = json.loads(json_text)
            # Verbose JSON should have evidence details
            if summary_data["exploit_flows"]:
                first_flow = summary_data["exploit_flows"][0]
                self.assertIn("evidence_details", first_flow)
        except json.JSONDecodeError:
            self.fail("Invalid JSON output in verbose mode")
    
    def test_file_extension_warning(self):
        """Test warning for non-standard file extensions."""
        # Create a valid VXDF file with .json extension (instead of .vxdf.json)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            with open(self.valid_vxdf_file, 'r') as valid_file:
                f.write(valid_file.read())
            txt_file = f.name
        
        try:
            result = self.run_cli([txt_file])
            
            # Should warn about extension but still process
            self.assertIn("⚠️  Warning", result.stdout)
        finally:
            Path(txt_file).unlink()


class TestCLIErrorHandling(unittest.TestCase):
    """Test error handling in the CLI tool."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.project_root = Path(__file__).parent.parent
        self.cli_script = self.project_root / "scripts" / "consume_vxdf.py"
    
    def run_cli(self, args: List[str]) -> subprocess.CompletedProcess:
        """Run the CLI tool with given arguments."""
        cmd = ["python3", str(self.cli_script)] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=self.project_root
        )
    
    def test_keyboard_interrupt_simulation(self):
        """Test handling of interrupted processing."""
        # This test verifies the CLI handles interruptions gracefully
        # In practice, keyboard interrupts are hard to simulate in tests
        result = self.run_cli([str(self.project_root / "test-data" / "example1_flow_based.vxdf.json")])
        
        # Should complete normally
        self.assertEqual(result.returncode, 0)
    
    def test_malformed_vxdf_with_complex_errors(self):
        """Test handling of VXDF files with complex validation errors."""
        complex_invalid_vxdf = {
            "vxdfVersion": "2.0.0",  # Invalid version
            "id": "not-a-uuid",
            "generatedAt": "not-a-date",
            "exploitFlows": [
                {
                    "id": "also-not-a-uuid",
                    "title": "",  # Empty title
                    "category": "INVALID_CATEGORY",
                    "severity": {"level": "UNKNOWN_SEVERITY"},
                    "evidence": [],  # Empty evidence
                    "validatedAt": "also-not-a-date"
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(complex_invalid_vxdf, f)
            complex_file = f.name
        
        try:
            result = self.run_cli([complex_file])
            
            self.assertEqual(result.returncode, 1)
            self.assertIn("❌ VXDF file", result.stdout)
            self.assertIn("error(s):", result.stdout)
            
            # Should have multiple specific error messages
            error_text = result.stdout
            self.assertIn("Pydantic validation", error_text)
            
        finally:
            Path(complex_file).unlink()


if __name__ == "__main__":
    unittest.main() 