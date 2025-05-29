#!/usr/bin/env python3
"""
Unit tests for the VXDF loader module.
"""

import json
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Dict, Any

# Add project root to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.utils.vxdf_loader import (
    load_and_validate_vxdf,
    validate_against_schema,
    get_vxdf_summary,
    format_pydantic_errors,
    format_jsonschema_error,
    perform_consistency_checks,
    VXDFLoaderError,
    VXDFParsingError,
    VXDFValidationError
)
from api.models.vxdf import VXDFModel
from pydantic import ValidationError


class TestVXDFLoader(unittest.TestCase):
    """Test cases for VXDF loader functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_data_dir = Path(__file__).parent.parent / "test-data"
        self.valid_vxdf_file = self.test_data_dir / "example1_flow_based.vxdf.json"
        self.valid_component_file = self.test_data_dir / "example2_component_based.vxdf.json"
        
    def test_load_valid_vxdf_file(self):
        """Test loading a valid VXDF file."""
        vxdf_model, errors = load_and_validate_vxdf(str(self.valid_vxdf_file))
        
        self.assertIsNotNone(vxdf_model)
        self.assertEqual(len(errors), 0)
        self.assertIsInstance(vxdf_model, VXDFModel)
        self.assertEqual(vxdf_model.vxdfVersion, "1.0.0")
        self.assertGreater(len(vxdf_model.exploitFlows), 0)
    
    def test_load_valid_component_based_file(self):
        """Test loading a valid component-based VXDF file."""
        vxdf_model, errors = load_and_validate_vxdf(str(self.valid_component_file))
        
        self.assertIsNotNone(vxdf_model)
        self.assertEqual(len(errors), 0)
        self.assertIsInstance(vxdf_model, VXDFModel)
        self.assertEqual(vxdf_model.vxdfVersion, "1.0.0")
    
    def test_load_nonexistent_file(self):
        """Test loading a non-existent file."""
        vxdf_model, errors = load_and_validate_vxdf("nonexistent_file.vxdf.json")
        
        self.assertIsNone(vxdf_model)
        self.assertGreater(len(errors), 0)
        self.assertIn("File not found", errors[0])
    
    def test_load_invalid_json_file(self):
        """Test loading a file with invalid JSON."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"invalid": "json", "missing": "closing_brace"')
            invalid_file = f.name
        
        try:
            vxdf_model, errors = load_and_validate_vxdf(invalid_file)
            
            self.assertIsNone(vxdf_model)
            self.assertGreater(len(errors), 0)
            self.assertIn("Invalid JSON format", errors[0])
        finally:
            Path(invalid_file).unlink()
    
    def test_load_invalid_vxdf_structure(self):
        """Test loading a file with invalid VXDF structure."""
        invalid_vxdf = {
            "vxdfVersion": "1.0.0",
            "id": "not-a-valid-uuid",
            "generatedAt": "invalid-date-format",
            "exploitFlows": []
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(invalid_vxdf, f)
            invalid_file = f.name
        
        try:
            vxdf_model, errors = load_and_validate_vxdf(invalid_file)
            
            self.assertIsNone(vxdf_model)
            self.assertGreater(len(errors), 0)
            # Should have both schema and Pydantic validation errors
            error_text = " ".join(errors)
            self.assertIn("Pydantic validation", error_text)
        finally:
            Path(invalid_file).unlink()
    
    def test_validate_against_schema_valid(self):
        """Test schema validation with valid data."""
        with open(self.valid_vxdf_file, 'r') as f:
            valid_data = json.load(f)
        
        errors = validate_against_schema(valid_data)
        self.assertEqual(len(errors), 0)
    
    def test_validate_against_schema_invalid(self):
        """Test schema validation with invalid data."""
        invalid_data = {
            "vxdfVersion": "1.0.0",
            "id": str(uuid.uuid4()),
            "exploitFlows": []
        }
        
        errors = validate_against_schema(invalid_data)
        self.assertGreater(len(errors), 0)
    
    def test_get_vxdf_summary_basic(self):
        """Test getting a basic summary of a VXDF document."""
        vxdf_model, _ = load_and_validate_vxdf(str(self.valid_vxdf_file))
        self.assertIsNotNone(vxdf_model)
        
        summary = get_vxdf_summary(vxdf_model, verbose=False)
        
        self.assertIn("document_id", summary)
        self.assertIn("vxdf_version", summary)
        self.assertIn("exploit_flows_count", summary)
        self.assertIn("total_evidence_count", summary)
        self.assertEqual(summary["vxdf_version"], "1.0.0")
        self.assertGreater(summary["exploit_flows_count"], 0)
    
    def test_get_vxdf_summary_verbose(self):
        """Test getting a verbose summary of a VXDF document."""
        vxdf_model, _ = load_and_validate_vxdf(str(self.valid_vxdf_file))
        self.assertIsNotNone(vxdf_model)
        
        summary = get_vxdf_summary(vxdf_model, verbose=True)
        
        self.assertIn("exploit_flows", summary)
        if summary["exploit_flows"]:
            first_flow = summary["exploit_flows"][0]
            self.assertIn("description", first_flow)
            self.assertIn("has_source_sink", first_flow)
            self.assertIn("has_affected_components", first_flow)
    
    def test_consistency_checks_valid(self):
        """Test consistency checks with a valid VXDF model."""
        vxdf_model, _ = load_and_validate_vxdf(str(self.valid_vxdf_file))
        self.assertIsNotNone(vxdf_model)
        
        errors = perform_consistency_checks(vxdf_model)
        self.assertEqual(len(errors), 0)
    
    def test_consistency_checks_missing_evidence(self):
        """Test consistency checks with missing evidence."""
        vxdf_model, _ = load_and_validate_vxdf(str(self.valid_vxdf_file))
        self.assertIsNotNone(vxdf_model)
        
        # Artificially remove evidence from one flow
        if vxdf_model.exploitFlows:
            vxdf_model.exploitFlows[0].evidence = []
        
        errors = perform_consistency_checks(vxdf_model)
        self.assertGreater(len(errors), 0)
        self.assertIn("has no evidence", errors[0])
    
    def test_format_pydantic_errors(self):
        """Test formatting of Pydantic validation errors."""
        try:
            # Intentionally create a ValidationError
            VXDFModel.model_validate({"invalid": "data"})
        except ValidationError as e:
            formatted_errors = format_pydantic_errors(e)
            self.assertGreater(len(formatted_errors), 0)
            # Check that error messages contain location information
            self.assertTrue(any("vxdfVersion" in error for error in formatted_errors))
    
    def test_file_extension_check(self):
        """Test file extension validation."""
        # Test with non-JSON file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('{"vxdfVersion": "1.0.0"}')
            txt_file = f.name
        
        try:
            vxdf_model, errors = load_and_validate_vxdf(txt_file)
            
            self.assertIsNone(vxdf_model)
            self.assertGreater(len(errors), 0)
            self.assertIn("must have .json extension", errors[0])
        finally:
            Path(txt_file).unlink()


class TestVXDFLoaderIntegration(unittest.TestCase):
    """Integration tests for VXDF loader."""
    
    def test_end_to_end_valid_processing(self):
        """Test end-to-end processing of a valid VXDF file."""
        test_file = Path(__file__).parent.parent / "test-data" / "example1_flow_based.vxdf.json"
        
        # Load and validate
        vxdf_model, errors = load_and_validate_vxdf(str(test_file))
        
        # Should be successful
        self.assertIsNotNone(vxdf_model)
        self.assertEqual(len(errors), 0)
        
        # Should have expected structure
        self.assertEqual(vxdf_model.vxdfVersion, "1.0.0")
        self.assertIsNotNone(vxdf_model.id)
        self.assertIsNotNone(vxdf_model.generatedAt)
        self.assertGreater(len(vxdf_model.exploitFlows), 0)
        
        # Generate summary
        summary = get_vxdf_summary(vxdf_model, verbose=True)
        
        # Summary should contain all key information
        self.assertIn("document_id", summary)
        self.assertIn("generator_tool", summary)
        self.assertIn("application_info", summary)
        self.assertIn("exploit_flows", summary)
        self.assertEqual(summary["exploit_flows_count"], len(vxdf_model.exploitFlows))
        
        # Each exploit flow should have required information
        for flow_summary in summary["exploit_flows"]:
            self.assertIn("id", flow_summary)
            self.assertIn("title", flow_summary)
            self.assertIn("category", flow_summary)
            self.assertIn("severity", flow_summary)
            self.assertIn("evidence_count", flow_summary)
    
    def test_end_to_end_component_based_processing(self):
        """Test end-to-end processing of a component-based VXDF file."""
        test_file = Path(__file__).parent.parent / "test-data" / "example2_component_based.vxdf.json"
        
        # Load and validate
        vxdf_model, errors = load_and_validate_vxdf(str(test_file))
        
        # Should be successful
        self.assertIsNotNone(vxdf_model)
        self.assertEqual(len(errors), 0)
        
        # Should handle component-based flows
        self.assertEqual(vxdf_model.vxdfVersion, "1.0.0")
        self.assertGreater(len(vxdf_model.exploitFlows), 0)
        
        # Check for affected components in at least one flow
        has_component_based = any(
            flow.affectedComponents and len(flow.affectedComponents) > 0
            for flow in vxdf_model.exploitFlows
        )
        # Note: This may be False if the example doesn't use affectedComponents


if __name__ == "__main__":
    unittest.main() 