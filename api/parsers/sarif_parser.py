"""
Parser for SARIF (Static Analysis Results Interchange Format) files.
"""
import json
import logging
import os
from typing import List, Dict, Any, Optional
from pathlib import Path

# Remove the sarif_om import as we'll parse the JSON directly
# from sarif_om import SarifLog  # type: ignore

from api.models.finding import Finding
from api.config import CWE_TO_VULN_TYPE, SEVERITY_THRESHOLDS

logger = logging.getLogger(__name__)

class SarifParser:
    """
    Parser for SARIF (Static Analysis Results Interchange Format) files.
    """
    
    def __init__(self, base_path: Optional[str] = None):
        """
        Initialize the SARIF parser.
        
        Args:
            base_path: Base path for resolving relative file paths in SARIF
        """
        self.base_path = base_path
    
    def parse_file(self, file_path: str) -> List[Finding]:
        """
        Parse a SARIF file and extract security findings.
        
        Args:
            file_path: Path to the SARIF file
            
        Returns:
            List of Finding objects
        """
        logger.info(f"Parsing SARIF file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)
            
            findings = []
            # Process each run in the SARIF file
            for run in sarif_data.get('runs', []):
                tool_name = run.get('tool', {}).get('driver', {}).get('name', "Unknown Tool")
                logger.debug(f"Processing run from tool: {tool_name}")
                
                results = run.get('results', [])
                if not results:
                    logger.info(f"No results found in run from {tool_name}")
                    continue
                
                for result in results:
                    # Skip informational or non-security findings
                    if not result.get('ruleId') or not self._is_security_finding(result):
                        continue
                    
                    finding = self._convert_to_finding(result, run, tool_name)
                    if finding:
                        findings.append(finding)
            
            logger.info(f"Extracted {len(findings)} security findings from SARIF file")
            return findings
        
        except Exception as e:
            logger.error(f"Error parsing SARIF file: {e}", exc_info=True)
            raise
    
    def _convert_to_finding(self, result: Dict[str, Any], run: Dict[str, Any], tool_name: str) -> Optional[Finding]:
        """
        Convert a SARIF result to a Finding object.
        
        Args:
            result: SARIF result object
            run: SARIF run object
            tool_name: Name of the tool that generated the result
            
        Returns:
            Finding object or None if the result should be skipped
        """
        try:
            # Get rule metadata
            rule = self._get_rule_metadata(result.get('ruleId', ''), run)
            
            # Extract vulnerability type from rule or tags
            vuln_type = self._determine_vulnerability_type(result, rule)
            if not vuln_type:
                logger.debug(f"Skipping finding with rule ID {result.get('ruleId', '')}: Unknown vulnerability type")
                return None
            
            # Extract code location
            location_info = self._extract_location(result)
            if not location_info:
                logger.debug(f"Skipping finding with rule ID {result.get('ruleId', '')}: No location information")
                return None
            
            # Extract severity
            severity, cvss_score = self._extract_severity(result, rule)
            
            # Extract CWE ID
            cwe_id = self._extract_cwe_id(rule)
            
            # Create finding
            finding = Finding(
                source_id=result.get('id') or result.get('ruleId', ''),
                source_type="SARIF",
                vulnerability_type=vuln_type,
                name=rule.get('name', result.get('ruleId', '')),
                description=rule.get('description', ''),
                severity=severity,
                cvss_score=cvss_score,
                cwe_id=cwe_id,
                file_path=location_info.get('file_path'),
                line_number=location_info.get('line_number'),
                column=location_info.get('column'),
                raw_data=self._get_raw_data(result)
            )
            
            return finding
        
        except Exception as e:
            logger.error(f"Error converting SARIF result to finding: {e}", exc_info=True)
            return None
    
    def _get_rule_metadata(self, rule_id: str, run: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get metadata for a rule from a SARIF run.
        
        Args:
            rule_id: ID of the rule
            run: SARIF run object
            
        Returns:
            Dictionary with rule metadata
        """
        if not run.get('tool') or not run.get('tool', {}).get('driver') or not run.get('tool', {}).get('driver', {}).get('rules'):
            return {}
        
        for rule in run.get('tool', {}).get('driver', {}).get('rules', []):
            if rule.get('id') == rule_id:
                result = {
                    'id': rule.get('id'),
                    'name': rule.get('name', rule.get('id')),
                    'description': rule.get('fullDescription', {}).get('text', ''),
                    'help': rule.get('help', {}).get('text'),
                    'properties': rule.get('properties', {})
                }
                
                # Extract tags if available
                if rule.get('properties'):
                    if 'tags' in rule.get('properties', {}):
                        result['tags'] = rule.get('properties', {}).get('tags', [])
                    if 'security-severity' in rule.get('properties', {}):
                        result['security_severity'] = rule.get('properties', {}).get('security-severity')
                
                return result
        
        return {}
    
    def _determine_vulnerability_type(self, result: Dict[str, Any], rule: Dict[str, Any]) -> Optional[str]:
        """
        Determine the vulnerability type from a SARIF result.
        
        Args:
            result: SARIF result object
            rule: Rule metadata
            
        Returns:
            Vulnerability type string or None if unknown
        """
        # Try to get from rule tags
        if 'tags' in rule:
            for tag in rule.get('tags', []):
                # Check for CWE tags
                if tag.startswith('CWE-'):
                    cwe_id = tag[4:]  # Remove "CWE-" prefix
                    if cwe_id in CWE_TO_VULN_TYPE:
                        return CWE_TO_VULN_TYPE[cwe_id]
                
                # Check for direct vulnerability type tags
                if tag.lower() in ['sql_injection', 'xss', 'path_traversal', 'command_injection']:
                    return tag.lower()
        
        # Check rule ID for clues
        rule_id_lower = rule.get('id', '').lower()
        if 'sql' in rule_id_lower and ('injection' in rule_id_lower or 'vuln' in rule_id_lower):
            return 'sql_injection'
        elif 'xss' in rule_id_lower or 'cross-site' in rule_id_lower:
            return 'xss'
        elif 'path' in rule_id_lower and ('traversal' in rule_id_lower or 'manipulation' in rule_id_lower):
            return 'path_traversal'
        elif ('command' in rule_id_lower or 'os' in rule_id_lower or 'exec' in rule_id_lower) and 'injection' in rule_id_lower:
            return 'command_injection'
        
        # Check rule name and description
        name_desc = (rule.get('name', '') + ' ' + rule.get('description', '')).lower()
        if 'sql' in name_desc and 'injection' in name_desc:
            return 'sql_injection'
        elif 'xss' in name_desc or 'cross-site scripting' in name_desc:
            return 'xss'
        elif 'path traversal' in name_desc or 'directory traversal' in name_desc:
            return 'path_traversal'
        elif ('command' in name_desc or 'os command' in name_desc) and 'injection' in name_desc:
            return 'command_injection'
        
        # If we get here, we couldn't determine the type
        return None
    
    def _extract_location(self, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Extract location information from a SARIF result.
        
        Args:
            result: SARIF result object
            
        Returns:
            Dictionary with location information or None if location is invalid
        """
        locations = result.get('locations', [])
        if not locations or not locations[0]:
            return None
        
        location = locations[0]
        physical_location = location.get('physicalLocation')
        if not physical_location:
            return None
        
        artifact_location = physical_location.get('artifactLocation')
        if not artifact_location or not artifact_location.get('uri'):
            return None
        
        file_path = artifact_location.get('uri')
        
        # Handle relative paths if base path is provided
        if self.base_path and not os.path.isabs(file_path) and not file_path.startswith('file://'):
            file_path = os.path.join(self.base_path, file_path)
        
        # Extract line and column
        line_number = None
        column = None
        if 'region' in physical_location:
            region = physical_location.get('region', {})
            line_number = region.get('startLine')
            column = region.get('startColumn')
        
        return {
            'file_path': file_path,
            'line_number': line_number,
            'column': column
        }
            
    def _extract_severity(self, result: Dict[str, Any], rule: Dict[str, Any]) -> tuple[str, Optional[float]]:
        """
        Extract severity information from a SARIF result.
        
        Args:
            result: SARIF result object
            rule: Rule metadata
            
        Returns:
            Tuple of (severity string, CVSS score)
        """
        # Try to get severity from rule properties
        if 'security_severity' in rule:
            try:
                severity_score = float(rule['security_severity'])
                if severity_score >= SEVERITY_THRESHOLDS['CRITICAL']:
                    return 'CRITICAL', severity_score
                elif severity_score >= SEVERITY_THRESHOLDS['HIGH']:
                    return 'HIGH', severity_score
                elif severity_score >= SEVERITY_THRESHOLDS['MEDIUM']:
                    return 'MEDIUM', severity_score
                elif severity_score >= SEVERITY_THRESHOLDS['LOW']:
                    return 'LOW', severity_score
                else:
                    return 'INFORMATIONAL', severity_score
            except (ValueError, TypeError):
                pass
        
        # Try to get level from result
        level = result.get('level', '').upper()
        if level in ['ERROR']:
            return 'HIGH', 7.0
        elif level in ['WARNING']:
            return 'MEDIUM', 4.0
        elif level in ['NOTE', 'NONE']:
            return 'LOW', 2.0
        
        # Default to MEDIUM if we can't determine it
        return 'MEDIUM', 5.0
    
    def _extract_cwe_id(self, rule: Dict[str, Any]) -> Optional[str]:
        """
        Extract CWE ID from rule metadata.
        
        Args:
            rule: Rule metadata
            
        Returns:
            CWE ID string or None if not found
        """
        # Try to get from tags
        if 'tags' in rule:
            for tag in rule.get('tags', []):
                if tag.startswith('CWE-'):
                    return tag
        
        # Try to find in description
        description = rule.get('description', '').upper()
        if 'CWE-' in description:
            # Try to extract CWE-NNN pattern
            import re
            match = re.search(r'CWE-\d+', description)
            if match:
                return match.group(0)
        
        return None
    
    def _is_security_finding(self, result: Dict[str, Any]) -> bool:
        """
        Determine if a SARIF result is a security finding.
        
        Args:
            result: SARIF result object
            
        Returns:
            True if the result is a security finding
        """
        # Check if result has been tagged as security
        if result.get('properties') and 'security-severity' in result.get('properties', {}):
            return True
        
        # Check the level - errors and warnings may be security issues
        level = result.get('level', '').upper()
        if level in ['ERROR', 'WARNING']:
            # But we should still try to filter only security-related ones
            message = result.get('message', {}).get('text', '')
            rule_id = result.get('ruleId', '')
            
            # Look for security-related keywords
            security_keywords = [
                'secur', 'vuln', 'cve', 'cwe', 'exploit', 'attack', 
                'malicious', 'injection', 'xss', 'csrf', 'traversal', 
                'sql', 'command', 'overflow', 'password', 'auth', 
                'sensitive', 'dos', 'denial', 'permission'
            ]
            
            combined_text = (message + ' ' + rule_id).lower()
            for keyword in security_keywords:
                if keyword in combined_text:
                    return True
        
        return False
    
    def _get_raw_data(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract raw data from a SARIF result for storage.
        
        Args:
            result: SARIF result object
            
        Returns:
            Dictionary with raw data
        """
        # Create a simplified copy to avoid too much data
        raw_data = {
            'rule_id': result.get('ruleId'),
            'message': result.get('message', {}).get('text') if isinstance(result.get('message'), dict) else result.get('message'),
            'level': result.get('level'),
            'locations': []
        }
        
        # Add location information
        if result.get('locations'):
            for location in result.get('locations', []):
                if isinstance(location, dict) and location.get('physicalLocation'):
                    phys_loc = location.get('physicalLocation', {})
                    loc_info = {
                        'file': phys_loc.get('artifactLocation', {}).get('uri') if isinstance(phys_loc.get('artifactLocation'), dict) else None,
                    }
                    
                    if phys_loc.get('region'):
                        region = phys_loc.get('region', {})
                        loc_info['line'] = region.get('startLine')
                        loc_info['column'] = region.get('startColumn')
                    
                    raw_data['locations'].append(loc_info)
        
        return raw_data
