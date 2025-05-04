"""
Parser for SARIF (Static Analysis Results Interchange Format) files.
"""
import json
import logging
import os
from typing import List, Dict, Any, Optional
from pathlib import Path

from sarif_om import SarifLog  # type: ignore

from vxdf_validate.models.finding import Finding
from vxdf_validate.config import CWE_TO_VULN_TYPE, SEVERITY_THRESHOLDS

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
            
            # Convert to SARIF object model
            sarif_log = SarifLog.from_json(sarif_data)
            
            findings = []
            for run in sarif_log.runs:
                tool_name = run.tool.driver.name if run.tool and run.tool.driver else "Unknown Tool"
                logger.debug(f"Processing run from tool: {tool_name}")
                
                if not run.results:
                    logger.info(f"No results found in run from {tool_name}")
                    continue
                
                for result in run.results:
                    # Skip informational or non-security findings
                    if not result.rule_id or not self._is_security_finding(result):
                        continue
                    
                    finding = self._convert_to_finding(result, run, tool_name)
                    if finding:
                        findings.append(finding)
            
            logger.info(f"Extracted {len(findings)} security findings from SARIF file")
            return findings
        
        except Exception as e:
            logger.error(f"Error parsing SARIF file: {e}", exc_info=True)
            raise
    
    def _convert_to_finding(self, result: Any, run: Any, tool_name: str) -> Optional[Finding]:
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
            rule = self._get_rule_metadata(result.rule_id, run)
            
            # Extract vulnerability type from rule or tags
            vuln_type = self._determine_vulnerability_type(result, rule)
            if not vuln_type:
                logger.debug(f"Skipping finding with rule ID {result.rule_id}: Unknown vulnerability type")
                return None
            
            # Extract code location
            location_info = self._extract_location(result)
            if not location_info:
                logger.debug(f"Skipping finding with rule ID {result.rule_id}: No location information")
                return None
            
            # Extract severity
            severity, cvss_score = self._extract_severity(result, rule)
            
            # Extract CWE ID
            cwe_id = self._extract_cwe_id(rule)
            
            # Create finding
            finding = Finding(
                source_id=result.id if hasattr(result, 'id') and result.id else result.rule_id,
                source_type="SARIF",
                vulnerability_type=vuln_type,
                name=rule.get('name', result.rule_id),
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
    
    def _get_rule_metadata(self, rule_id: str, run: Any) -> Dict[str, Any]:
        """
        Get metadata for a rule from a SARIF run.
        
        Args:
            rule_id: ID of the rule
            run: SARIF run object
            
        Returns:
            Dictionary with rule metadata
        """
        if not run.tool or not run.tool.driver or not run.tool.driver.rules:
            return {}
        
        for rule in run.tool.driver.rules:
            if rule.id == rule_id:
                result = {
                    'id': rule.id,
                    'name': rule.name if hasattr(rule, 'name') else rule.id,
                    'description': rule.full_description.text if hasattr(rule, 'full_description') else '',
                    'help': rule.help.text if hasattr(rule, 'help') else None,
                    'properties': rule.properties if hasattr(rule, 'properties') else {}
                }
                
                # Extract tags if available
                if hasattr(rule, 'properties') and rule.properties:
                    if 'tags' in rule.properties:
                        result['tags'] = rule.properties['tags']
                    if 'security-severity' in rule.properties:
                        result['security_severity'] = rule.properties['security-severity']
                
                return result
        
        return {}
    
    def _determine_vulnerability_type(self, result: Any, rule: Dict[str, Any]) -> Optional[str]:
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
            for tag in rule['tags']:
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
    
    def _extract_location(self, result: Any) -> Optional[Dict[str, Any]]:
        """
        Extract location information from a SARIF result.
        
        Args:
            result: SARIF result object
            
        Returns:
            Dictionary with location information or None if location is invalid
        """
        if not result.locations or not result.locations[0]:
            return None
        
        location = result.locations[0]
        if not location.physical_location:
            return None
        
        physical_location = location.physical_location
        if not physical_location.artifact_location or not physical_location.artifact_location.uri:
            return None
        
        file_path = physical_location.artifact_location.uri
        
        # Handle relative paths if base path is provided
        if self.base_path and not os.path.isabs(file_path) and not file_path.startswith('file://'):
            file_path = os.path.join(self.base_path, file_path)
        
        # Extract line and column
        line_number = None
        column = None
        if physical_location.region:
            region = physical_location.region
            line_number = region.start_line if hasattr(region, 'start_line') else None
            column = region.start_column if hasattr(region, 'start_column') else None
        
        return {
            'file_path': file_path,
            'line_number': line_number,
            'column': column
        }
    
    def _extract_severity(self, result: Any, rule: Dict[str, Any]) -> tuple[str, Optional[float]]:
        """
        Extract severity information from a SARIF result.
        
        Args:
            result: SARIF result object
            rule: Rule metadata
            
        Returns:
            Tuple of (severity level, CVSS score)
        """
        # Try to get severity from result level
        if hasattr(result, 'level'):
            if result.level == 'error':
                severity = 'HIGH'
                cvss_score = 7.5
            elif result.level == 'warning':
                severity = 'MEDIUM'
                cvss_score = 5.0
            elif result.level == 'note':
                severity = 'LOW'
                cvss_score = 3.0
            else:
                severity = 'MEDIUM'
                cvss_score = 5.0
        else:
            severity = 'MEDIUM'
            cvss_score = 5.0
        
        # Override with security-severity if available
        if 'security_severity' in rule:
            try:
                sec_severity = float(rule['security_severity'])
                cvss_score = sec_severity
                
                # Map to named severity levels
                if sec_severity >= SEVERITY_THRESHOLDS['CRITICAL']:
                    severity = 'CRITICAL'
                elif sec_severity >= SEVERITY_THRESHOLDS['HIGH']:
                    severity = 'HIGH'
                elif sec_severity >= SEVERITY_THRESHOLDS['MEDIUM']:
                    severity = 'MEDIUM'
                elif sec_severity >= SEVERITY_THRESHOLDS['LOW']:
                    severity = 'LOW'
                else:
                    severity = 'LOW'
            except (ValueError, TypeError):
                pass  # Keep default severity
        
        return severity, cvss_score
    
    def _extract_cwe_id(self, rule: Dict[str, Any]) -> Optional[str]:
        """
        Extract CWE ID from rule metadata.
        
        Args:
            rule: Rule metadata
            
        Returns:
            CWE ID string or None if not found
        """
        # Look for CWE in tags
        if 'tags' in rule:
            for tag in rule['tags']:
                if tag.startswith('CWE-'):
                    return tag[4:]  # Remove "CWE-" prefix
        
        # Look for CWE in properties
        if 'properties' in rule and isinstance(rule['properties'], dict):
            props = rule['properties']
            if 'cwe' in props:
                cwe = props['cwe']
                if isinstance(cwe, list) and cwe:
                    return str(cwe[0]).replace('CWE-', '')
                else:
                    return str(cwe).replace('CWE-', '')
        
        return None
    
    def _is_security_finding(self, result: Any) -> bool:
        """
        Determine if a SARIF result is a security finding.
        
        Args:
            result: SARIF result object
            
        Returns:
            True if the result is a security finding, False otherwise
        """
        # Basic check - if it has a rule ID, we'll consider it
        if not result.rule_id:
            return False
        
        # If it's a security tool, assume all results are security-related
        rule_id_lower = result.rule_id.lower()
        security_terms = ['security', 'vuln', 'cwe', 'owasp', 'injection', 'xss']
        
        for term in security_terms:
            if term in rule_id_lower:
                return True
        
        # Check level - security findings are usually errors or warnings
        if hasattr(result, 'level') and result.level in ['error', 'warning']:
            return True
        
        # Default to False
        return False
    
    def _get_raw_data(self, result: Any) -> Dict[str, Any]:
        """
        Extract raw data from a SARIF result for storage.
        
        Args:
            result: SARIF result object
            
        Returns:
            Dictionary with raw data
        """
        # Convert to dict, only including serializable fields
        raw_data = {}
        
        if hasattr(result, 'rule_id'):
            raw_data['rule_id'] = result.rule_id
        
        if hasattr(result, 'message') and hasattr(result.message, 'text'):
            raw_data['message'] = result.message.text
        
        if hasattr(result, 'level'):
            raw_data['level'] = result.level
        
        # Include locations if available
        if hasattr(result, 'locations') and result.locations:
            locations = []
            for loc in result.locations:
                loc_dict = {}
                
                if hasattr(loc, 'physical_location') and loc.physical_location:
                    phy_loc = loc.physical_location
                    phy_loc_dict = {}
                    
                    if hasattr(phy_loc, 'artifact_location') and phy_loc.artifact_location:
                        phy_loc_dict['artifact_location'] = {
                            'uri': phy_loc.artifact_location.uri if hasattr(phy_loc.artifact_location, 'uri') else None
                        }
                    
                    if hasattr(phy_loc, 'region') and phy_loc.region:
                        phy_loc_dict['region'] = {
                            'start_line': phy_loc.region.start_line if hasattr(phy_loc.region, 'start_line') else None,
                            'start_column': phy_loc.region.start_column if hasattr(phy_loc.region, 'start_column') else None,
                            'end_line': phy_loc.region.end_line if hasattr(phy_loc.region, 'end_line') else None,
                            'end_column': phy_loc.region.end_column if hasattr(phy_loc.region, 'end_column') else None
                        }
                    
                    loc_dict['physical_location'] = phy_loc_dict
                
                locations.append(loc_dict)
            
            raw_data['locations'] = locations
        
        # Include codeFlows if available for data flow tracking
        if hasattr(result, 'code_flows') and result.code_flows:
            code_flows = []
            for flow in result.code_flows:
                flow_dict = {}
                
                if hasattr(flow, 'thread_flows') and flow.thread_flows:
                    thread_flows = []
                    for thread_flow in flow.thread_flows:
                        thread_dict = {}
                        
                        if hasattr(thread_flow, 'locations') and thread_flow.locations:
                            tf_locations = []
                            for tf_loc in thread_flow.locations:
                                tf_loc_dict = {}
                                
                                if hasattr(tf_loc, 'location') and tf_loc.location:
                                    if hasattr(tf_loc.location, 'physical_location') and tf_loc.location.physical_location:
                                        phy_loc = tf_loc.location.physical_location
                                        phy_loc_dict = {}
                                        
                                        if hasattr(phy_loc, 'artifact_location') and phy_loc.artifact_location:
                                            phy_loc_dict['artifact_location'] = {
                                                'uri': phy_loc.artifact_location.uri if hasattr(phy_loc.artifact_location, 'uri') else None
                                            }
                                        
                                        if hasattr(phy_loc, 'region') and phy_loc.region:
                                            phy_loc_dict['region'] = {
                                                'start_line': phy_loc.region.start_line if hasattr(phy_loc.region, 'start_line') else None,
                                                'start_column': phy_loc.region.start_column if hasattr(phy_loc.region, 'start_column') else None
                                            }
                                        
                                        tf_loc_dict['physical_location'] = phy_loc_dict
                                    
                                    if hasattr(tf_loc.location, 'message') and hasattr(tf_loc.location.message, 'text'):
                                        tf_loc_dict['message'] = tf_loc.location.message.text
                                
                                tf_locations.append(tf_loc_dict)
                            
                            thread_dict['locations'] = tf_locations
                        
                        thread_flows.append(thread_dict)
                    
                    flow_dict['thread_flows'] = thread_flows
                
                code_flows.append(flow_dict)
            
            raw_data['code_flows'] = code_flows
        
        return raw_data
