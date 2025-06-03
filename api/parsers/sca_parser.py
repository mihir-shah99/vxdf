"""
Parser for SCA (Software Composition Analysis) tool outputs.
Supports multiple formats: npm audit, pip-audit, CycloneDX, and generic formats.
"""
import json
import logging
import os
from typing import List, Dict, Any, Optional
from pathlib import Path

from api.models.finding import Finding
from api.config import CWE_TO_VULN_TYPE, SEVERITY_THRESHOLDS

logger = logging.getLogger(__name__)

class ScaParser:
    """
    Parser for SCA (Software Composition Analysis) tool outputs.
    """
    
    def __init__(self, tool_type: Optional[str] = None):
        """
        Initialize the SCA parser.
        
        Args:
            tool_type: Type of SCA tool (npm_audit, pip_audit, cyclonedx, generic)
        """
        self.tool_type = tool_type
    
    def parse_file(self, file_path: str) -> List[Finding]:
        """
        Parse an SCA output file and extract security findings.
        
        Args:
            file_path: Path to the SCA output file
            
        Returns:
            List of Finding objects
        """
        logger.info(f"Parsing SCA file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                sca_data = json.load(f)
            
            # Determine parser to use
            tool_type = self._detect_tool_type(sca_data, self.tool_type)
            logger.debug(f"Detected SCA tool type: {tool_type}")
            
            # Parse based on tool type
            if tool_type == 'npm_audit':
                findings = self._parse_npm_audit(sca_data)
            elif tool_type == 'pip_audit':
                findings = self._parse_pip_audit(sca_data)
            elif tool_type == 'cyclonedx':
                findings = self._parse_cyclonedx(sca_data)
            else:
                findings = self._parse_generic(sca_data)
            
            logger.info(f"Extracted {len(findings)} security findings from SCA file")
            return findings
        
        except Exception as e:
            logger.error(f"Error parsing SCA file: {e}", exc_info=True)
            raise
    
    def _detect_tool_type(self, data: Dict[str, Any], specified_type: Optional[str] = None) -> str:
        """
        Detect the SCA tool type based on the data format.
        
        Args:
            data: Parsed JSON data
            specified_type: User-specified tool type
            
        Returns:
            Detected tool type
        """
        if specified_type:
            return specified_type
        
        # npm audit detection
        if 'auditReportVersion' in data and 'vulnerabilities' in data:
            return 'npm_audit'
        
        # pip-audit detection
        if 'vulnerabilities' in data and isinstance(data['vulnerabilities'], list):
            if any('package' in vuln and 'id' in vuln for vuln in data['vulnerabilities']):
                return 'pip_audit'
        
        # CycloneDX detection
        if 'bomFormat' in data and data.get('bomFormat') == 'CycloneDX':
            return 'cyclonedx'
        
        # Default to generic
        return 'generic'
    
    def _parse_npm_audit(self, data: Dict[str, Any]) -> List[Finding]:
        """
        Parse npm audit JSON format.
        
        Args:
            data: Parsed npm audit JSON data
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            vulnerabilities = data.get('vulnerabilities', {})
            
            for package_name, vuln_data in vulnerabilities.items():
                # Process main vulnerability information
                finding = self._convert_npm_vuln_to_finding(package_name, vuln_data)
                if finding:
                    findings.append(finding)
                
                # Also process via information if available (detailed advisory data)
                via = vuln_data.get('via', [])
                if isinstance(via, list):
                    for via_item in via:
                        if isinstance(via_item, dict) and 'source' in via_item:
                            # This is detailed advisory information
                            advisory_finding = self._convert_npm_advisory_to_finding(package_name, via_item, vuln_data)
                            if advisory_finding:
                                findings.append(advisory_finding)
        
        except Exception as e:
            logger.error(f"Error parsing npm audit data: {e}", exc_info=True)
        
        return findings
    
    def _parse_pip_audit(self, data: Dict[str, Any]) -> List[Finding]:
        """
        Parse pip-audit JSON format.
        
        Args:
            data: Parsed pip-audit JSON data
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            vulnerabilities = data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                finding = self._convert_pip_vuln_to_finding(vuln)
                if finding:
                    findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error parsing pip-audit data: {e}", exc_info=True)
        
        return findings
    
    def _parse_cyclonedx(self, data: Dict[str, Any]) -> List[Finding]:
        """
        Parse CycloneDX SBOM JSON format.
        
        Args:
            data: Parsed CycloneDX JSON data
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            # Parse vulnerabilities directly
            vulnerabilities = data.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                finding = self._convert_cyclonedx_vuln_to_finding(vuln, data)
                if finding:
                    findings.append(finding)
            
            # Parse component vulnerabilities
            components = data.get('components', [])
            for component in components:
                if 'vulnerabilities' in component:
                    for vuln in component['vulnerabilities']:
                        finding = self._convert_cyclonedx_vuln_to_finding(vuln, data, component)
                        if finding:
                            findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error parsing CycloneDX data: {e}", exc_info=True)
        
        return findings
    
    def _parse_generic(self, data: Dict[str, Any]) -> List[Finding]:
        """
        Parse generic SCA JSON format.
        
        Args:
            data: Parsed generic JSON data
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            # Look for various array structures
            if 'vulnerabilities' in data and isinstance(data['vulnerabilities'], list):
                items = data['vulnerabilities']
            elif 'findings' in data and isinstance(data['findings'], list):
                items = data['findings']
            elif 'issues' in data and isinstance(data['issues'], list):
                items = data['issues']
            elif 'components' in data and isinstance(data['components'], list):
                items = data['components']
            elif isinstance(data, list):
                items = data
            else:
                items = [data]
            
            for item in items:
                finding = self._convert_generic_to_finding(item)
                if finding:
                    findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error parsing generic SCA data: {e}", exc_info=True)
        
        return findings
    
    def _convert_npm_vuln_to_finding(self, package_name: str, vuln_data: Dict[str, Any]) -> Optional[Finding]:
        """
        Convert npm vulnerability to Finding object.
        
        Args:
            package_name: Name of the vulnerable package
            vuln_data: Vulnerability data
            
        Returns:
            Finding object or None
        """
        try:
            name = f"Vulnerable package: {package_name}"
            description = f"Package {package_name} has known vulnerabilities"
            
            # Extract severity
            severity = vuln_data.get('severity', 'moderate').upper()
            if severity == 'MODERATE':
                severity = 'MEDIUM'
            elif severity not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                severity = 'MEDIUM'
            
            # Map severity to CVSS
            cvss_score = 5.0  # Default
            if severity == 'CRITICAL':
                cvss_score = 9.0
            elif severity == 'HIGH':
                cvss_score = 7.5
            elif severity == 'MEDIUM':
                cvss_score = 5.0
            elif severity == 'LOW':
                cvss_score = 3.0
            
            # Get range information
            range_info = vuln_data.get('range', '')
            if range_info:
                description += f" (affected versions: {range_info})"
            
            finding = Finding(
                source_id=f"npm-{package_name}-{hash(str(vuln_data))}",
                source_type="SCA-NPM",
                vulnerability_type="vulnerable_component",
                name=name,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                raw_data={
                    'package': package_name,
                    'vulnerability': vuln_data,
                    'tool': 'npm_audit'
                }
            )
            
            return finding
        
        except Exception as e:
            logger.error(f"Error converting npm vulnerability to finding: {e}", exc_info=True)
            return None
    
    def _convert_npm_advisory_to_finding(self, package_name: str, advisory: Dict[str, Any], context: Dict[str, Any]) -> Optional[Finding]:
        """
        Convert npm advisory to Finding object.
        
        Args:
            package_name: Name of the vulnerable package
            advisory: Advisory data
            context: Additional context
            
        Returns:
            Finding object or None
        """
        try:
            advisory_id = advisory.get('source', 'unknown')
            name = advisory.get('title', f"Security advisory {advisory_id} in {package_name}")
            description = advisory.get('overview', '')
            
            # Extract CWE
            cwe_ids = advisory.get('cwe', [])
            cwe_id = None
            if cwe_ids and isinstance(cwe_ids, list):
                cwe_id = str(cwe_ids[0]).replace('CWE-', '')
            
            # Extract severity
            severity = advisory.get('severity', 'moderate').upper()
            if severity == 'MODERATE':
                severity = 'MEDIUM'
            elif severity not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                severity = 'MEDIUM'
            
            # Map severity to CVSS
            cvss_score = 5.0  # Default
            if severity == 'CRITICAL':
                cvss_score = 9.0
            elif severity == 'HIGH':
                cvss_score = 7.5
            elif severity == 'MEDIUM':
                cvss_score = 5.0
            elif severity == 'LOW':
                cvss_score = 3.0
            
            # Determine vulnerability type
            vuln_type = self._determine_vuln_type_from_cwe_description(cwe_id, description)
            
            finding = Finding(
                source_id=f"npm-advisory-{advisory_id}",
                source_type="SCA-NPM",
                vulnerability_type=vuln_type,
                name=name,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cwe_id=cwe_id,
                raw_data={
                    'package': package_name,
                    'advisory': advisory,
                    'context': context,
                    'tool': 'npm_audit'
                }
            )
            
            return finding
        
        except Exception as e:
            logger.error(f"Error converting npm advisory to finding: {e}", exc_info=True)
            return None
    
    def _convert_pip_vuln_to_finding(self, vuln: Dict[str, Any]) -> Optional[Finding]:
        """
        Convert pip-audit vulnerability to Finding object.
        
        Args:
            vuln: Vulnerability data
            
        Returns:
            Finding object or None
        """
        try:
            package_name = vuln.get('package', 'unknown')
            vuln_id = vuln.get('id', 'unknown')
            name = f"{vuln_id} in {package_name}"
            description = vuln.get('description', '')
            
            # Extract severity (pip-audit may not always have this)
            severity = 'MEDIUM'  # Default for SCA findings
            cvss_score = 5.0
            
            # Look for CVSS data
            if 'fix_versions' in vuln and vuln['fix_versions']:
                description += f" (fixed in: {', '.join(vuln['fix_versions'])})"
            
            finding = Finding(
                source_id=f"pip-{vuln_id}",
                source_type="SCA-Pip",
                vulnerability_type="vulnerable_component",
                name=name,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                raw_data={
                    'package': package_name,
                    'vulnerability': vuln,
                    'tool': 'pip_audit'
                }
            )
            
            return finding
        
        except Exception as e:
            logger.error(f"Error converting pip vulnerability to finding: {e}", exc_info=True)
            return None
    
    def _convert_cyclonedx_vuln_to_finding(self, vuln: Dict[str, Any], sbom: Dict[str, Any], component: Optional[Dict[str, Any]] = None) -> Optional[Finding]:
        """
        Convert CycloneDX vulnerability to Finding object.
        
        Args:
            vuln: Vulnerability data
            sbom: Full SBOM data
            component: Associated component if available
            
        Returns:
            Finding object or None
        """
        try:
            vuln_id = vuln.get('id', 'unknown')
            description = vuln.get('description', '')
            
            # Get component info
            component_name = 'unknown'
            if component:
                component_name = component.get('name', component.get('bom-ref', 'unknown'))
            
            name = f"{vuln_id} in {component_name}"
            
            # Extract CWE
            cwe_id = None
            cwes = vuln.get('cwes', [])
            if cwes:
                cwe_id = str(cwes[0]).replace('CWE-', '')
            
            # Extract severity and CVSS
            severity = 'MEDIUM'
            cvss_score = 5.0
            
            ratings = vuln.get('ratings', [])
            for rating in ratings:
                if rating.get('method') == 'CVSSv3':
                    score = rating.get('score')
                    if score:
                        cvss_score = float(score)
                        if cvss_score >= SEVERITY_THRESHOLDS['CRITICAL']:
                            severity = 'CRITICAL'
                        elif cvss_score >= SEVERITY_THRESHOLDS['HIGH']:
                            severity = 'HIGH'
                        elif cvss_score >= SEVERITY_THRESHOLDS['MEDIUM']:
                            severity = 'MEDIUM'
                        elif cvss_score >= SEVERITY_THRESHOLDS['LOW']:
                            severity = 'LOW'
                    break
            
            # Determine vulnerability type
            vuln_type = self._determine_vuln_type_from_cwe_description(cwe_id, description)
            
            finding = Finding(
                source_id=f"cyclonedx-{vuln_id}",
                source_type="SCA-CycloneDX",
                vulnerability_type=vuln_type,
                name=name,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cwe_id=cwe_id,
                raw_data={
                    'vulnerability': vuln,
                    'component': component,
                    'tool': 'cyclonedx'
                }
            )
            
            return finding
        
        except Exception as e:
            logger.error(f"Error converting CycloneDX vulnerability to finding: {e}", exc_info=True)
            return None
    
    def _convert_generic_to_finding(self, item: Dict[str, Any]) -> Optional[Finding]:
        """
        Convert generic SCA item to Finding object.
        
        Args:
            item: Generic SCA item data
            
        Returns:
            Finding object or None
        """
        try:
            # Look for common field names
            name = None
            for field in ['name', 'title', 'id', 'vulnerability_id', 'advisory_id']:
                if field in item:
                    name = item[field]
                    break
            
            if not name:
                name = "Unknown SCA Finding"
            
            # Look for package name
            package_name = None
            for field in ['package', 'component', 'library', 'dependency']:
                if field in item:
                    if isinstance(item[field], dict):
                        package_name = item[field].get('name', str(item[field]))
                    else:
                        package_name = str(item[field])
                    break
            
            if package_name and package_name not in name:
                name = f"{name} in {package_name}"
            
            # Look for description
            description = None
            for field in ['description', 'summary', 'overview', 'details']:
                if field in item:
                    description = item[field]
                    break
            
            if not description:
                description = ""
            
            # Look for severity
            severity = 'MEDIUM'
            cvss_score = 5.0
            
            severity_str = None
            for field in ['severity', 'risk', 'impact', 'criticality']:
                if field in item:
                    severity_str = str(item[field])
                    break
            
            if severity_str:
                severity_str = severity_str.lower()
                if severity_str in ['critical', 'crit']:
                    severity = 'CRITICAL'
                    cvss_score = 9.0
                elif severity_str in ['high', 'severe']:
                    severity = 'HIGH'
                    cvss_score = 7.5
                elif severity_str in ['medium', 'moderate']:
                    severity = 'MEDIUM'
                    cvss_score = 5.0
                elif severity_str in ['low', 'minor']:
                    severity = 'LOW'
                    cvss_score = 3.0
            
            # Look for CVSS score
            for field in ['cvss', 'cvss_score', 'score']:
                if field in item:
                    try:
                        cvss_score = float(item[field])
                        break
                    except (ValueError, TypeError):
                        pass
            
            # Look for CWE
            cwe_id = None
            for field in ['cwe', 'cwe_id', 'cwes']:
                if field in item:
                    cwe_val = item[field]
                    if isinstance(cwe_val, list) and cwe_val:
                        cwe_val = cwe_val[0]
                    if isinstance(cwe_val, str):
                        cwe_id = cwe_val.replace('CWE-', '')
                    elif isinstance(cwe_val, (int, float)):
                        cwe_id = str(int(cwe_val))
                    break
            
            # Determine vulnerability type
            vuln_type = self._determine_vuln_type_from_cwe_description(cwe_id, description)
            
            finding = Finding(
                source_id=str(item.get('id', hash(name))),
                source_type="SCA-Generic",
                vulnerability_type=vuln_type,
                name=name,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cwe_id=cwe_id,
                raw_data={
                    'item': item,
                    'package': package_name,
                    'tool': 'generic'
                }
            )
            
            return finding
        
        except Exception as e:
            logger.error(f"Error converting generic SCA item to finding: {e}", exc_info=True)
            return None
    
    def _determine_vuln_type_from_cwe_description(self, cwe_id: Optional[str], description: str) -> str:
        """
        Determine vulnerability type from CWE ID and description.
        
        Args:
            cwe_id: CWE ID if available
            description: Vulnerability description
            
        Returns:
            Vulnerability type string
        """
        # Check CWE mapping first
        if cwe_id and cwe_id in CWE_TO_VULN_TYPE:
            return CWE_TO_VULN_TYPE[cwe_id]
        
        # Check description for keywords
        desc_lower = description.lower()
        
        if 'sql' in desc_lower and 'injection' in desc_lower:
            return 'sql_injection'
        elif 'xss' in desc_lower or 'cross-site script' in desc_lower:
            return 'xss'
        elif ('path' in desc_lower and 'traversal' in desc_lower) or 'directory' in desc_lower:
            return 'path_traversal'
        elif ('command' in desc_lower or 'cmd' in desc_lower or 'os' in desc_lower) and 'injection' in desc_lower:
            return 'command_injection'
        elif 'component' in desc_lower or 'dependency' in desc_lower or 'package' in desc_lower:
            return 'vulnerable_component'
        
        # Default to vulnerable component for SCA findings
        return 'vulnerable_component' 