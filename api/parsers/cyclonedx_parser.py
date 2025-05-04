"""
Parser for CycloneDX Software Bill of Materials (SBOM) with vulnerability data.
"""
import json
import logging
import os
from typing import List, Dict, Any, Optional
from pathlib import Path

import cyclonedx.model.bom  # type: ignore
from cyclonedx.parser import BaseParser, parse_json_file, parse_xml_file  # type: ignore

from api.models.finding import Finding
from api.config import CWE_TO_VULN_TYPE, SEVERITY_THRESHOLDS

logger = logging.getLogger(__name__)

class CycloneDXParser:
    """
    Parser for CycloneDX Software Bill of Materials (SBOM) with vulnerability data.
    """
    
    def __init__(self):
        """
        Initialize the CycloneDX parser.
        """
        pass
    
    def parse_file(self, file_path: str) -> List[Finding]:
        """
        Parse a CycloneDX file and extract security findings.
        
        Args:
            file_path: Path to the CycloneDX file
            
        Returns:
            List of Finding objects
        """
        logger.info(f"Parsing CycloneDX file: {file_path}")
        
        try:
            # Determine file format based on extension
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext == '.json':
                bom = parse_json_file(file_path)
            elif file_ext in ['.xml', '.cdx']:
                bom = parse_xml_file(file_path)
            else:
                # Try JSON first, then XML
                try:
                    bom = parse_json_file(file_path)
                except Exception:
                    bom = parse_xml_file(file_path)
            
            findings = []
            
            # Process components with vulnerabilities
            self._process_components(bom.components, findings)
            
            # Process direct vulnerabilities if present
            if hasattr(bom, 'vulnerabilities') and bom.vulnerabilities:
                self._process_vulnerabilities(bom.vulnerabilities, bom.components, findings)
            
            logger.info(f"Extracted {len(findings)} security findings from CycloneDX file")
            return findings
        
        except Exception as e:
            logger.error(f"Error parsing CycloneDX file: {e}", exc_info=True)
            raise
    
    def _process_components(self, components: List[Any], findings: List[Finding]) -> None:
        """
        Process components in a BOM and extract vulnerabilities.
        
        Args:
            components: List of CycloneDX components
            findings: List to append findings to
        """
        if not components:
            return
        
        for component in components:
            # Process nested components recursively
            if hasattr(component, 'components') and component.components:
                self._process_components(component.components, findings)
            
            # Process vulnerabilities in this component
            if hasattr(component, 'vulnerabilities') and component.vulnerabilities:
                for vuln in component.vulnerabilities:
                    finding = self._convert_to_finding(vuln, component)
                    if finding:
                        findings.append(finding)
    
    def _process_vulnerabilities(self, vulnerabilities: List[Any], components: List[Any], findings: List[Finding]) -> None:
        """
        Process vulnerabilities in a BOM.
        
        Args:
            vulnerabilities: List of CycloneDX vulnerabilities
            components: List of CycloneDX components
            findings: List to append findings to
        """
        component_map = {}
        if components:
            for component in components:
                if hasattr(component, 'bom_ref') and component.bom_ref:
                    component_map[component.bom_ref] = component
        
        for vuln in vulnerabilities:
            # Try to find affected component
            component = None
            if hasattr(vuln, 'affects') and vuln.affects:
                for affect in vuln.affects:
                    if hasattr(affect, 'ref') and affect.ref in component_map:
                        component = component_map[affect.ref]
                        break
            
            finding = self._convert_to_finding(vuln, component)
            if finding:
                findings.append(finding)
    
    def _convert_to_finding(self, vuln: Any, component: Optional[Any] = None) -> Optional[Finding]:
        """
        Convert a CycloneDX vulnerability to a Finding object.
        
        Args:
            vuln: CycloneDX vulnerability object
            component: Associated component if available
            
        Returns:
            Finding object or None if the vulnerability should be skipped
        """
        try:
            # Get basic vulnerability info
            vuln_id = vuln.id if hasattr(vuln, 'id') else None
            if not vuln_id:
                logger.warning("Skipping vulnerability with no ID")
                return None
            
            # Extract description
            description = ""
            if hasattr(vuln, 'description') and vuln.description:
                description = vuln.description
            
            # Extract CWE ID
            cwe_id = None
            if hasattr(vuln, 'cwes') and vuln.cwes:
                for cwe in vuln.cwes:
                    if cwe.startswith('CWE-'):
                        cwe_id = cwe[4:]  # Remove "CWE-" prefix
                        break
                    else:
                        cwe_id = cwe
            
            # Determine vulnerability type from CWE
            vuln_type = None
            if cwe_id and cwe_id in CWE_TO_VULN_TYPE:
                vuln_type = CWE_TO_VULN_TYPE[cwe_id]
            else:
                # Try to determine from description or ID
                vuln_id_lower = vuln_id.lower() if vuln_id else ""
                desc_lower = description.lower()
                
                if 'sql' in desc_lower and 'injection' in desc_lower:
                    vuln_type = 'sql_injection'
                elif 'xss' in desc_lower or 'cross-site scripting' in desc_lower:
                    vuln_type = 'xss'
                elif 'path traversal' in desc_lower or 'directory traversal' in desc_lower:
                    vuln_type = 'path_traversal'
                elif ('command' in desc_lower or 'os command' in desc_lower) and 'injection' in desc_lower:
                    vuln_type = 'command_injection'
                elif 'sql' in vuln_id_lower and 'injection' in vuln_id_lower:
                    vuln_type = 'sql_injection'
                elif 'xss' in vuln_id_lower:
                    vuln_type = 'xss'
                elif 'path' in vuln_id_lower and 'traversal' in vuln_id_lower:
                    vuln_type = 'path_traversal'
                elif ('command' in vuln_id_lower or 'exec' in vuln_id_lower) and 'injection' in vuln_id_lower:
                    vuln_type = 'command_injection'
                else:
                    vuln_type = 'other'  # Default type
            
            # Extract severity and CVSS score
            severity = 'MEDIUM'  # Default
            cvss_score = None
            
            if hasattr(vuln, 'ratings') and vuln.ratings:
                for rating in vuln.ratings:
                    if hasattr(rating, 'method') and rating.method == 'CVSS_V3':
                        if hasattr(rating, 'score') and rating.score is not None:
                            cvss_score = float(rating.score)
                            
                            # Map CVSS score to severity
                            if cvss_score >= SEVERITY_THRESHOLDS['CRITICAL']:
                                severity = 'CRITICAL'
                            elif cvss_score >= SEVERITY_THRESHOLDS['HIGH']:
                                severity = 'HIGH'
                            elif cvss_score >= SEVERITY_THRESHOLDS['MEDIUM']:
                                severity = 'MEDIUM'
                            elif cvss_score >= SEVERITY_THRESHOLDS['LOW']:
                                severity = 'LOW'
                            else:
                                severity = 'LOW'
                        
                        break
            
            # Extract component info
            component_info = {}
            if component:
                if hasattr(component, 'name'):
                    component_info['name'] = component.name
                if hasattr(component, 'version'):
                    component_info['version'] = component.version
                if hasattr(component, 'purl'):
                    component_info['purl'] = component.purl
                if hasattr(component, 'type'):
                    component_info['type'] = component.type
            
            # Build raw data
            raw_data = {
                'vulnerability_id': vuln_id,
                'component': component_info,
                'references': []
            }
            
            # Add references
            if hasattr(vuln, 'references') and vuln.references:
                for ref in vuln.references:
                    ref_data = {}
                    if hasattr(ref, 'id'):
                        ref_data['id'] = ref.id
                    if hasattr(ref, 'url'):
                        ref_data['url'] = ref.url
                    if hasattr(ref, 'type'):
                        ref_data['type'] = ref.type
                    raw_data['references'].append(ref_data)
            
            # Create finding
            finding = Finding(
                source_id=vuln_id,
                source_type="CycloneDX",
                vulnerability_type=vuln_type,
                name=f"{vuln_id} in {component_info.get('name', 'Unknown Component')}",
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cwe_id=cwe_id,
                raw_data=raw_data
            )
            
            return finding
        
        except Exception as e:
            logger.error(f"Error converting CycloneDX vulnerability to finding: {e}", exc_info=True)
            return None
