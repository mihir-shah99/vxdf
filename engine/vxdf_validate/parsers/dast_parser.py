"""
Parser for DAST (Dynamic Application Security Testing) tool outputs.
Currently supports generic JSON and ZAP JSON format.
"""
import json
import logging
import os
from typing import List, Dict, Any, Optional
from pathlib import Path

from vxdf_validate.models.finding import Finding
from vxdf_validate.config import CWE_TO_VULN_TYPE, SEVERITY_THRESHOLDS

logger = logging.getLogger(__name__)

class DastParser:
    """
    Parser for DAST (Dynamic Application Security Testing) tool outputs.
    """
    
    def __init__(self, tool_type: Optional[str] = None):
        """
        Initialize the DAST parser.
        
        Args:
            tool_type: Type of DAST tool (zap, burp, generic)
        """
        self.tool_type = tool_type
    
    def parse_file(self, file_path: str) -> List[Finding]:
        """
        Parse a DAST output file and extract security findings.
        
        Args:
            file_path: Path to the DAST output file
            
        Returns:
            List of Finding objects
        """
        logger.info(f"Parsing DAST file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                dast_data = json.load(f)
            
            # Determine parser to use
            tool_type = self._detect_tool_type(dast_data, self.tool_type)
            logger.debug(f"Detected DAST tool type: {tool_type}")
            
            # Parse based on tool type
            if tool_type == 'zap':
                findings = self._parse_zap(dast_data)
            elif tool_type == 'burp':
                findings = self._parse_burp(dast_data)
            else:
                findings = self._parse_generic(dast_data)
            
            logger.info(f"Extracted {len(findings)} security findings from DAST file")
            return findings
        
        except Exception as e:
            logger.error(f"Error parsing DAST file: {e}", exc_info=True)
            raise
    
    def _detect_tool_type(self, data: Dict[str, Any], specified_type: Optional[str] = None) -> str:
        """
        Detect the DAST tool type based on the data format.
        
        Args:
            data: Parsed JSON data
            specified_type: User-specified tool type
            
        Returns:
            Detected tool type
        """
        if specified_type:
            return specified_type
        
        # ZAP detection
        if '@version' in data and 'site' in data and isinstance(data['site'], list):
            return 'zap'
        
        # Burp detection
        if 'issue_events' in data or 'issues' in data and 'scan_information' in data:
            return 'burp'
        
        # Default to generic
        return 'generic'
    
    def _parse_zap(self, data: Dict[str, Any]) -> List[Finding]:
        """
        Parse ZAP JSON format.
        
        Args:
            data: Parsed ZAP JSON data
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            sites = data.get('site', [])
            if not isinstance(sites, list):
                sites = [sites]
            
            for site in sites:
                site_name = site.get('@name', 'Unknown Site')
                alerts = site.get('alerts', [])
                
                if not isinstance(alerts, list):
                    alerts = [alerts]
                
                for alert in alerts:
                    instances = alert.get('instances', [])
                    if not isinstance(instances, list):
                        instances = [instances]
                    
                    for instance in instances:
                        finding = self._convert_zap_to_finding(alert, instance, site_name)
                        if finding:
                            findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error parsing ZAP data: {e}", exc_info=True)
        
        return findings
    
    def _parse_burp(self, data: Dict[str, Any]) -> List[Finding]:
        """
        Parse Burp JSON format.
        
        Args:
            data: Parsed Burp JSON data
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            # Handle Burp Enterprise format
            if 'issue_events' in data:
                for event in data['issue_events']:
                    if 'issue' in event:
                        finding = self._convert_burp_to_finding(event['issue'])
                        if finding:
                            findings.append(finding)
            
            # Handle Burp Professional format
            elif 'issues' in data:
                for issue in data['issues']:
                    finding = self._convert_burp_to_finding(issue)
                    if finding:
                        findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error parsing Burp data: {e}", exc_info=True)
        
        return findings
    
    def _parse_generic(self, data: Dict[str, Any]) -> List[Finding]:
        """
        Parse generic JSON format.
        
        Args:
            data: Parsed generic JSON data
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            # Look for an array of findings/issues/vulnerabilities
            if 'findings' in data and isinstance(data['findings'], list):
                items = data['findings']
            elif 'issues' in data and isinstance(data['issues'], list):
                items = data['issues']
            elif 'vulnerabilities' in data and isinstance(data['vulnerabilities'], list):
                items = data['vulnerabilities']
            elif 'results' in data and isinstance(data['results'], list):
                items = data['results']
            elif isinstance(data, list):
                items = data
            else:
                # If no clear array structure, wrap the whole object
                items = [data]
            
            for item in items:
                finding = self._convert_generic_to_finding(item)
                if finding:
                    findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error parsing generic DAST data: {e}", exc_info=True)
        
        return findings
    
    def _convert_zap_to_finding(self, alert: Dict[str, Any], instance: Dict[str, Any], site_name: str) -> Optional[Finding]:
        """
        Convert a ZAP alert to a Finding object.
        
        Args:
            alert: ZAP alert data
            instance: Specific instance of the alert
            site_name: Name of the site
            
        Returns:
            Finding object or None
        """
        try:
            # Extract basic info
            name = alert.get('name', 'Unknown ZAP Alert')
            description = alert.get('desc', '')
            if alert.get('solution'):
                description += f"\n\nSolution: {alert['solution']}"
            
            # Extract severity
            risk = alert.get('riskcode', 2)
            if isinstance(risk, str):
                try:
                    risk = int(risk)
                except ValueError:
                    risk = 2
            
            if risk == 3:
                severity = 'HIGH'
                cvss_score = 7.5
            elif risk == 2:
                severity = 'MEDIUM'
                cvss_score = 5.0
            elif risk == 1:
                severity = 'LOW'
                cvss_score = 3.0
            else:
                severity = 'INFORMATIONAL'
                cvss_score = 0.0
            
            # Extract CWE ID
            cwe_id = None
            if 'cweid' in alert:
                cwe_id = str(alert['cweid'])
            
            # Determine vulnerability type
            vuln_type = self._determine_vuln_type_from_name_cwe(name, cwe_id)
            
            # Extract URL and request/response
            url = instance.get('uri', '')
            
            # Find request and response
            request = instance.get('requestheader', '')
            if instance.get('requestbody'):
                request += "\n\n" + instance['requestbody']
            
            response = instance.get('responseheader', '')
            if instance.get('responsebody'):
                response += "\n\n" + instance['responsebody']
            
            # Create finding
            finding = Finding(
                source_id=f"ZAP-{alert.get('pluginid', '')}-{hash(url)}",
                source_type="DAST-ZAP",
                vulnerability_type=vuln_type,
                name=name,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cwe_id=cwe_id,
                raw_data={
                    'alert': alert,
                    'instance': instance,
                    'site': site_name,
                    'url': url,
                    'request': request,
                    'response': response
                }
            )
            
            return finding
        
        except Exception as e:
            logger.error(f"Error converting ZAP alert to finding: {e}", exc_info=True)
            return None
    
    def _convert_burp_to_finding(self, issue: Dict[str, Any]) -> Optional[Finding]:
        """
        Convert a Burp issue to a Finding object.
        
        Args:
            issue: Burp issue data
            
        Returns:
            Finding object or None
        """
        try:
            # Extract basic info
            name = issue.get('name', issue.get('issue_type_name', 'Unknown Burp Issue'))
            description = issue.get('description', issue.get('issue_description', ''))
            if issue.get('remediation'):
                description += f"\n\nRemediation: {issue['remediation']}"
            
            # Extract severity
            severity_map = {
                'high': 'HIGH',
                'medium': 'MEDIUM',
                'low': 'LOW',
                'info': 'INFORMATIONAL',
                'critical': 'CRITICAL',
                'information': 'INFORMATIONAL'
            }
            
            severity_str = issue.get('severity', issue.get('severity_level', 'medium')).lower()
            severity = severity_map.get(severity_str, 'MEDIUM')
            
            # Map severity to CVSS
            cvss_score = 5.0  # Default medium
            if severity == 'CRITICAL':
                cvss_score = 9.0
            elif severity == 'HIGH':
                cvss_score = 7.5
            elif severity == 'MEDIUM':
                cvss_score = 5.0
            elif severity == 'LOW':
                cvss_score = 3.0
            else:
                cvss_score = 0.0
            
            # Extract CWE ID from vulnerability classification
            cwe_id = None
            if 'vulnerability_classifications' in issue:
                for classification in issue['vulnerability_classifications']:
                    if 'CWE-' in classification:
                        cwe_start = classification.find('CWE-')
                        cwe_end = classification.find(' ', cwe_start)
                        if cwe_end == -1:
                            cwe_end = len(classification)
                        cwe_id = classification[cwe_start+4:cwe_end]
                        break
            
            # Determine vulnerability type
            vuln_type = self._determine_vuln_type_from_name_cwe(name, cwe_id)
            
            # Extract URL and request/response
            url = ''
            request = ''
            response = ''
            
            # Handle request response based on Burp version
            if 'evidence' in issue:
                for evidence in issue['evidence']:
                    if 'request_response' in evidence:
                        rr = evidence['request_response']
                        if 'url' in rr:
                            url = rr['url']
                        if 'request' in rr:
                            request = rr['request']
                        if 'response' in rr:
                            response = rr['response']
                        break
            elif 'request_response' in issue:
                rr = issue['request_response'][0] if isinstance(issue['request_response'], list) else issue['request_response']
                if 'url' in rr:
                    url = rr['url']
                if 'request' in rr:
                    request = rr['request']
                if 'response' in rr:
                    response = rr['response']
            elif 'host' in issue and 'path' in issue:
                url = f"{issue.get('protocol', 'https')}://{issue['host']}{issue['path']}"
            
            # Create finding
            finding = Finding(
                source_id=str(issue.get('serial_number', issue.get('id', hash(name)))),
                source_type="DAST-Burp",
                vulnerability_type=vuln_type,
                name=name,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cwe_id=cwe_id,
                raw_data={
                    'issue': issue,
                    'url': url,
                    'request': request,
                    'response': response
                }
            )
            
            return finding
        
        except Exception as e:
            logger.error(f"Error converting Burp issue to finding: {e}", exc_info=True)
            return None
    
    def _convert_generic_to_finding(self, item: Dict[str, Any]) -> Optional[Finding]:
        """
        Convert a generic DAST item to a Finding object.
        
        Args:
            item: Generic DAST item data
            
        Returns:
            Finding object or None
        """
        try:
            # Look for common field names
            name = None
            for field in ['name', 'title', 'alert', 'vulnerability', 'issue_name', 'issue_type']:
                if field in item:
                    name = item[field]
                    break
            
            if not name:
                name = "Unknown DAST Finding"
            
            # Look for description
            description = None
            for field in ['description', 'desc', 'details', 'detail', 'message']:
                if field in item:
                    description = item[field]
                    break
            
            if not description:
                description = ""
            
            # Look for severity
            severity_str = None
            for field in ['severity', 'risk', 'impact', 'criticality']:
                if field in item:
                    severity_str = str(item[field])
                    break
            
            # Map severity string to our levels
            severity = 'MEDIUM'  # Default
            cvss_score = 5.0  # Default
            
            if severity_str:
                severity_str = severity_str.lower()
                if severity_str in ['critical', 'crit', '0', 'p0']:
                    severity = 'CRITICAL'
                    cvss_score = 9.0
                elif severity_str in ['high', 'severe', 'important', '1', 'p1', '3']:
                    severity = 'HIGH'
                    cvss_score = 7.5
                elif severity_str in ['medium', 'moderate', 'warning', '2', 'p2']:
                    severity = 'MEDIUM'
                    cvss_score = 5.0
                elif severity_str in ['low', 'minor', 'info', '3', 'p3', '1']:
                    severity = 'LOW'
                    cvss_score = 3.0
                elif severity_str in ['informational', 'information', 'notice', '4', 'p4', '0']:
                    severity = 'INFORMATIONAL'
                    cvss_score = 0.0
            
            # Look for CVSS score (it might override the severity mapping)
            for field in ['cvss', 'cvss_score', 'score', 'cvss_base_score']:
                if field in item:
                    try:
                        cvss_score = float(item[field])
                        # Remap severity based on CVSS
                        if cvss_score >= SEVERITY_THRESHOLDS['CRITICAL']:
                            severity = 'CRITICAL'
                        elif cvss_score >= SEVERITY_THRESHOLDS['HIGH']:
                            severity = 'HIGH'
                        elif cvss_score >= SEVERITY_THRESHOLDS['MEDIUM']:
                            severity = 'MEDIUM'
                        elif cvss_score >= SEVERITY_THRESHOLDS['LOW']:
                            severity = 'LOW'
                        else:
                            severity = 'INFORMATIONAL'
                        break
                    except (ValueError, TypeError):
                        pass
            
            # Look for CWE ID
            cwe_id = None
            for field in ['cwe', 'cwe_id', 'cweid', 'cwe-id']:
                if field in item:
                    cwe_val = item[field]
                    if isinstance(cwe_val, str):
                        # Strip "CWE-" prefix if present
                        cwe_id = cwe_val.replace('CWE-', '')
                    elif isinstance(cwe_val, (int, float)):
                        cwe_id = str(int(cwe_val))
                    break
            
            # Determine vulnerability type
            vuln_type = self._determine_vuln_type_from_name_cwe(name, cwe_id)
            
            # Look for URL
            url = None
            for field in ['url', 'uri', 'location', 'link']:
                if field in item:
                    url = item[field]
                    break
            
            # Create finding
            finding = Finding(
                source_id=str(item.get('id', item.get('serial', hash(name)))),
                source_type="DAST-Generic",
                vulnerability_type=vuln_type,
                name=name,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cwe_id=cwe_id,
                raw_data={
                    'item': item,
                    'url': url
                }
            )
            
            return finding
        
        except Exception as e:
            logger.error(f"Error converting generic DAST item to finding: {e}", exc_info=True)
            return None
    
    def _determine_vuln_type_from_name_cwe(self, name: str, cwe_id: Optional[str] = None) -> str:
        """
        Determine vulnerability type from name and CWE ID.
        
        Args:
            name: Vulnerability name
            cwe_id: CWE ID if available
            
        Returns:
            Vulnerability type string
        """
        # Check CWE mapping first
        if cwe_id and cwe_id in CWE_TO_VULN_TYPE:
            return CWE_TO_VULN_TYPE[cwe_id]
        
        # Check name for keywords
        name_lower = name.lower()
        
        if 'sql' in name_lower and 'injection' in name_lower:
            return 'sql_injection'
        elif 'xss' in name_lower or 'cross-site script' in name_lower:
            return 'xss'
        elif ('path' in name_lower and 'traversal' in name_lower) or 'directory' in name_lower:
            return 'path_traversal'
        elif ('command' in name_lower or 'cmd' in name_lower or 'os' in name_lower) and 'injection' in name_lower:
            return 'command_injection'
        
        # Default to 'other' if we can't determine
        return 'other'
