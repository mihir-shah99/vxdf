#!/usr/bin/env python3
"""
🔍 VXDF SARIF Validator
A beautiful CLI tool to validate SARIF files and generate VXDF reports.
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import time
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich import print as rprint
from rich.syntax import Syntax

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from api.core.engine import ValidationEngine
from api.parsers.sarif_parser import SarifParser
from api.core.validator import ValidatorFactory
from api.models.vxdf import VXDFModel

# Initialize Rich console
console = Console()

# Configure logging with custom formatter
class ColorFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno >= logging.ERROR:
            return f"❌ {super().format(record)}"
        elif record.levelno >= logging.WARNING:
            return f"⚠️  {super().format(record)}"
        else:
            return f"ℹ️  {super().format(record)}"

handler = logging.StreamHandler()
handler.setFormatter(ColorFormatter('%(message)s'))
logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def print_banner():
    """Print a beautiful banner."""
    banner = """
    ██╗   ██╗██╗  ██╗██████╗ ███████╗
    ██║   ██║╚██╗██╔╝██╔══██╗██╔════╝
    ██║   ██║ ╚███╔╝ ██║  ██║█████╗  
    ╚██╗ ██╔╝ ██╔██╗ ██║  ██║██╔══╝  
     ╚████╔╝ ██╔╝ ██╗██████╔╝██║     
      ╚═══╝  ╚═╝  ╚═╝╚═════╝ ╚═╝     
    """
    console.print(Panel(banner, 
                       title="[bold cyan]VXDF SARIF Validator[/]", 
                       subtitle="[italic]Validating security findings with style[/]",
                       style="bold magenta"))

def print_summary(vxdf_report: Dict[str, Any]):
    """Print a beautiful summary of the VXDF report."""
    console.print("\n🎯 [bold cyan]Validation Summary[/]")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Finding", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("Location", style="blue")
    
    for flow in vxdf_report["exploitFlows"]:
        status_color = {
            "OPEN": "[red]⚠️  EXPLOITABLE[/]",
            "FALSE_POSITIVE_AFTER_REVALIDATION": "[green]✅ NOT EXPLOITABLE[/]"
        }.get(flow["status"], flow["status"])
        
        severity_icon = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFORMATIONAL": "⚪"
        }.get(flow["severity"]["level"], "⚪")
        
        table.add_row(
            flow["title"],
            status_color,
            f"{severity_icon} {flow['severity']['level']}",
            f"{flow['source']['filePath']}:{flow['source']['startLine']}"
        )
    
    console.print(table)

def print_detailed_summary(vxdf_report: Dict[str, Any]):
    """Print a detailed human-readable summary of exploitable findings."""
    exploitable_flows = [flow for flow in vxdf_report["exploitFlows"] if flow["status"] == "OPEN"]
    
    if not exploitable_flows:
        console.print("\n🎉 [green]No exploitable vulnerabilities found![/]")
        return
    
    console.print("\n🚨 [bold red]Exploitable Vulnerabilities Details[/]")
    console.print("[bold yellow]═══════════════════════════════════[/]\n")
    
    # Print application info
    app_info = vxdf_report["applicationInfo"]
    console.print(Panel(
        f"[bold cyan]Application:[/] {app_info['name']}\n" +
        (f"[bold cyan]Version:[/] {app_info['version']}\n" if app_info['version'] else "") +
        (f"[bold cyan]Repository:[/] {app_info['repositoryUrl']}\n" if app_info['repositoryUrl'] else "") +
        f"[bold cyan]Report Generated:[/] {vxdf_report['generatedAt']}",
        title="[bold blue]Scan Information[/]",
        border_style="blue"
    ))
    console.print()
    
    for i, flow in enumerate(exploitable_flows, 1):
        # Create sections for the finding
        basic_info = [
            f"[bold cyan]Finding ID:[/] {flow['title']}",
            f"[bold cyan]Category:[/] {flow['category']}",
            f"[bold cyan]Severity:[/] {flow['severity']['level']}"
        ]
        
        if flow['severity'].get('cvssV3_1'):
            basic_info.append(f"[bold cyan]CVSS v3.1:[/] {flow['severity']['cvssV3_1']}")
        if flow['severity'].get('cvssV4_0'):
            basic_info.append(f"[bold cyan]CVSS v4.0:[/] {flow['severity']['cvssV4_0']}")
        
        # Location information
        location_info = []
        if flow['source']:
            src = flow['source']
            location_info.extend([
                "[bold cyan]Source Location:[/]",
                f"• File: {src['filePath']}",
                f"• Line: {src['startLine']}" + (f"-{src['endLine']}" if src['endLine'] else ""),
                f"• Column: {src['startColumn']}" + (f"-{src['endColumn']}" if src['endColumn'] else "")
            ])
            if src.get('httpMethod'):
                location_info.append(f"• HTTP Method: {src['httpMethod']}")
            if src.get('parameterName'):
                location_info.append(f"• Parameter: {src['parameterName']}")
            if src.get('headerName'):
                location_info.append(f"• Header: {src['headerName']}")
        
        # Vulnerability details
        vuln_details = [
            "[bold cyan]Description:[/]",
            flow['description'] if flow['description'] else "No description available"
        ]
        
        if flow.get('cwes'):
            vuln_details.extend([
                "",
                "[bold cyan]CWE IDs:[/]",
                "• " + "\n• ".join(str(cwe) for cwe in flow['cwes'])
            ])
        
        # Evidence and validation
        evidence_details = ["[bold cyan]Evidence & Validation:[/]"]
        for evidence in flow['evidence']:
            evidence_details.extend([
                f"• Type: {evidence['evidenceType']}",
                f"• Method: {evidence['validationMethod']}",
                f"• Details: {evidence['data']['dataContent']}"
            ])
            if evidence['data'].get('dataTypeDescription'):
                evidence_details.append(f"  Additional Info: {evidence['data']['dataTypeDescription']}")
        
        # Exploitation trace
        trace_details = []
        if flow.get('trace'):
            trace_details.extend([
                "",
                "[bold cyan]Exploitation Path:[/]"
            ])
            for step in sorted(flow['trace'], key=lambda x: x['order']):
                trace_details.extend([
                    f"Step {step['order'] + 1}:",
                    f"• Type: {step['stepType']}",
                    f"• Description: {step['description']}"
                ])
        
        # Remediation
        remediation_details = []
        if flow.get('remediationRecommendations'):
            remediation_details.extend([
                "",
                "[bold cyan]Remediation Recommendations:[/]",
                flow['remediationRecommendations']
            ])
        
        # OWASP Categories
        owasp_details = []
        if flow.get('owaspTopTenCategories'):
            owasp_details.extend([
                "",
                "[bold cyan]OWASP Top 10 Categories:[/]",
                "• " + "\n• ".join(flow['owaspTopTenCategories'])
            ])
        
        # Combine all sections
        all_details = (
            basic_info + 
            [""] + location_info +
            [""] + vuln_details +
            [""] + evidence_details +
            trace_details +
            remediation_details +
            owasp_details
        )
        
        # Create the main panel for this finding
        console.print(Panel(
            "\n".join(all_details),
            title=f"[bold red]Exploitable Finding #{i}[/]",
            border_style="red"
        ))
        console.print()  # Add spacing between findings

def print_statistics(vxdf_report: Dict[str, Any]):
    """Print statistical insights about the findings."""
    flows = vxdf_report["exploitFlows"]
    
    # Count by severity
    severity_counts = {}
    for flow in flows:
        severity = flow["severity"]["level"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Count by status
    status_counts = {}
    for flow in flows:
        status = flow["status"]
        status_counts[status] = status_counts.get(status, 0) + 1
    
    # Count by category
    category_counts = {}
    for flow in flows:
        category = flow["category"]
        category_counts[category] = category_counts.get(category, 0) + 1
    
    # Create statistics table
    stats_table = Table(title="[bold cyan]Vulnerability Statistics[/]", show_header=True, header_style="bold magenta")
    
    # Severity statistics
    stats_table.add_row(
        "Severity Distribution",
        "\n".join([f"{severity}: {count} finding(s)" for severity, count in severity_counts.items()])
    )
    
    # Status statistics
    stats_table.add_row(
        "Status Distribution",
        "\n".join([f"{status}: {count} finding(s)" for status, count in status_counts.items()])
    )
    
    # Category statistics
    stats_table.add_row(
        "Category Distribution",
        "\n".join([f"{category}: {count} finding(s)" for category, count in category_counts.items()])
    )
    
    console.print("\n[bold cyan]Statistical Insights[/]")
    console.print("[bold yellow]═══════════════════[/]\n")
    console.print(stats_table)
    console.print()

def validate_sarif(input_file: str, output_dir: str) -> bool:
    """
    Validate a SARIF file and generate a VXDF report.
    
    Args:
        input_file: Path to input SARIF file
        output_dir: Directory to store the VXDF report
    
    Returns:
        bool: True if validation was successful
    """
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            # Initialize components
            init_task = progress.add_task("🚀 Initializing validation engine...", total=1)
            engine = ValidationEngine()
            sarif_parser = SarifParser()
            validator_factory = ValidatorFactory()
            progress.update(init_task, completed=1)
            
            # Parse SARIF file
            parse_task = progress.add_task("📝 Parsing SARIF file...", total=1)
            with open(input_file, 'r') as f:
                sarif_data = json.load(f)
            findings = sarif_parser.parse_file(input_file)
            progress.update(parse_task, completed=1)
            
            console.print(f"\n🔍 Found [bold cyan]{len(findings)}[/] findings to validate")
            
            # Validate each finding
            validate_task = progress.add_task("🔬 Validating findings...", total=len(findings))
            validated_count = 0
            
            for i, finding in enumerate(findings, 1):
                console.print(f"\n[bold]Finding {i}/{len(findings)}:[/] {finding.name}")
                
                # Get appropriate validator
                validator = validator_factory.get_validator(finding.vulnerability_type)
                console.print(f"Using validator: [italic]{validator.__class__.__name__}[/]")
                
                try:
                    # Setup validation environment
                    container = engine.setup_validation_container(finding)
                    console.print("🐳 Docker container ready")
                    
                    # Perform validation
                    validation_result = validator.validate(finding)
                    if validation_result.is_exploitable:
                        status = "[bold red]✋ Exploitable[/]"
                        validated_count += 1
                    else:
                        status = "[bold green]✅ Not exploitable[/]"
                    console.print(f"Validation complete: {status}")
                    
                    # Collect evidence
                    evidence = engine.collect_evidence(finding, validation_result)
                    console.print(f"📊 Collected {len(evidence)} pieces of evidence")
                    
                    # Update finding with validation results
                    finding.is_validated = validation_result.is_validated
                    finding.is_exploitable = validation_result.is_exploitable
                    finding.validation_message = validation_result.message
                    finding.evidence = evidence
                    
                except Exception as e:
                    logger.error(f"Error validating finding: {e}")
                    continue
                finally:
                    # Cleanup validation environment
                    engine.cleanup_validation_container(container)
                    console.print("🧹 Cleaned up validation container")
                
                progress.update(validate_task, completed=validated_count)
            
            # Generate VXDF report
            report_task = progress.add_task("📊 Generating VXDF report...", total=1)
            vxdf_report = engine.generate_vxdf(
                findings,
                target_name=f"SARIF Validation Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            
            # Save VXDF report
            output_file = os.path.join(output_dir, f"validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.vxdf.json")
            with open(output_file, 'w') as f:
                vxdf_dict = vxdf_report.model_dump(mode='json')
                json.dump(vxdf_dict, f, indent=2, default=str)
            
            progress.update(report_task, completed=1)
            
            # Print summaries
            print_summary(vxdf_dict)
            print_statistics(vxdf_dict)
            print_detailed_summary(vxdf_dict)
            
            console.print(f"\n✨ VXDF report saved to: [bold cyan]{output_file}[/]")
            return True
            
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Validate SARIF files and generate VXDF reports",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("input", help="Path to input SARIF file")
    parser.add_argument("--output-dir", default="output", help="Directory to store VXDF report (default: output)")
    
    args = parser.parse_args()
    
    print_banner()
    
    console.print(f"\n📁 Input file: [bold cyan]{args.input}[/]")
    console.print(f"📂 Output directory: [bold cyan]{args.output_dir}[/]\n")
    
    success = validate_sarif(args.input, args.output_dir)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 