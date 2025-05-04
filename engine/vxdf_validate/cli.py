"""
Command-line interface for VXDF Validate.
"""
import os
import sys
import logging
import json
import time
from typing import List, Optional, Dict
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

from vxdf_validate import __version__
from vxdf_validate.utils.logger import setup_logging
from vxdf_validate.core.engine import ValidationEngine
from vxdf_validate.models.database import init_db
from vxdf_validate.parsers import ParserType, get_parser
from vxdf_validate.config import OUTPUT_DIR

# Configure console for rich output
console = Console()
logger = logging.getLogger(__name__)

@click.group()
@click.version_option(version=__version__)
@click.option('--debug/--no-debug', default=False, help='Enable debug logging')
def cli(debug):
    """
    VXDF Validate: Validate security findings and generate standardized VXDF output.
    """
    log_level = logging.DEBUG if debug else logging.INFO
    setup_logging()
    logging.getLogger().setLevel(log_level)
    
    # Initialize database
    init_db()

@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--type', 'parser_type', type=click.Choice(['sarif', 'cyclonedx', 'dast']), 
              help='Type of file to parse. If not provided, type will be auto-detected.')
@click.option('--output', '-o', type=click.Path(), 
              help='Output file for VXDF results. Default is a timestamped file in the output directory.')
@click.option('--validate/--no-validate', default=True, 
              help='Whether to validate findings or just parse and convert')
@click.option('--vuln-types', '-v', multiple=True, 
              type=click.Choice(['sql_injection', 'xss', 'path_traversal', 'command_injection', 'all']), 
              default=['all'], help='Vulnerability types to process')
@click.option('--min-severity', type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']), 
              default='LOW', help='Minimum severity to process')
@click.option('--target', '-t', help='Target application name for the VXDF document')
@click.option('--target-version', help='Target application version for the VXDF document')
@click.option('--max-findings', type=int, help='Maximum number of findings to process')
def process(file_path, parser_type, output, validate, vuln_types, min_severity, target, target_version, max_findings):
    """
    Process a security findings file and generate VXDF output.
    """
    try:
        # Determine parser type if not provided
        if not parser_type:
            parser_type = _detect_file_type(file_path)
            console.print(f"[bold blue]Auto-detected file type:[/] {parser_type}")
        
        # Initialize engine
        engine = ValidationEngine()
        
        # Set default output file if not provided
        if not output:
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"vxdf_results_{Path(file_path).stem}_{timestamp}.json"
            output = os.path.join(OUTPUT_DIR, filename)
        
        # Convert vuln_types to a list of actual types (handling 'all' special case)
        if 'all' in vuln_types:
            vuln_filter = None  # No filtering
        else:
            vuln_filter = list(vuln_types)
        
        # Process file
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            # Parse file
            parse_task = progress.add_task(f"Parsing {parser_type.upper()} file...", total=100)
            parser = get_parser(ParserType(parser_type))
            findings = parser.parse_file(file_path)
            progress.update(parse_task, completed=100)
            
            # Filter findings
            filter_task = progress.add_task("Filtering findings...", total=100)
            if vuln_filter or min_severity != 'INFORMATIONAL' or max_findings:
                original_count = len(findings)
                findings = engine.filter_findings(findings, vuln_types=vuln_filter, 
                                                min_severity=min_severity, max_count=max_findings)
                console.print(f"[bold]Filtered from {original_count} to {len(findings)} findings[/]")
            progress.update(filter_task, completed=100)
            
            # Validate if requested
            if validate:
                validate_task = progress.add_task("Validating findings...", total=len(findings))
                validated_findings = []
                
                for i, finding in enumerate(findings):
                    result = engine.validate_finding(finding)
                    validated_findings.append(result)
                    progress.update(validate_task, completed=i+1, 
                                    description=f"Validating finding {i+1}/{len(findings)}: {finding.name[:30]}...")
                
                findings = validated_findings
            
            # Generate VXDF
            vxdf_task = progress.add_task("Generating VXDF document...", total=100)
            vxdf_doc = engine.generate_vxdf(findings, target_name=target, target_version=target_version)
            progress.update(vxdf_task, completed=100)
            
            # Save output
            save_task = progress.add_task("Saving VXDF document...", total=100)
            os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
            with open(output, 'w', encoding='utf-8') as f:
                f.write(vxdf_doc.to_json(pretty=True))
            progress.update(save_task, completed=100)
        
        # Display summary
        _display_summary(vxdf_doc, output)
    
    except Exception as e:
        logger.error(f"Error processing file: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)

@cli.command()
@click.argument('vxdf_file', type=click.Path(exists=True))
def analyze(vxdf_file):
    """
    Analyze a VXDF file and display summary information.
    """
    try:
        from vxdf_validate.models.vxdf import VXDFDocument
        
        with open(vxdf_file, 'r', encoding='utf-8') as f:
            vxdf_content = f.read()
        
        vxdf_doc = VXDFDocument.from_json(vxdf_content)
        _display_summary(vxdf_doc, vxdf_file)
    
    except Exception as e:
        logger.error(f"Error analyzing VXDF file: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)

@cli.command()
def serve():
    """
    Start the VXDF Validate web server.
    """
    try:
        from vxdf_validate.server import app
        
        console.print("[bold green]Starting VXDF Validate web server...[/]")
        console.print("[bold]Visit:[/] http://localhost:5000")
        console.print("[bold]Press CTRL+C to stop[/]")
        
        # Start Flask server
        app.run(host='0.0.0.0', port=5000, debug=True)
    
    except Exception as e:
        logger.error(f"Error starting web server: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)

def _detect_file_type(file_path: str) -> str:
    """
    Auto-detect the type of security findings file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Detected parser type
    """
    file_ext = Path(file_path).suffix.lower()
    
    # Check extension first
    if file_ext == '.sarif':
        return 'sarif'
    elif file_ext in ['.cdx', '.xml', '.json']:
        # Could be CycloneDX, need to check content
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                first_chunk = f.read(1000)
                if '"bomFormat": "CycloneDX"' in first_chunk or '<bom xmlns="http://cyclonedx.org/schema/' in first_chunk:
                    return 'cyclonedx'
        except Exception:
            pass
    
    # Open and check content
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                
                # Check for SARIF format
                if '$schema' in data and 'sarif' in data['$schema']:
                    return 'sarif'
                elif 'version' in data and 'runs' in data:
                    return 'sarif'
                
                # Check for CycloneDX format
                if 'bomFormat' in data and data['bomFormat'] == 'CycloneDX':
                    return 'cyclonedx'
                
                # Default to DAST format for other JSON
                return 'dast'
            
            except json.JSONDecodeError:
                # Try to check if it's XML CycloneDX
                f.seek(0)
                first_chunk = f.read(1000)
                if '<bom xmlns="http://cyclonedx.org/schema/' in first_chunk:
                    return 'cyclonedx'
    
    except Exception:
        pass
    
    # Default to DAST if we can't determine
    return 'dast'

def _display_summary(vxdf_doc, output_file):
    """
    Display a summary of the VXDF document.
    
    Args:
        vxdf_doc: VXDF document
        output_file: Path to the output file
    """
    # Ensure the document has a summary
    if not vxdf_doc.summary:
        vxdf_doc.generate_summary()
    
    # Create summary table
    summary = vxdf_doc.summary
    
    console.print("\n[bold green]VXDF Document Summary[/]")
    console.print(f"Generated by: [bold]{vxdf_doc.metadata.generator_name} {vxdf_doc.metadata.generator_version}[/]")
    console.print(f"Target application: [bold]{vxdf_doc.metadata.target_application}[/]", end="")
    if vxdf_doc.metadata.target_version:
        console.print(f" version [bold]{vxdf_doc.metadata.target_version}[/]")
    else:
        console.print()
    
    # Findings statistics
    console.print("\n[bold]Findings Statistics:[/]")
    stats_table = Table(show_header=True, header_style="bold blue")
    stats_table.add_column("Metric", style="dim")
    stats_table.add_column("Count", justify="right")
    
    stats_table.add_row("Total Flows", str(summary.total_flows))
    stats_table.add_row("Confirmed Exploitable", str(summary.exploitable_flows))
    stats_table.add_row("Confirmed Non-Exploitable", str(summary.non_exploitable_flows))
    
    console.print(stats_table)
    
    # Severity breakdown
    if summary.by_severity:
        console.print("\n[bold]Severity Breakdown:[/]")
        severity_table = Table(show_header=True, header_style="bold blue")
        severity_table.add_column("Severity")
        severity_table.add_column("Count", justify="right")
        
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        for severity in severity_order:
            if severity in summary.by_severity:
                style = "red" if severity == "CRITICAL" else (
                    "orange3" if severity == "HIGH" else (
                    "yellow" if severity == "MEDIUM" else (
                    "green" if severity == "LOW" else "blue"
                )))
                severity_table.add_row(f"[{style}]{severity}[/{style}]", str(summary.by_severity[severity]))
        
        console.print(severity_table)
    
    # Vulnerability type breakdown
    if summary.by_vulnerability_type:
        console.print("\n[bold]Vulnerability Type Breakdown:[/]")
        vuln_table = Table(show_header=True, header_style="bold blue")
        vuln_table.add_column("Vulnerability Type")
        vuln_table.add_column("Count", justify="right")
        
        for vuln_type, count in sorted(summary.by_vulnerability_type.items(), key=lambda x: x[1], reverse=True):
            vuln_table.add_row(vuln_type, str(count))
        
        console.print(vuln_table)
    
    # Output information
    console.print(f"\n[bold green]VXDF document saved to:[/] {output_file}")
    
    # Sample usage
    console.print("\n[bold blue]Next steps:[/]")
    console.print("  - Analyze: [bold]vxdf analyze " + output_file + "[/]")
    console.print("  - Serve: [bold]vxdf serve[/] (to view in web interface)")

if __name__ == '__main__':
    cli()
