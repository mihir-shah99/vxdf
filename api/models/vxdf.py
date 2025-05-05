"""
Models for representing VXDF (Validated Exploitable Data Flow) data structures.
"""
import uuid
import datetime
import json
from typing import List, Dict, Optional, Any, Union
from enum import Enum
from pydantic import BaseModel, Field, validator

class SeverityLevel(str, Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

class CodeLocation(BaseModel):
    """Represents a location in code."""
    file_path: str = Field(..., description="Path to the file")
    line_number: Optional[int] = Field(None, description="Line number")
    column: Optional[int] = Field(None, description="Column number")
    code_snippet: Optional[str] = Field(None, description="Code snippet")

class DataFlowStep(BaseModel):
    """Represents a step in a data flow."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique ID for the step")
    description: str = Field(..., description="Description of this step")
    location: CodeLocation = Field(..., description="Location in code")
    step_type: str = Field(default="intermediate", description="Type of step (source, sink, intermediate)")
    value: Optional[str] = Field(None, description="Value at this point in the flow")

class EvidenceItem(BaseModel):
    """Represents a piece of evidence supporting exploitability."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique ID for this evidence")
    type: str = Field(..., description="Type of evidence (http_request, stack_trace, etc.)")
    description: str = Field(..., description="Description of what this evidence proves")
    content: str = Field(..., description="The actual evidence content")
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, description="When this evidence was generated")
    reproduction_steps: Optional[str] = Field(None, description="Steps to reproduce this evidence")
    related_step_id: Optional[str] = Field(None, description="ID of the data flow step this evidence relates to")
    requires_manual_verification: bool = Field(default=False, description="Whether this evidence requires manual verification")

class VXDFFlow(BaseModel):
    """Represents a single validated exploitable data flow."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique ID for this flow")
    name: str = Field(..., description="Short name for this vulnerability")
    description: str = Field(..., description="Detailed description of the vulnerability")
    vulnerability_type: str = Field(..., description="Type of vulnerability (e.g., sql_injection)")
    cwe_id: Optional[str] = Field(None, description="CWE identifier for this vulnerability type")
    severity: SeverityLevel = Field(..., description="Severity level of this vulnerability")
    cvss_score: Optional[float] = Field(None, description="CVSS score if available")
    source: CodeLocation = Field(..., description="Source location where untrusted data enters")
    sink: CodeLocation = Field(..., description="Sink location where the vulnerability occurs")
    steps: List[DataFlowStep] = Field(default_factory=list, description="Steps in the data flow from source to sink")
    evidence: List[EvidenceItem] = Field(..., description="Evidence supporting exploitability")
    is_exploitable: bool = Field(..., description="Whether this flow is confirmed to be exploitable")
    validation_date: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, description="When this flow was validated")
    validation_message: Optional[str] = Field(None, description="Additional message about validation")
    mitigation: Optional[str] = Field(None, description="Suggested mitigation for this vulnerability")
    raw_finding_id: Optional[str] = Field(None, description="ID of the original finding in the source")
    
    # Optional vendor-specific fields
    x_extensions: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Vendor-specific extensions")

class VXDFMetadata(BaseModel):
    """Metadata for a VXDF document."""
    version: str = Field("1.0", description="VXDF schema version")
    generated_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, description="When this document was generated")
    generator_name: str = Field("VXDF Validate", description="Name of the tool that generated this document")
    generator_version: str = Field(..., description="Version of the generator tool")
    target_application: str = Field(..., description="Name of the application that was analyzed")
    target_version: Optional[str] = Field(None, description="Version of the target application")
    target_context: Optional[str] = Field(None, description="Context or environment of the target")

class VXDFSummary(BaseModel):
    """Summary statistics for a VXDF document."""
    total_flows: int = Field(0, description="Total number of flows in the document")
    exploitable_flows: int = Field(0, description="Number of confirmed exploitable flows")
    non_exploitable_flows: int = Field(0, description="Number of confirmed non-exploitable flows")
    by_severity: Dict[str, int] = Field(default_factory=dict, description="Count of flows by severity")
    by_vulnerability_type: Dict[str, int] = Field(default_factory=dict, description="Count of flows by vulnerability type")

class VXDFDocument(BaseModel):
    """Top-level VXDF document."""
    metadata: VXDFMetadata = Field(..., description="Metadata about this document")
    flows: List[VXDFFlow] = Field(..., description="List of validated exploitable data flows")
    summary: Optional[VXDFSummary] = Field(None, description="Summary statistics")
    
    def to_json(self, pretty: bool = False) -> str:
        """
        Convert to JSON string.
        
        Args:
            pretty: Whether to format with indentation
            
        Returns:
            JSON string representation
        """
        # Create a custom JSON encoder to handle datetime objects
        class DateTimeEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, datetime.datetime):
                    return obj.isoformat()
                return super().default(obj)
        
        if pretty:
            return json.dumps(self.dict(), indent=2, cls=DateTimeEncoder)
        else:
            return json.dumps(self.dict(), cls=DateTimeEncoder)
    
    @classmethod
    def from_json(cls, json_str: str) -> "VXDFDocument":
        """
        Create a VXDF document from a JSON string.
        
        Args:
            json_str: JSON string to parse.
            
        Returns:
            VXDFDocument: Parsed VXDF document.
        """
        data = json.loads(json_str)
        return cls.parse_obj(data)
    
    def generate_summary(self) -> None:
        """
        Generate summary statistics for this document.
        """
        summary = VXDFSummary(
            total_flows=len(self.flows),
            exploitable_flows=sum(1 for flow in self.flows if flow.is_exploitable),
            non_exploitable_flows=sum(1 for flow in self.flows if not flow.is_exploitable)
        )
        
        # Count by severity
        by_severity = {}
        for flow in self.flows:
            if flow.severity in by_severity:
                by_severity[flow.severity] += 1
            else:
                by_severity[flow.severity] = 1
        summary.by_severity = by_severity
        
        # Count by vulnerability type
        by_type = {}
        for flow in self.flows:
            if flow.vulnerability_type in by_type:
                by_type[flow.vulnerability_type] += 1
            else:
                by_type[flow.vulnerability_type] = 1
        summary.by_vulnerability_type = by_type
        
        self.summary = summary
