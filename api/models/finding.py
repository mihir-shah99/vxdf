"""
Database models for representing security findings.
"""
import uuid
import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey, JSON, Enum
from sqlalchemy.orm import relationship

from api.models.database import Base

class Finding(Base):
    """
    Model representing a security finding from a scanner.
    """
    __tablename__ = "findings"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source_id = Column(String(255), nullable=True, index=True)  # Original ID from scanner
    source_type = Column(String(50), nullable=False)  # SARIF, CycloneDX, etc.
    vulnerability_type = Column(String(100), nullable=False)  # sql_injection, xss, etc.
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(50), nullable=True)  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score = Column(Float, nullable=True)
    cwe_id = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.UTC), onupdate=lambda: datetime.datetime.now(datetime.UTC))
    
    # Source code location information
    file_path = Column(String(1024), nullable=True)
    line_number = Column(Integer, nullable=True)
    column = Column(Integer, nullable=True)
    
    # Validation results
    is_validated = Column(Boolean, default=False)
    is_exploitable = Column(Boolean, nullable=True)  # True=confirmed, False=rejected, None=not validated
    validation_date = Column(DateTime, nullable=True)
    validation_message = Column(Text, nullable=True)
    validation_attempts = Column(Integer, default=0)
    
    # Raw data from source
    raw_data = Column(JSON, nullable=True)
    
    # VXDF output data
    vxdf_data = Column(JSON, nullable=True)


class Evidence(Base):
    """
    Model representing evidence for a security finding's exploitability.
    """
    __tablename__ = "evidence"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    evidence_type = Column(String(100), nullable=False)  # http_request, stack_trace, etc.
    description = Column(Text, nullable=True)
    content = Column(Text, nullable=False)  # The actual evidence data
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.UTC))


# Define relationship after both classes are defined
Finding.evidence = relationship("Evidence", cascade="all, delete-orphan")
