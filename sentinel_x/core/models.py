"""
Data models for SENTINEL-X incident investigation
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from enum import Enum


class Severity(str, Enum):
    """Severity levels for incidents and alerts"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LogEntry(BaseModel):
    """Represents a single log entry"""
    timestamp: datetime
    source: str
    message: str
    severity: Severity = Severity.INFO
    metadata: Dict[str, Any] = Field(default_factory=dict)
    raw_data: Optional[str] = None


class Alert(BaseModel):
    """Represents a security alert"""
    alert_id: str
    timestamp: datetime
    alert_type: str
    severity: Severity
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    affected_assets: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Anomaly(BaseModel):
    """Represents a detected anomaly"""
    anomaly_id: str
    timestamp: datetime
    anomaly_type: str
    confidence: float
    description: str
    affected_entities: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)


class MitreMapping(BaseModel):
    """MITRE ATT&CK technique mapping"""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: List[str] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    """Event in the incident timeline"""
    timestamp: datetime
    event_type: str
    description: str
    source: str
    severity: Severity
    related_entities: List[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    """Investigation hypothesis"""
    hypothesis_id: str
    description: str
    confidence: float
    evidence_for: List[str] = Field(default_factory=list)
    evidence_against: List[str] = Field(default_factory=list)
    status: str = "active"  # active, confirmed, rejected


class IncidentReport(BaseModel):
    """Final incident report"""
    incident_id: str
    timestamp: datetime
    title: str
    summary: str
    severity: Severity
    root_cause: str
    affected_assets: List[str]
    timeline: List[TimelineEvent]
    mitre_mappings: List[MitreMapping]
    mitigation_actions: List[str]
    confidence: float
    is_incident: bool = True
    investigation_steps: List[str] = Field(default_factory=list)
    hypotheses: List[Hypothesis] = Field(default_factory=list)
