"""
Data models for security alerts and related structures
"""

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """Types of security alerts"""
    MALWARE = "malware"
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    SUSPICIOUS_LOGIN = "suspicious_login"
    DATA_EXFILTRATION = "data_exfiltration"
    NETWORK_ANOMALY = "network_anomaly"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN_ATTACK = "supply_chain_attack"
    AI_ANOMALY = "ai_anomaly"
    CUSTOM_RULE_MATCH = "custom_rule_match"
    VULNERABILITY_EXPLOITATION = "vulnerability_exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_AND_CONTROL = "command_and_control"
    UNKNOWN = "unknown"


class AlertStatus(Enum):
    """Alert processing status"""
    NEW = "new"
    IN_PROGRESS = "in_progress"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    CLOSED = "closed"


class ResponseAction(Enum):
    """Possible response actions"""
    MONITOR = "monitor"
    INVESTIGATE = "investigate"
    CONTAIN = "contain"
    ISOLATE = "isolate"
    BLOCK_IP = "block_ip"
    DISABLE_USER = "disable_user"
    ESCALATE = "escalate"
    AUTO_RESOLVE = "auto_resolve"
    NOTIFY_ANALYST = "notify_analyst"
    CREATE_INCIDENT = "create_incident"
    PRESERVE_EVIDENCE = "preserve_evidence"


@dataclass
class SecurityAlert:
    """
    Core security alert data structure
    
    This represents a normalized security alert that can come from any source
    and be processed through the alert triage workflow.
    """
    # Core identification
    alert_id: str
    timestamp: datetime.datetime
    source_system: str
    alert_type: AlertType
    description: str
    
    # Network information
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    
    # User and asset information
    user_id: Optional[str] = None
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    
    # Additional metadata
    raw_data: Optional[Dict[str, Any]] = None
    tags: List[str] = field(default_factory=list)
    
    # Analysis results (filled by agents)
    status: AlertStatus = AlertStatus.NEW
    is_false_positive: Optional[bool] = None
    severity: Optional[AlertSeverity] = None
    confidence_score: Optional[float] = None
    context_data: Optional[Dict[str, Any]] = None
    recommended_actions: List[ResponseAction] = field(default_factory=list)
    assigned_analyst: Optional[str] = None
    
    # Workflow tracking
    workflow_id: Optional[str] = None
    processing_start_time: Optional[datetime.datetime] = None
    processing_end_time: Optional[datetime.datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for serialization"""
        result = {}
        for field_name, field_value in self.__dict__.items():
            if isinstance(field_value, Enum):
                result[field_name] = field_value.value
            elif isinstance(field_value, datetime.datetime):
                result[field_name] = field_value.isoformat()
            elif isinstance(field_value, list) and field_value and isinstance(field_value[0], Enum):
                result[field_name] = [item.value for item in field_value]
            else:
                result[field_name] = field_value
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityAlert':
        """Create alert from dictionary"""
        # Convert enum fields
        if 'alert_type' in data and isinstance(data['alert_type'], str):
            data['alert_type'] = AlertType(data['alert_type'])
        if 'status' in data and isinstance(data['status'], str):
            data['status'] = AlertStatus(data['status'])
        if 'severity' in data and isinstance(data['severity'], str):
            data['severity'] = AlertSeverity(data['severity'])
        
        # Convert datetime fields
        if 'timestamp' in data and isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.datetime.fromisoformat(data['timestamp'])
        if 'processing_start_time' in data and isinstance(data['processing_start_time'], str):
            data['processing_start_time'] = datetime.datetime.fromisoformat(data['processing_start_time'])
        if 'processing_end_time' in data and isinstance(data['processing_end_time'], str):
            data['processing_end_time'] = datetime.datetime.fromisoformat(data['processing_end_time'])
            
        # Convert action lists
        if 'recommended_actions' in data:
            actions = data['recommended_actions']
            if actions and isinstance(actions[0], str):
                data['recommended_actions'] = [ResponseAction(action) for action in actions]
                
        return cls(**data)


@dataclass
class ThreatIntelligence:
    """Threat intelligence data for an indicator"""
    indicator: str
    indicator_type: str  # ip, domain, hash, etc.
    reputation: str      # clean, suspicious, malicious
    confidence: float    # 0.0 - 1.0
    first_seen: Optional[datetime.datetime] = None
    last_seen: Optional[datetime.datetime] = None
    sources: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)


@dataclass
class UserContext:
    """User context information"""
    user_id: str
    username: str
    department: Optional[str] = None
    title: Optional[str] = None
    privilege_level: str = "standard"  # standard, elevated, admin
    last_login: Optional[datetime.datetime] = None
    login_count_24h: int = 0
    failed_login_count_24h: int = 0
    is_service_account: bool = False
    recent_activities: List[str] = field(default_factory=list)
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {}
        for field_name, field_value in self.__dict__.items():
            if isinstance(field_value, datetime.datetime):
                result[field_name] = field_value.isoformat()
            else:
                result[field_name] = field_value
        return result



@dataclass
class NetworkContext:
    """Network context information"""
    source_geolocation: Optional[Dict[str, str]] = None
    destination_geolocation: Optional[Dict[str, str]] = None
    network_segment: Optional[str] = None
    connection_count: int = 0
    data_volume: Optional[str] = None
    protocol_analysis: Optional[Dict[str, Any]] = None
    is_internal_communication: bool = False


@dataclass
class AnalysisResult:
    """Result of agent analysis"""
    agent_id: str
    agent_name: str
    analysis_type: str
    timestamp: datetime.datetime
    confidence: float
    result: Dict[str, Any]
    reasoning: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)


@dataclass
class WorkflowResult:
    """Complete workflow execution result"""
    workflow_id: str
    alert: SecurityAlert
    start_time: datetime.datetime
    end_time: datetime.datetime
    agents_involved: List[str]
    analysis_results: List[AnalysisResult]
    final_decision: str
    processing_time_seconds: float
    
    @property
    def success(self) -> bool:
        """Whether the workflow completed successfully"""
        return self.alert.status in [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE, AlertStatus.ESCALATED]


@dataclass
class IncidentTicket:
    """SOAR incident ticket"""
    ticket_id: str
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    status: str
    assigned_to: Optional[str] = None
    created_time: Optional[datetime.datetime] = None
    updated_time: Optional[datetime.datetime] = None
    soar_platform: str = "unknown"
    external_url: Optional[str] = None
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {}
        for field_name, field_value in self.__dict__.items():
            if isinstance(field_value, datetime.datetime):
                result[field_name] = field_value.isoformat()
            elif isinstance(field_value, Enum):
                result[field_name] = field_value.value
            else:
                result[field_name] = field_value
        return result


# Validation functions
def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        parts = ip.split('.')
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except (ValueError, AttributeError):
        return False


def validate_alert_data(alert_data: Dict[str, Any]) -> List[str]:
    """Validate alert data and return list of validation errors"""
    errors = []
    
    required_fields = ['alert_id', 'timestamp', 'source_system', 'alert_type', 'description']
    for field in required_fields:
        if field not in alert_data or not alert_data[field]:
            errors.append(f"Missing required field: {field}")
    
    # Validate IP addresses if present
    for ip_field in ['source_ip', 'destination_ip']:
        if ip_field in alert_data and alert_data[ip_field]:
            if not validate_ip_address(alert_data[ip_field]):
                errors.append(f"Invalid IP address format: {ip_field}")
    
    # Validate timestamp format
    if 'timestamp' in alert_data:
        try:
            if isinstance(alert_data['timestamp'], str):
                datetime.datetime.fromisoformat(alert_data['timestamp'])
        except ValueError:
            errors.append("Invalid timestamp format")
    
    # Validate alert type
    if 'alert_type' in alert_data:
        try:
            AlertType(alert_data['alert_type'])
        except ValueError:
            errors.append(f"Invalid alert type: {alert_data['alert_type']}")
    
    return errors


# Helper functions for common operations
def normalize_alert_data(raw_alert: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize alert data from various sources"""
    normalized = {}
    
    # Map common field variations
    field_mappings = {
        'id': 'alert_id',
        'time': 'timestamp',
        'src_ip': 'source_ip',
        'dst_ip': 'destination_ip',
        'type': 'alert_type',
        'desc': 'description',
        'message': 'description'
    }
    
    for key, value in raw_alert.items():
        mapped_key = field_mappings.get(key.lower(), key)
        normalized[mapped_key] = value
    
    # Ensure required defaults
    if 'timestamp' not in normalized:
        normalized['timestamp'] = datetime.datetime.now().isoformat()
    
    if 'status' not in normalized:
        normalized['status'] = AlertStatus.NEW.value
    
    return normalized


def calculate_risk_score(alert: SecurityAlert) -> float:
    """Calculate overall risk score for an alert"""
    score = 0.0
    
    # Base score from severity
    severity_scores = {
        AlertSeverity.LOW: 0.2,
        AlertSeverity.MEDIUM: 0.4,
        AlertSeverity.HIGH: 0.7,
        AlertSeverity.CRITICAL: 1.0
    }
    
    if alert.severity:
        score += severity_scores[alert.severity] * 0.4
    
    # Adjust based on confidence
    if alert.confidence_score:
        score *= alert.confidence_score
    
    # Adjust based on alert type
    high_risk_types = [
        AlertType.MALWARE,
        AlertType.DATA_EXFILTRATION,
        AlertType.PRIVILEGE_ESCALATION
    ]
    
    if alert.alert_type in high_risk_types:
        score += 0.2
    
    # External IP increases risk
    if alert.source_ip and not alert.source_ip.startswith(('10.', '192.168.', '172.')):
        score += 0.1
    
    return min(score, 1.0)