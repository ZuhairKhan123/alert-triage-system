"""
Message types and data structures for Coral Protocol communication
"""

import datetime
import uuid
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Dict, Any, Optional


class MessageType(Enum):
    """Standard message types for the Alert Triage workflow"""
    ALERT_RECEIVED = "alert_received"
    FALSE_POSITIVE_CHECK = "false_positive_check"
    SEVERITY_DETERMINATION = "severity_determination"
    CONTEXT_GATHERING = "context_gathering"
    RESPONSE_DECISION = "response_decision"
    WORKFLOW_COMPLETE = "workflow_complete"
    
    # System-level messages
    AGENT_REGISTRATION = "agent_registration"
    AGENT_DISCOVERY = "agent_discovery"
    HEARTBEAT = "heartbeat"
    ERROR = "error"
    
    # Custom workflow messages
    THREAT_HUNT_REQUEST = "threat_hunt_request"
    ESCALATION_REQUEST = "escalation_request"
    CONTAINMENT_ACTION = "containment_action"


class MessagePriority(Enum):
    """Message priority levels"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class CoralMessage:
    """
    Standardized message format for Coral Protocol
    
    This implements the core messaging structure defined in the Coral Protocol
    specification for secure, traceable agent communication.
    """
    id: str
    sender_id: str
    receiver_id: str
    message_type: MessageType
    thread_id: str
    payload: Dict[str, Any]
    timestamp: datetime.datetime
    priority: MessagePriority = MessagePriority.NORMAL
    reply_to: Optional[str] = None
    correlation_id: Optional[str] = None
    
    def __post_init__(self):
        """Validate message after initialization"""
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.thread_id:
            self.thread_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = datetime.datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary for serialization"""
        return {
            **asdict(self),
            'timestamp': self.timestamp.isoformat(),
            'message_type': self.message_type.value,
            'priority': self.priority.value
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CoralMessage':
        """Create message from dictionary"""
        data['timestamp'] = datetime.datetime.fromisoformat(data['timestamp'])
        data['message_type'] = MessageType(data['message_type'])
        data['priority'] = MessagePriority(data.get('priority', MessagePriority.NORMAL.value))
        return cls(**data)
    
    def create_reply(self, sender_id: str, payload: Dict[str, Any], 
                    message_type: Optional[MessageType] = None) -> 'CoralMessage':
        """Create a reply message to this message"""
        return CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=sender_id,
            receiver_id=self.sender_id,
            message_type=message_type or self.message_type,
            thread_id=self.thread_id,
            payload=payload,
            timestamp=datetime.datetime.now(),
            reply_to=self.id,
            correlation_id=self.correlation_id
        )


@dataclass 
class AgentCapability:
    """
    Agent capability definition for Coral registry
    
    Defines what an agent can do and how other agents can interact with it.
    """
    name: str
    description: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    version: str = "1.0.0"
    tags: Optional[list] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class AgentStatus:
    """Agent status information"""
    agent_id: str
    name: str
    status: str  # "online", "offline", "busy", "error"
    last_heartbeat: datetime.datetime
    message_queue_size: int = 0
    active_threads: int = 0
    processed_messages: int = 0
    error_count: int = 0


@dataclass
class WorkflowMetrics:
    """Metrics for workflow execution"""
    workflow_id: str
    start_time: datetime.datetime
    end_time: Optional[datetime.datetime] = None
    total_messages: int = 0
    agents_involved: int = 0
    status: str = "running"  # "running", "completed", "failed", "cancelled"
    error_message: Optional[str] = None
    
    @property
    def duration(self) -> Optional[datetime.timedelta]:
        """Calculate workflow duration"""
        if self.end_time:
            return self.end_time - self.start_time
        return None