"""
Coral Protocol Framework for Multi-Agent AI Systems
A Python implementation of the Coral Protocol for secure agent coordination
"""

from .agent_base import CoralAgent, AgentCapability
from .message_types import CoralMessage, MessageType
from .registry import CoralRegistry
from .exceptions import CoralException, AgentRegistrationError, MessageRoutingError

__version__ = "1.0.0"
__author__ = "Alert Triage System Team"

__all__ = [
    "CoralAgent",
    "AgentCapability", 
    "CoralMessage",
    "MessageType",
    "CoralRegistry",
    "CoralException",
    "AgentRegistrationError",
    "MessageRoutingError"
]