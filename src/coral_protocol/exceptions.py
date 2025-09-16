"""
Exception classes for Coral Protocol
"""


class CoralException(Exception):
    """Base exception for all Coral Protocol errors"""
    
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}


class AgentRegistrationError(CoralException):
    """Raised when agent registration fails"""
    
    def __init__(self, agent_id: str, reason: str):
        super().__init__(
            f"Failed to register agent '{agent_id}': {reason}",
            error_code="AGENT_REGISTRATION_FAILED",
            details={"agent_id": agent_id, "reason": reason}
        )


class MessageRoutingError(CoralException):
    """Raised when message routing fails"""
    
    def __init__(self, message_id: str, receiver_id: str, reason: str):
        super().__init__(
            f"Failed to route message '{message_id}' to agent '{receiver_id}': {reason}",
            error_code="MESSAGE_ROUTING_FAILED",
            details={
                "message_id": message_id,
                "receiver_id": receiver_id,
                "reason": reason
            }
        )


class AgentNotFoundError(CoralException):
    """Raised when an agent cannot be found"""
    
    def __init__(self, agent_id: str):
        super().__init__(
            f"Agent '{agent_id}' not found in registry",
            error_code="AGENT_NOT_FOUND",
            details={"agent_id": agent_id}
        )


class CapabilityNotFoundError(CoralException):
    """Raised when a required capability is not found"""
    
    def __init__(self, capability_name: str):
        super().__init__(
            f"No agents found with capability '{capability_name}'",
            error_code="CAPABILITY_NOT_FOUND",
            details={"capability_name": capability_name}
        )


class MessageValidationError(CoralException):
    """Raised when message validation fails"""
    
    def __init__(self, message_id: str, validation_errors: list):
        super().__init__(
            f"Message '{message_id}' failed validation: {', '.join(validation_errors)}",
            error_code="MESSAGE_VALIDATION_FAILED",
            details={
                "message_id": message_id,
                "validation_errors": validation_errors
            }
        )


class WorkflowTimeoutError(CoralException):
    """Raised when a workflow times out"""
    
    def __init__(self, workflow_id: str, timeout_seconds: int):
        super().__init__(
            f"Workflow '{workflow_id}' timed out after {timeout_seconds} seconds",
            error_code="WORKFLOW_TIMEOUT",
            details={
                "workflow_id": workflow_id,
                "timeout_seconds": timeout_seconds
            }
        )


class AgentBusyError(CoralException):
    """Raised when an agent is too busy to process messages"""
    
    def __init__(self, agent_id: str, queue_size: int, max_queue_size: int):
        super().__init__(
            f"Agent '{agent_id}' is busy (queue size: {queue_size}/{max_queue_size})",
            error_code="AGENT_BUSY",
            details={
                "agent_id": agent_id,
                "queue_size": queue_size,
                "max_queue_size": max_queue_size
            }
        )


class SecurityViolationError(CoralException):
    """Raised when a security violation is detected"""
    
    def __init__(self, agent_id: str, violation_type: str, details: str):
        super().__init__(
            f"Security violation by agent '{agent_id}': {violation_type} - {details}",
            error_code="SECURITY_VIOLATION",
            details={
                "agent_id": agent_id,
                "violation_type": violation_type,
                "violation_details": details
            }
        )