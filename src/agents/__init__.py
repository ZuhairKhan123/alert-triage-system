"""
Alert Triage System Agents Package

This package contains all the specialized agents that work together to process
security alerts through the complete triage workflow.
"""

from .alert_receiver import AlertReceiverAgent
from .false_positive_checker import FalsePositiveCheckerAgent
from .severity_analyzer import SeverityAnalyzerAgent
from .context_gatherer import ContextGathererAgent
from .response_coordinator import ResponseCoordinatorAgent
from .workflow_orchestrator import WorkflowOrchestratorAgent

__all__ = [
    "AlertReceiverAgent",
    "FalsePositiveCheckerAgent", 
    "SeverityAnalyzerAgent",
    "ContextGathererAgent",
    "ResponseCoordinatorAgent",
    "WorkflowOrchestratorAgent"
]

# Agent registry for dynamic loading
AGENT_REGISTRY = {
    "alert_receiver": AlertReceiverAgent,
    "false_positive_checker": FalsePositiveCheckerAgent,
    "severity_analyzer": SeverityAnalyzerAgent,
    "context_gatherer": ContextGathererAgent,
    "response_coordinator": ResponseCoordinatorAgent,
    "workflow_orchestrator": WorkflowOrchestratorAgent
}

def create_agent(agent_type: str, **kwargs):
    """Factory function to create agents dynamically"""
    if agent_type not in AGENT_REGISTRY:
        raise ValueError(f"Unknown agent type: {agent_type}")
    
    agent_class = AGENT_REGISTRY[agent_type]
    return agent_class(**kwargs)

def get_available_agents():
    """Get list of available agent types"""
    return list(AGENT_REGISTRY.keys())