"""
Workflow Orchestrator Agent - Manages the overall alert triage workflow
"""

import datetime
import uuid
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from coral_protocol import CoralAgent, AgentCapability, CoralMessage, MessageType
from models.alert_models import SecurityAlert, WorkflowResult, AnalysisResult, AlertStatus
from utils.logging_config import SecurityAuditLogger, PerformanceLogger


logger = logging.getLogger(__name__)


@dataclass
class WorkflowStep:
    """Individual workflow step tracking"""
    step_name: str
    agent_id: str
    start_time: datetime.datetime
    end_time: Optional[datetime.datetime] = None
    status: str = "pending"  # pending, in_progress, completed, failed
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    
    @property
    def duration(self) -> Optional[float]:
        """Calculate step duration in seconds"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None


class WorkflowOrchestratorAgent(CoralAgent):
    """
    Main orchestrator that manages the complete alert triage workflow
    
    This agent:
    1. Initiates new workflows
    2. Tracks workflow progress
    3. Handles workflow completion
    4. Manages workflow failures and recovery
    5. Provides workflow status and metrics
    6. Coordinates workflow optimization
    """
    
    def __init__(self):
        capabilities = [
            AgentCapability(
                name="orchestrate_workflow",
                description="Orchestrate the complete alert triage workflow from start to finish",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert_data": {"type": "object"},
                        "workflow_options": {"type": "object"}
                    },
                    "required": ["alert_data"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "workflow_id": {"type": "string"},
                        "status": {"type": "string"},
                        "estimated_completion": {"type": "string"}
                    }
                }
            ),
            AgentCapability(
                name="monitor_workflow",
                description="Monitor and track workflow execution progress",
                input_schema={
                    "type": "object",
                    "properties": {
                        "workflow_id": {"type": "string"}
                    }
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "workflow_status": {"type": "object"},
                        "progress_percentage": {"type": "number"},
                        "current_step": {"type": "string"}
                    }
                }
            )
        ]
        
        super().__init__(
            agent_id="workflow_orchestrator",
            name="Workflow Orchestrator",
            capabilities=capabilities
        )
        
        # Workflow tracking
        self.active_workflows = {}  # workflow_id -> workflow_info
        self.completed_workflows = {}  # workflow_id -> WorkflowResult
        self.workflow_templates = {}
        
        # Performance tracking
        self.total_workflows = 0
        self.successful_workflows = 0
        self.failed_workflows = 0
        self.average_processing_time = 0.0
        
        # Specialized loggers
        self.security_logger = SecurityAuditLogger()
        self.performance_logger = PerformanceLogger()
        
        # Configuration
        self.workflow_timeout = 300  # 5 minutes default
        self.max_concurrent_workflows = 100
        
        # Initialize workflow templates
        self._initialize_workflow_templates()
        
    def _initialize_workflow_templates(self):
        """Initialize workflow templates for different scenarios"""
        
        # Standard alert triage workflow
        self.workflow_templates["standard_triage"] = {
            "name": "Standard Alert Triage",
            "steps": [
                {
                    "name": "alert_reception",
                    "agent": "alert_receiver",
                    "timeout": 30,
                    "required": True
                },
                {
                    "name": "false_positive_check",
                    "agent": "false_positive_checker", 
                    "timeout": 60,
                    "required": True
                },
                {
                    "name": "severity_analysis",
                    "agent": "severity_analyzer",
                    "timeout": 45,
                    "required": True
                },
                {
                    "name": "context_gathering",
                    "agent": "context_gatherer",
                    "timeout": 90,
                    "required": True
                },
                {
                    "name": "response_coordination",
                    "agent": "response_coordinator",
                    "timeout": 60,
                    "required": True
                }
            ],
            "estimated_duration": 285,  # sum of timeouts
            "success_criteria": ["response_coordination"]
        }
        
        # Fast-track workflow for low-severity alerts
        self.workflow_templates["fast_track"] = {
            "name": "Fast Track Workflow",
            "steps": [
                {
                    "name": "alert_reception",
                    "agent": "alert_receiver",
                    "timeout": 15,
                    "required": True
                },
                {
                    "name": "false_positive_check",
                    "agent": "false_positive_checker",
                    "timeout": 30,
                    "required": True
                },
                {
                    "name": "basic_response",
                    "agent": "response_coordinator",
                    "timeout": 30,
                    "required": True
                }
            ],
            "estimated_duration": 75,
            "success_criteria": ["basic_response"]
        }
        
        # Enhanced workflow for critical alerts
        self.workflow_templates["critical_enhanced"] = {
            "name": "Critical Alert Enhanced Workflow",
            "steps": [
                {
                    "name": "alert_reception",
                    "agent": "alert_receiver",
                    "timeout": 20,
                    "required": True
                },
                {
                    "name": "severity_analysis",
                    "agent": "severity_analyzer",
                    "timeout": 30,
                    "required": True
                },
                {
                    "name": "threat_hunting",
                    "agent": "threat_hunter",
                    "timeout": 120,
                    "required": False
                },
                {
                    "name": "context_gathering",
                    "agent": "context_gatherer",
                    "timeout": 60,
                    "required": True
                },
                {
                    "name": "response_coordination",
                    "agent": "response_coordinator",
                    "timeout": 45,
                    "required": True
                }
            ],
            "estimated_duration": 275,
            "success_criteria": ["response_coordination"]
        }
        
    async def handle_message(self, message: CoralMessage):
        """Handle incoming messages"""
        if message.message_type == MessageType.WORKFLOW_COMPLETE:
            await self._handle_workflow_completion(message)
        elif message.message_type == MessageType.ERROR:
            await self._handle_workflow_error(message)
        else:
            logger.warning(f"Unexpected message type: {message.message_type}")
            
    async def start_alert_triage_workflow(self, alert_data: Dict[str, Any], 
                                        workflow_type: str = "standard_triage") -> str:
        """Start a new alert triage workflow"""
        
        if len(self.active_workflows) >= self.max_concurrent_workflows:
            raise RuntimeError("Maximum concurrent workflows reached")
            
        # Generate workflow ID
        workflow_id = f"workflow_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Select workflow template
        template = self.workflow_templates.get(workflow_type, self.workflow_templates["standard_triage"])
        
        # Initialize workflow tracking
        workflow_info = {
            "workflow_id": workflow_id,
            "template_name": template["name"],
            "alert_data": alert_data,
            "start_time": datetime.datetime.now(),
            "status": "initiated",
            "current_step": 0,
            "steps": [],
            "estimated_completion": datetime.datetime.now() + datetime.timedelta(seconds=template["estimated_duration"]),
            "error_count": 0,
            "retry_count": 0
        }
        
        # Initialize workflow steps
        for i, step_config in enumerate(template["steps"]):
            step = WorkflowStep(
                step_name=step_config["name"],
                agent_id=step_config["agent"],
                start_time=datetime.datetime.now() if i == 0 else None,
                status="pending" if i > 0 else "in_progress"
            )
            workflow_info["steps"].append(step)
            
        self.active_workflows[workflow_id] = workflow_info
        self.total_workflows += 1
        
        # Start the workflow by sending initial message
        await self._start_workflow_execution(workflow_id)
        
        # Log workflow initiation
        self.security_logger.log_system_event(
            "workflow_initiated",
            {
                "workflow_id": workflow_id,
                "alert_id": alert_data.get("alert_id", "unknown"),
                "template": workflow_type
            }
        )
        
        logger.info(f"Started workflow {workflow_id} using template {workflow_type}")
        return workflow_id
        
    async def _start_workflow_execution(self, workflow_id: str):
        """Start executing the workflow"""
        
        workflow_info = self.active_workflows[workflow_id]
        first_step = workflow_info["steps"][0]
        
        # Create initial message to start the workflow
        initial_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id=first_step.agent_id,
            message_type=MessageType.ALERT_RECEIVED,
            thread_id=workflow_id,
            payload={
                "alert_data": workflow_info["alert_data"],
                "workflow_metadata": {
                    "workflow_id": workflow_id,
                    "step_name": first_step.step_name,
                    "step_timeout": 30
                }
            },
            timestamp=datetime.datetime.now()
        )
        
        # Update workflow status
        workflow_info["status"] = "running"
        first_step.status = "in_progress"
        first_step.start_time = datetime.datetime.now()
        
        # Send the message
        await self.send_message(initial_message)
        
    async def _handle_workflow_completion(self, message: CoralMessage):
        """Handle workflow step completion"""
        
        workflow_id = message.thread_id
        
        if workflow_id not in self.active_workflows:
            logger.warning(f"Received completion for unknown workflow: {workflow_id}")
            return
            
        workflow_info = self.active_workflows[workflow_id]
        current_step_index = workflow_info["current_step"]
        
        # Update current step
        if current_step_index < len(workflow_info["steps"]):
            current_step = workflow_info["steps"][current_step_index]
            current_step.status = "completed"
            current_step.end_time = datetime.datetime.now()
            current_step.result = message.payload
            
            # Log step completion
            self.performance_logger.log_workflow_timing(
                workflow_id,
                current_step.agent_id,
                current_step.step_name,
                current_step.duration * 1000 if current_step.duration else 0
            )
            
        # Check if workflow is complete
        action = message.payload.get("action", "")
        
        if action in ["dismissed_false_positive", "analysis_complete", "response_coordinated"]:
            await self._complete_workflow(workflow_id, message)
        else:
            # Continue to next step
            await self._advance_workflow(workflow_id, message)
            
    async def _advance_workflow(self, workflow_id: str, completion_message: CoralMessage):
        """Advance workflow to the next step"""
        
        workflow_info = self.active_workflows[workflow_id]
        workflow_info["current_step"] += 1
        next_step_index = workflow_info["current_step"]
        
        # Check if there are more steps
        if next_step_index >= len(workflow_info["steps"]):
            await self._complete_workflow(workflow_id, completion_message)
            return
            
        # Get next step
        next_step = workflow_info["steps"][next_step_index]
        next_step.status = "in_progress"
        next_step.start_time = datetime.datetime.now()
        
        # Determine next message type based on step
        message_type_map = {
            "false_positive_check": MessageType.FALSE_POSITIVE_CHECK,
            "severity_analysis": MessageType.SEVERITY_DETERMINATION,
            "context_gathering": MessageType.CONTEXT_GATHERING,
            "response_coordination": MessageType.RESPONSE_DECISION
        }
        
        next_message_type = message_type_map.get(
            next_step.step_name, 
            MessageType.ALERT_RECEIVED
        )
        
        # Create message for next step
        next_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id=next_step.agent_id,
            message_type=next_message_type,
            thread_id=workflow_id,
            payload=completion_message.payload,  # Forward previous result
            timestamp=datetime.datetime.now()
        )
        
        await self.send_message(next_message)
        logger.debug(f"Advanced workflow {workflow_id} to step: {next_step.step_name}")
        
    async def _complete_workflow(self, workflow_id: str, completion_message: CoralMessage):
        """Complete the workflow and generate results"""
        
        workflow_info = self.active_workflows[workflow_id]
        end_time = datetime.datetime.now()
        
        # Extract final alert data
        alert_data = completion_message.payload.get("alert", {})
        alert = SecurityAlert.from_dict(alert_data) if alert_data else None
        
        # Create workflow result
        result = WorkflowResult(
            workflow_id=workflow_id,
            alert=alert,
            start_time=workflow_info["start_time"],
            end_time=end_time,
            agents_involved=[step.agent_id for step in workflow_info["steps"]],
            analysis_results=self._extract_analysis_results(workflow_info),
            final_decision=completion_message.payload.get("action", "completed"),
            processing_time_seconds=(end_time - workflow_info["start_time"]).total_seconds()
        )
        
        # Update statistics
        if result.success:
            self.successful_workflows += 1
        else:
            self.failed_workflows += 1
            
        # Update average processing time
        self._update_average_processing_time(result.processing_time_seconds)
        
        # Store result and clean up
        self.completed_workflows[workflow_id] = result
        del self.active_workflows[workflow_id]
        
        # Log completion
        self.security_logger.log_alert_processed(
            alert.alert_id if alert else "unknown",
            workflow_id,
            result.final_decision,
            alert.confidence_score if alert else 0.0,
            {
                "processing_time": result.processing_time_seconds,
                "agents_involved": len(result.agents_involved),
                "success": result.success
            }
        )
        
        logger.info(f"Workflow {workflow_id} completed in {result.processing_time_seconds:.2f}s - "
                   f"Decision: {result.final_decision}")
                   
    async def _handle_workflow_error(self, message: CoralMessage):
        """Handle workflow errors and implement recovery"""
        
        workflow_id = message.thread_id
        
        if workflow_id not in self.active_workflows:
            logger.warning(f"Received error for unknown workflow: {workflow_id}")
            return
            
        workflow_info = self.active_workflows[workflow_id]
        workflow_info["error_count"] += 1
        
        error_details = message.payload.get("error", "Unknown error")
        logger.error(f"Workflow {workflow_id} error: {error_details}")
        
        # Mark current step as failed
        current_step_index = workflow_info["current_step"]
        if current_step_index < len(workflow_info["steps"]):
            current_step = workflow_info["steps"][current_step_index]
            current_step.status = "failed"
            current_step.end_time = datetime.datetime.now()
            current_step.error_message = error_details
            
        # Implement retry logic
        max_retries = 2
        if workflow_info["retry_count"] < max_retries:
            await self._retry_workflow_step(workflow_id)
        else:
            await self._fail_workflow(workflow_id, error_details)
            
    async def _retry_workflow_step(self, workflow_id: str):
        """Retry the current workflow step"""
        
        workflow_info = self.active_workflows[workflow_id]
        workflow_info["retry_count"] += 1
        
        current_step_index = workflow_info["current_step"]
        current_step = workflow_info["steps"][current_step_index]
        
        # Reset step status
        current_step.status = "in_progress"
        current_step.start_time = datetime.datetime.now()
        current_step.error_message = None
        
        logger.info(f"Retrying workflow {workflow_id} step {current_step.step_name} "
                   f"(attempt {workflow_info['retry_count'] + 1})")
        
        # Recreate and send the message for this step
        # This would need more sophisticated logic to recreate the exact message
        # For now, we'll mark it as failed and continue
        await self._fail_workflow(workflow_id, "Retry not implemented")
        
    async def _fail_workflow(self, workflow_id: str, error_reason: str):
        """Mark workflow as failed"""
        
        workflow_info = self.active_workflows[workflow_id]
        end_time = datetime.datetime.now()
        
        # Create failed workflow result
        result = WorkflowResult(
            workflow_id=workflow_id,
            alert=None,  # May not have complete alert data
            start_time=workflow_info["start_time"],
            end_time=end_time,
            agents_involved=[step.agent_id for step in workflow_info["steps"]],
            analysis_results=[],
            final_decision="failed",
            processing_time_seconds=(end_time - workflow_info["start_time"]).total_seconds()
        )
        
        # Update statistics
        self.failed_workflows += 1
        
        # Store result and clean up
        self.completed_workflows[workflow_id] = result
        del self.active_workflows[workflow_id]
        
        # Log failure
        self.security_logger.log_system_event(
            "workflow_failed",
            {
                "workflow_id": workflow_id,
                "error_reason": error_reason,
                "processing_time": result.processing_time_seconds
            }
        )
        
        logger.error(f"Workflow {workflow_id} failed: {error_reason}")
        
    def _extract_analysis_results(self, workflow_info: Dict[str, Any]) -> List[AnalysisResult]:
        """Extract analysis results from workflow steps"""
        
        results = []
        
        for step in workflow_info["steps"]:
            if step.status == "completed" and step.result:
                analysis_result = AnalysisResult(
                    agent_id=step.agent_id,
                    agent_name=step.agent_id.replace("_", " ").title(),
                    analysis_type=step.step_name,
                    timestamp=step.end_time or datetime.datetime.now(),
                    confidence=step.result.get("confidence", 0.5),
                    result=step.result,
                    reasoning=step.result.get("reasoning", []),
                    recommendations=step.result.get("recommended_actions", [])
                )
                results.append(analysis_result)
                
        return results
        
    def _update_average_processing_time(self, processing_time: float):
        """Update running average of processing time"""
        
        total_completed = self.successful_workflows + self.failed_workflows
        if total_completed == 1:
            self.average_processing_time = processing_time
        else:
            # Running average calculation
            self.average_processing_time = (
                (self.average_processing_time * (total_completed - 1) + processing_time) 
                / total_completed
            )
            
    async def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed status of a specific workflow"""
        
        # Check active workflows
        if workflow_id in self.active_workflows:
            workflow_info = self.active_workflows[workflow_id]
            
            # Calculate progress
            completed_steps = sum(1 for step in workflow_info["steps"] if step.status == "completed")
            total_steps = len(workflow_info["steps"])
            progress = (completed_steps / total_steps) * 100 if total_steps > 0 else 0
            
            return {
                "workflow_id": workflow_id,
                "status": workflow_info["status"],
                "template_name": workflow_info["template_name"],
                "progress_percentage": progress,
                "current_step": workflow_info["current_step"],
                "steps": [
                    {
                        "name": step.step_name,
                        "agent": step.agent_id,
                        "status": step.status,
                        "duration": step.duration,
                        "error": step.error_message
                    }
                    for step in workflow_info["steps"]
                ],
                "start_time": workflow_info["start_time"].isoformat(),
                "estimated_completion": workflow_info["estimated_completion"].isoformat(),
                "error_count": workflow_info["error_count"],
                "retry_count": workflow_info["retry_count"]
            }
            
        # Check completed workflows
        if workflow_id in self.completed_workflows:
            result = self.completed_workflows[workflow_id]
            return {
                "workflow_id": workflow_id,
                "status": "completed",
                "success": result.success,
                "final_decision": result.final_decision,
                "processing_time": result.processing_time_seconds,
                "agents_involved": result.agents_involved,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat()
            }
            
        return None
        
    async def get_orchestrator_metrics(self) -> Dict[str, Any]:
        """Get comprehensive orchestrator metrics"""
        
        return {
            "total_workflows": self.total_workflows,
            "active_workflows": len(self.active_workflows),
            "successful_workflows": self.successful_workflows,
            "failed_workflows": self.failed_workflows,
            "success_rate": (
                self.successful_workflows / (self.successful_workflows + self.failed_workflows)
                if (self.successful_workflows + self.failed_workflows) > 0 else 0
            ),
            "average_processing_time": self.average_processing_time,
            "workflows_per_hour": 0.0,  # Would calculate based on time window
            "queue_size": self.message_queue.qsize(),
            "available_templates": list(self.workflow_templates.keys())
        }
        
    async def optimize_workflows(self) -> Dict[str, Any]:
        """Analyze workflows and suggest optimizations"""
        
        optimizations = {
            "bottleneck_analysis": {},
            "template_recommendations": {},
            "performance_insights": {}
        }
        
        # Analyze completed workflows for bottlenecks
        if self.completed_workflows:
            step_times = {}
            
            for result in self.completed_workflows.values():
                for analysis in result.analysis_results:
                    step_name = analysis.analysis_type
                    if step_name not in step_times:
                        step_times[step_name] = []
                    # Would extract actual timing from analysis
                    
            # Identify slowest steps
            for step_name, times in step_times.items():
                if times:
                    avg_time = sum(times) / len(times)
                    optimizations["bottleneck_analysis"][step_name] = {
                        "average_time": avg_time,
                        "sample_count": len(times),
                        "recommendation": "optimize" if avg_time > 60 else "acceptable"
                    }
                    
        return optimizations
        
    def get_agent_metrics(self) -> Dict[str, Any]:
        """Get agent performance metrics"""
        
        return {
            "total_workflows_orchestrated": self.total_workflows,
            "active_workflows": len(self.active_workflows),
            "success_rate": (
                self.successful_workflows / self.total_workflows
                if self.total_workflows > 0 else 0
            ),
            "average_processing_time": self.average_processing_time,
            "queue_size": self.message_queue.qsize()
        }