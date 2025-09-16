"""
Alert Triage System - Main Application
Production-ready security alert triage using Coral Protocol
"""

import asyncio
import logging
import signal
import sys
import datetime
from typing import Dict, Any, List
import json

# Import Coral Protocol components
from coral_protocol import CoralRegistry

# Import all agents
from agents.alert_receiver import AlertReceiverAgent
from agents.false_positive_checker import FalsePositiveCheckerAgent
# Note: Import remaining agents when they're created
# from agents.severity_analyzer import SeverityAnalyzerAgent
# from agents.context_gatherer import ContextGathererAgent
# from agents.response_coordinator import ResponseCoordinatorAgent
# from agents.workflow_orchestrator import WorkflowOrchestratorAgent

# Import configuration and utilities
from utils.logging_config import setup_logging
from utils.config_loader import load_config
from utils.metrics_collector import MetricsCollector


logger = logging.getLogger(__name__)


class AlertTriageSystem:
    """
    Complete Alert Triage System using Coral Protocol
    
    This is the main system that orchestrates all agents for security alert processing.
    """
    
    def __init__(self, config_path: str = "config/default.yaml"):
        self.config = load_config(config_path)
        self.coral_registry = CoralRegistry()
        self.agents = []
        self.agent_tasks = []
        self.metrics_collector = MetricsCollector()
        self.running = False
        
        # Setup logging
        setup_logging(self.config.get("logging", {}))
        
    async def initialize(self):
        """Initialize the complete system"""
        logger.info("Initializing Alert Triage System...")
        
        try:
            # Create all agents
            await self._create_agents()
            
            # Register agents with Coral Protocol
            await self._register_agents()
            
            # Start agent message processing
            await self._start_agent_processing()
            
            # Setup signal handlers for graceful shutdown
            self._setup_signal_handlers()
            
            self.running = True
            logger.info("Alert Triage System initialized successfully!")
            
        except Exception as e:
            logger.error(f"Failed to initialize system: {e}")
            raise
            
    async def _create_agents(self):
        """Create all agent instances"""
        
        # Create core workflow agents
        self.agents = [
            AlertReceiverAgent(),
            FalsePositiveCheckerAgent(),
            # TODO: Add remaining agents when implemented
            # SeverityAnalyzerAgent(),
            # ContextGathererAgent(), 
            # ResponseCoordinatorAgent(),
            # WorkflowOrchestratorAgent()
        ]
        
        logger.info(f"Created {len(self.agents)} agents")
        
    async def _register_agents(self):
        """Register all agents with Coral Protocol"""
        
        for agent in self.agents:
            await agent.register_with_coral(self.coral_registry)
            
        logger.info("All agents registered with Coral Protocol")
        
    async def _start_agent_processing(self):
        """Start message processing for all agents"""
        
        self.agent_tasks = []
        for agent in self.agents:
            task = asyncio.create_task(
                agent.process_messages(),
                name=f"agent_{agent.agent_id}_processing"
            )
            self.agent_tasks.append(task)
            
        logger.info(f"Started message processing for {len(self.agent_tasks)} agents")
        
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating shutdown...")
            asyncio.create_task(self.shutdown())
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
    async def process_alert(self, alert_data: Dict[str, Any]) -> str:
        """
        Process a security alert through the complete workflow
        
        Args:
            alert_data: Raw alert data from any source
            
        Returns:
            Workflow ID for tracking
        """
        if not self.running:
            raise RuntimeError("System not initialized or not running")
            
        # Find the alert receiver agent
        alert_receiver = None
        for agent in self.agents:
            if agent.agent_id == "alert_receiver":
                alert_receiver = agent
                break
                
        if not alert_receiver:
            raise RuntimeError("Alert receiver agent not found")
            
        # Create workflow thread ID
        workflow_id = f"workflow_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{alert_data.get('alert_id', 'unknown')}"
        
        # Create initial message
        from coral_protocol.message_types import CoralMessage, MessageType
        import uuid
        
        initial_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id="system",
            receiver_id="alert_receiver",
            message_type=MessageType.ALERT_RECEIVED,
            thread_id=workflow_id,
            payload={"alert_data": alert_data},
            timestamp=datetime.datetime.now()
        )
        
        # Send to alert receiver
        await self.coral_registry.route_message(initial_message)
        
        # Track metrics
        await self.metrics_collector.record_alert_submitted(workflow_id)
        
        logger.info(f"Alert processing started with workflow ID: {workflow_id}")
        return workflow_id
        
    async def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """Get status of a specific workflow"""
        return await self.coral_registry.get_workflow_status(workflow_id)
        
    async def get_system_metrics(self) -> Dict[str, Any]:
        """Get comprehensive system metrics"""
        
        # Registry metrics
        registry_metrics = self.coral_registry.get_registry_metrics()
        
        # Agent metrics
        agent_metrics = {}
        for agent in self.agents:
            if hasattr(agent, 'get_agent_metrics'):
                agent_metrics[agent.agent_id] = agent.get_agent_metrics()
                
        # System metrics
        system_metrics = await self.metrics_collector.get_system_metrics()
        
        return {
            "registry": registry_metrics,
            "agents": agent_metrics,
            "system": system_metrics,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
    async def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive system health check"""
        
        health_status = "healthy"
        issues = []
        
        # Check registry health
        registry_health = await self.coral_registry.health_check()
        if registry_health["status"] != "healthy":
            health_status = "degraded"
            issues.append("Registry issues detected")
            
        # Check agent health
        agent_health = {}
        for agent in self.agents:
            if hasattr(agent, 'health_check'):
                agent_health[agent.agent_id] = await agent.health_check()
                if agent_health[agent.agent_id]["status"] != "healthy":
                    health_status = "degraded"
                    issues.extend(agent_health[agent.agent_id]["issues"])
                    
        # Check if any agent tasks have failed
        failed_tasks = [task for task in self.agent_tasks if task.done() and task.exception()]
        if failed_tasks:
            health_status = "critical"
            issues.append(f"{len(failed_tasks)} agent tasks have failed")
            
        return {
            "status": health_status,
            "issues": issues,
            "registry_health": registry_health,
            "agent_health": agent_health,
            "system_uptime": (
                datetime.datetime.now() - self.metrics_collector.start_time
            ).total_seconds() if hasattr(self.metrics_collector, 'start_time') else 0
        }
        
    async def shutdown(self):
        """Gracefully shutdown the system"""
        logger.info("Starting system shutdown...")
        
        self.running = False
        
        try:
            # Shutdown agents
            shutdown_tasks = []
            for agent in self.agents:
                if hasattr(agent, 'shutdown'):
                    shutdown_tasks.append(agent.shutdown())
                    
            if shutdown_tasks:
                await asyncio.gather(*shutdown_tasks, return_exceptions=True)
                
            # Cancel agent processing tasks
            for task in self.agent_tasks:
                task.cancel()
                
            if self.agent_tasks:
                await asyncio.gather(*self.agent_tasks, return_exceptions=True)
                
            logger.info("System shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            
    async def run_forever(self):
        """Run the system indefinitely"""
        logger.info("Alert Triage System is running...")
        
        try:
            # Keep the system running
            while self.running:
                await asyncio.sleep(1)
                
                # Periodic cleanup
                await self.coral_registry.cleanup_completed_workflows()
                
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
        finally:
            await self.shutdown()


async def demo_alert_processing():
    """Demonstrate the alert triage system with sample alerts"""
    
    # Sample security alerts for testing
    sample_alerts = [
        {
            "alert_id": "ALT-2024-001",
            "timestamp": datetime.datetime.now().isoformat(),
            "source_system": "IDS",
            "type": "brute_force",
            "description": "Multiple failed login attempts detected",
            "source_ip": "203.0.113.45",
            "user_id": "admin_user",
            "failed_attempts": 15
        },
        {
            "alert_id": "ALT-2024-002", 
            "timestamp": datetime.datetime.now().isoformat(),
            "source_system": "EDR",
            "type": "malware",
            "description": "Suspicious executable detected",
            "source_ip": "10.0.0.25",
            "user_id": "test_user",
            "file_hash": "abc123def456"
        },
        {
            "alert_id": "ALT-2024-003",
            "timestamp": datetime.datetime.now().isoformat(), 
            "source_system": "Network Monitor",
            "type": "data_exfiltration",
            "description": "Large data transfer to external IP",
            "source_ip": "192.168.1.100",
            "destination_ip": "198.51.100.42",
            "user_id": "finance_user",
            "data_volume": "500MB"
        },
        {
            "alert_id": "ALT-2024-004",
            "timestamp": datetime.datetime.now().isoformat(),
            "source_system": "Antivirus",
            "type": "malware",
            "description": "antivirus_test_file detected during scheduled scan",
            "source_ip": "10.0.0.100",
            "user_id": "test_user",
            "file_path": "/tmp/eicar_test_file"
        }
    ]
    
    # Initialize the system
    system = AlertTriageSystem()
    
    try:
        await system.initialize()
        
        logger.info("=== Starting Alert Triage Demo ===")
        
        # Process each sample alert
        workflow_ids = []
        for alert in sample_alerts:
            workflow_id = await system.process_alert(alert)
            workflow_ids.append(workflow_id)
            logger.info(f"Submitted alert {alert['alert_id']} for processing (workflow: {workflow_id})")
            
        # Wait for processing to complete
        logger.info("Waiting for workflows to complete...")
        await asyncio.sleep(10)  # Give time for processing
        
        # Check workflow statuses
        for workflow_id in workflow_ids:
            status = await system.get_workflow_status(workflow_id)
            if status:
                logger.info(f"Workflow {workflow_id}: {status['message_count']} messages, "
                          f"{len(status['agents_involved'])} agents involved")
        
        # Show system metrics
        metrics = await system.get_system_metrics()
        logger.info(f"System processed {metrics['registry']['total_messages_routed']} messages")
        
        # Health check
        health = await system.health_check()
        logger.info(f"System health: {health['status']}")
        
        logger.info("=== Demo completed successfully ===")
        
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        raise
    finally:
        await system.shutdown()


async def run_production_system():
    """Run the production system"""
    
    config_path = "config/production.yaml"
    system = AlertTriageSystem(config_path)
    
    try:
        await system.initialize()
        await system.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.error(f"System error: {e}")
        raise
    finally:
        await system.shutdown()


def main():
    """Main entry point"""
    
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        # Run demo mode
        asyncio.run(demo_alert_processing())
    else:
        # Run production mode
        asyncio.run(run_production_system())


if __name__ == "__main__":
    main()