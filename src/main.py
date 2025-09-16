#!/usr/bin/env python3
"""
Alert Triage System - Main Entry Point
"""

import asyncio
import sys
import logging
from datetime import datetime
from typing import Dict, Any, List
import json

# Third-party imports  
from fastapi import FastAPI, HTTPException, BackgroundTasks
from contextlib import asynccontextmanager
import uvicorn

# Import Coral Protocol components
from coral_protocol import CoralRegistry

# Import all agents
from agents.alert_receiver import AlertReceiverAgent
from agents.false_positive_checker import FalsePositiveCheckerAgent
from agents.severity_analyzer import SeverityAnalyzerAgent
from agents.context_gatherer import ContextGathererAgent
from agents.response_coordinator import ResponseCoordinatorAgent
from agents.workflow_orchestrator import WorkflowOrchestratorAgent

# Import configuration and utilities
from utils.logging_config import setup_logging
from utils.config_loader import load_config
from utils.metrics_collector import MetricsCollector

logger = logging.getLogger(__name__)

# Global system instance
system_instance = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events"""
    global system_instance
    
    # Startup
    config = load_config("config/default.yaml")
    system_instance = AlertTriageSystem(config)
    await system_instance.initialize()
    
    logger.info("Web server started successfully!")
    logger.info("Webhook endpoint: http://localhost:8080/webhook/alert")
    logger.info("Health endpoint: http://localhost:8080/health")
    logger.info("Metrics endpoint: http://localhost:8080/metrics")
    
    yield
    
    # Shutdown
    if system_instance:
        await system_instance.shutdown()

# FastAPI app
app = FastAPI(
    title="Alert Triage System API",
    description="Real-time security alert processing system",
    version="1.0.0",
    lifespan=lifespan
)

class AlertTriageSystem:
    """Main system orchestrator"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.registry = CoralRegistry()
        self.agents = []
        self.metrics = MetricsCollector()
        self.running = False
        
    async def initialize(self):
        """Initialize all system components"""
        logger.info("Initializing Alert Triage System...")
        
        # Create agents
        agent_classes = [
            AlertReceiverAgent,
            FalsePositiveCheckerAgent, 
            SeverityAnalyzerAgent,
            ContextGathererAgent,
            ResponseCoordinatorAgent,
            WorkflowOrchestratorAgent
        ]
        
        for agent_class in agent_classes:
            agent = agent_class()  # Don't pass config - agents don't expect it
            self.agents.append(agent)
            
        logger.info(f"Created {len(self.agents)} agents")
        
        # Register agents with Coral Protocol
        for agent in self.agents:
            await agent.register_with_coral(self.registry)
            
        logger.info("All agents registered with Coral Protocol")
        
        # Start message processing for all agents
        for agent in self.agents:
            asyncio.create_task(agent.process_messages())
            
        logger.info("Alert Triage System initialized successfully!")

        
        self.running = True

    async def process_alert(self, alert_data: Dict[str, Any]) -> str:
        """Process an incoming alert"""
        if not self.running:
            raise Exception("System not running")
            
        alert_id = alert_data.get('alert_id', f"ALT-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
        
        logger.info(f"Processing incoming alert: {alert_id}")
        
        # Start workflow
        workflow_id = f"workflow_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{alert_id}"
        
        # Send to alert receiver
        alert_receiver = self.agents[0]  # First agent is AlertReceiver
        await alert_receiver.process_alert(alert_data, workflow_id)
        
        logger.info(f"Alert {alert_id} submitted for processing (workflow: {workflow_id})")
        return workflow_id
    
    def get_health(self) -> Dict[str, Any]:
        """Get system health status"""
        return {
            "status": "healthy" if self.running else "unhealthy",
            "agents_count": len(self.agents),
            "agents_running": sum(1 for agent in self.agents if hasattr(agent, 'running') and agent.running),
            "timestamp": datetime.now().isoformat()
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get system metrics"""
        return self.metrics.get_all_metrics()
    
    async def shutdown(self):
        """Shutdown the system"""
        logger.info("Starting system shutdown...")
        
        for agent in self.agents:
            if hasattr(agent, 'shutdown'):
                await agent.shutdown()
                
        self.running = False
        logger.info("System shutdown complete")

# FastAPI Routes
@app.post("/webhook/alert")
async def receive_alert(alert_data: Dict[str, Any], background_tasks: BackgroundTasks):
    """Receive and process an alert via webhook"""
    global system_instance
    
    if not system_instance or not system_instance.running:
        raise HTTPException(status_code=503, detail="System not ready")
    
    try:
        # Process alert in background to return quickly
        workflow_id = await system_instance.process_alert(alert_data)
        
        return {
            "status": "success",
            "message": "Alert received and processing started",
            "workflow_id": workflow_id,
            "alert_id": alert_data.get('alert_id')
        }
    except Exception as e:
        logger.error(f"Error processing alert: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing alert: {str(e)}")

@app.get("/health")
async def health_check():
    """System health check endpoint"""
    global system_instance
    
    if system_instance:
        return system_instance.get_health()
    else:
        return {"status": "unhealthy", "reason": "System not initialized"}

@app.get("/metrics")
async def get_metrics():
    """Get system metrics endpoint"""
    global system_instance
    
    if system_instance:
        return system_instance.get_metrics()
    else:
        return {"error": "System not available"}

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Alert Triage System",
        "status": "running",
        "endpoints": {
            "webhook": "/webhook/alert",
            "health": "/health", 
            "metrics": "/metrics"
        }
    }

async def run_demo():
    """Run demo mode with sample alerts"""
    # Load configuration
    config = load_config("config/default.yaml")
    
    # Create system
    system = AlertTriageSystem(config)
    await system.initialize()
    
    logger.info("=== Starting Alert Triage Demo ===")
    
    # Sample demo alerts
    demo_alerts = [
        {
            "alert_id": "ALT-2024-001",
            "timestamp": "2024-09-15T20:45:30Z",
            "source_system": "EDR",
            "type": "malware_detection",
            "description": "Suspicious executable detected",
            "source_ip": "203.0.113.45",
            "user_id": "jdoe",
            "file_hash": "d41d8cd98f00b204e9800998ecf8427e"
        },
        {
            "alert_id": "ALT-2024-002",
            "timestamp": "2024-09-15T20:46:15Z",
            "source_system": "SIEM",
            "type": "brute_force",
            "description": "Multiple failed login attempts",
            "source_ip": "192.168.1.100",
            "user_id": "admin",
            "affected_resource": "web_server"
        },
        {
            "alert_id": "ALT-2024-003",
            "timestamp": "2024-09-15T20:47:22Z",
            "source_system": "Network",
            "type": "data_exfiltration",
            "description": "Unusual outbound traffic detected",
            "source_ip": "10.0.0.45",
            "user_id": "bsmith",
            "data_volume": "500MB"
        },
        {
            "alert_id": "ALT-2024-004",
            "timestamp": "2024-09-15T20:48:10Z",
            "source_system": "Endpoint",
            "type": "malware_detection",
            "description": "EICAR test file detected",
            "source_ip": "172.16.0.10",
            "user_id": "tester",
            "file_path": "/tmp/eicar_test_file"
        }
    ]
    
    workflows = []
    for alert in demo_alerts:
        workflow_id = await system.process_alert(alert)
        workflows.append(workflow_id)
    
    # Wait for processing
    logger.info("Waiting for workflows to complete...")
    await asyncio.sleep(10)
    
    # Show results
    for workflow_id in workflows:
        messages = system.registry.get_workflow_messages(workflow_id)
        agents = system.registry.get_workflow_agents(workflow_id)
        logger.info(f"Workflow {workflow_id}: {len(messages)} messages, {len(agents)} agents involved")
    
    total_messages = system.registry.get_total_messages()
    logger.info(f"System processed {total_messages} messages")
    logger.info(f"System health: {system.registry.get_system_health()}")
    
    logger.info("=== Demo completed successfully ===")
    await system.shutdown()

def main():
    """Main entry point"""
    # Load configuration first
    config = load_config("config/default.yaml")
    
    # Setup logging with config
    setup_logging(config)
    
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        # Run demo mode
        asyncio.run(run_demo())
    else:
        # Run web server mode
        logger.info("Starting Alert Triage System in web server mode...")
        
        # Start the server
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=8080,
            log_level="info",
            reload=False
        )

if __name__ == "__main__":
    main()