"""
Alert Triage System - Usage Examples

This file contains comprehensive examples demonstrating how to use the Alert Triage System
in various scenarios, from basic alert processing to advanced integrations.
"""

import asyncio
import datetime
import json
from typing import Dict, Any, List

# Import the main system components
from src.main import AlertTriageSystem
from src.coral_protocol import CoralRegistry, CoralMessage, MessageType
from src.coral_protocol.agent_base import CoralAgent
from src.agents import (
    AlertReceiverAgent,
    FalsePositiveCheckerAgent,
    SeverityAnalyzerAgent,
    ContextGathererAgent,
    ResponseCoordinatorAgent,
    WorkflowOrchestratorAgent
)
from src.models.alert_models import SecurityAlert, AlertType, AlertSeverity
from src.api.webhook_server import WebhookReceiver


# ===============================================
# Example 1: Basic Alert Processing
# ===============================================

async def example_basic_alert_processing():
    """
    Basic example: Process a single alert through the complete workflow
    """
    print("=== Example 1: Basic Alert Processing ===")
    
    # Initialize the system
    system = AlertTriageSystem()
    await system.initialize()
    
    try:
        # Create a sample alert
        alert_data = {
            "alert_id": "EXAMPLE-001",
            "timestamp": datetime.datetime.now().isoformat(),
            "source_system": "Splunk",
            "type": "brute_force",
            "description": "Multiple failed login attempts detected from external IP",
            "source_ip": "203.0.113.45",
            "destination_ip": "10.0.0.100",
            "user_id": "admin_user",
            "failed_attempts": 15,
            "time_window": "5 minutes"
        }
        
        print(f"Processing alert: {alert_data['alert_id']}")
        
        # Submit alert for processing
        workflow_id = await system.process_alert(alert_data)
        print(f"Workflow started: {workflow_id}")
        
        # Wait for processing to complete
        await asyncio.sleep(10)
        
        # Check workflow status
        status = await system.get_workflow_status(workflow_id)
        if status:
            print(f"Workflow status: {status['status']}")
            print(f"Progress: {status.get('progress_percentage', 0):.1f}%")
            
            if status['status'] == 'completed':
                print(f"Final decision: {status.get('final_decision', 'unknown')}")
        
        # Get system metrics
        metrics = await system.get_system_metrics()
        print(f"Total alerts processed: {metrics['system']['alerts_processed']}")
        
    finally:
        await system.shutdown()
    
    print("✓ Basic alert processing example completed\n")


# ===============================================
# Example 2: Batch Alert Processing
# ===============================================

async def example_batch_alert_processing():
    """
    Process multiple alerts concurrently to demonstrate system scalability
    """
    print("=== Example 2: Batch Alert Processing ===")
    
    # Sample alert templates
    alert_templates = [
        {
            "type": "malware",
            "description": "Suspicious executable detected on workstation",
            "source_system": "EDR",
            "file_hash": "abc123def456789",
            "hostname": "WORKSTATION-{:03d}"
        },
        {
            "type": "phishing",
            "description": "Suspicious email with malicious attachment",
            "source_system": "Email Security",
            "sender_email": "attacker{}@malicious.example",
            "recipient_email": "user{}@company.com"
        },
        {
            "type": "data_exfiltration",
            "description": "Large data transfer to external IP",
            "source_system": "DLP",
            "source_ip": "10.0.0.{}",
            "destination_ip": "198.51.100.{}",
            "data_volume": "{}MB"
        },
        {
            "type": "network_anomaly",
            "description": "Unusual network traffic pattern detected",
            "source_system": "Network Monitor",
            "source_ip": "10.0.1.{}",
            "protocol": "TCP",
            "port": "{}"
        }
    ]
    
    system = AlertTriageSystem()
    await system.initialize()
    
    try:
        print("Generating and processing 20 alerts...")
        
        workflow_ids = []
        
        # Generate and submit alerts
        for i in range(20):
            template = alert_templates[i % len(alert_templates)]
            
            alert_data = {
                "alert_id": f"BATCH-{i+1:03d}",
                "timestamp": datetime.datetime.now().isoformat(),
                "source_system": template["source_system"],
                "type": template["type"],
                "description": template["description"]
            }
            
            # Add template-specific fields
            for key, value in template.items():
                if key not in ["type", "description", "source_system"]:
                    if "{}" in str(value):
                        alert_data[key] = value.format(i+1)
                    else:
                        alert_data[key] = value
            
            # Submit alert
            workflow_id = await system.process_alert(alert_data)
            workflow_ids.append(workflow_id)
        
        print(f"Submitted {len(workflow_ids)} alerts for processing")
        
        # Wait for processing
        print("Waiting for processing to complete...")
        await asyncio.sleep(15)
        
        # Check results
        completed = 0
        decisions = {}
        
        for workflow_id in workflow_ids:
            status = await system.get_workflow_status(workflow_id)
            if status and status['status'] == 'completed':
                completed += 1
                decision = status.get('final_decision', 'unknown')
                decisions[decision] = decisions.get(decision, 0) + 1
        
        print(f"Completed workflows: {completed}/{len(workflow_ids)}")
        print("Decision breakdown:")
        for decision, count in decisions.items():
            print(f"  {decision}: {count}")
        
        # Show system performance
        metrics = await system.get_system_metrics()
        print(f"Average processing time: {metrics['system']['average_processing_time']:.2f}s")
        print(f"Alerts per second: {metrics['system']['alerts_per_second']:.2f}")
        
    finally:
        await system.shutdown()
    
    print("✓ Batch alert processing example completed\n")


# ===============================================
# Example 3: Webhook Integration
# ===============================================

async def example_webhook_integration():
    """
    Demonstrate webhook-based alert ingestion from external systems
    """
    print("=== Example 3: Webhook Integration ===")
    
    # Initialize system and webhook receiver
    system = AlertTriageSystem()
    await system.initialize()
    
    webhook_config = {
        "secret": "example-webhook-secret",
        "require_auth": False,
        "max_payload_size": 1048576
    }
    
    webhook_receiver = WebhookReceiver(system, webhook_config)
    
    try:
        # Start webhook server
        await webhook_receiver.start_server(host="localhost", port=8080)
        print("Webhook server started on http://localhost:8080")
        
        # Simulate webhook calls using different formats
        webhook_examples = [
            {
                "endpoint": "/webhook/splunk",
                "data": {
                    "result": {
                        "sid": "splunk_12345",
                        "_time": datetime.datetime.now().isoformat(),
                        "search_name": "Brute Force Attack Detection",
                        "src_ip": "203.0.113.45",
                        "dest_ip": "10.0.0.100",
                        "user": "admin_user",
                        "count": 15
                    }
                }
            },
            {
                "endpoint": "/webhook/sentinel",
                "data": {
                    "object": {
                        "properties": {
                            "incidentNumber": 12345,
                            "title": "Suspicious Login Activity",
                            "description": "Multiple failed login attempts detected",
                            "severity": "Medium",
                            "createdTimeUtc": datetime.datetime.now().isoformat()
                        }
                    }
                }
            },
            {
                "endpoint": "/webhook/edr",
                "data": {
                    "alert": {
                        "id": "edr_67890",
                        "timestamp": datetime.datetime.now().isoformat(),
                        "type": "malware_detection",
                        "description": "Malicious file detected and quarantined",
                        "hostname": "WORKSTATION-042",
                        "file_path": "C:\\Users\\user\\Downloads\\malware.exe",
                        "sha256": "abc123def456789",
                        "username": "corporate_user"
                    }
                }
            }
        ]
        
        print("Simulating webhook calls...")
        
        # In a real scenario, external systems would make these HTTP calls
        # For demonstration, we'll simulate the webhook processing directly
        
        workflow_ids = []
        for example in webhook_examples:
            # Simulate webhook processing
            print(f"Processing webhook: {example['endpoint']}")
            
            # Convert webhook data to standardized alert format
            if "splunk" in example["endpoint"]:
                alert_data = {
                    "alert_id": f"splunk_{example['data']['result']['sid']}",
                    "timestamp": example['data']['result']['_time'],
                    "source_system": "splunk",
                    "type": "brute_force",
                    "description": example['data']['result']['search_name'],
                    "source_ip": example['data']['result']['src_ip'],
                    "destination_ip": example['data']['result']['dest_ip'],
                    "user_id": example['data']['result']['user'],
                    "raw_data": example['data']
                }
            elif "sentinel" in example["endpoint"]:
                props = example['data']['object']['properties']
                alert_data = {
                    "alert_id": f"sentinel_{props['incidentNumber']}",
                    "timestamp": props['createdTimeUtc'],
                    "source_system": "sentinel",
                    "type": "suspicious_login",
                    "description": props['description'],
                    "severity": props['severity'].lower(),
                    "raw_data": example['data']
                }
            elif "edr" in example["endpoint"]:
                edr_data = example['data']['alert']
                alert_data = {
                    "alert_id": f"edr_{edr_data['id']}",
                    "timestamp": edr_data['timestamp'],
                    "source_system": "edr",
                    "type": "malware",
                    "description": edr_data['description'],
                    "hostname": edr_data['hostname'],
                    "file_path": edr_data['file_path'],
                    "file_hash": edr_data['sha256'],
                    "user_id": edr_data['username'],
                    "raw_data": example['data']
                }
            
            # Process through system
            workflow_id = await system.process_alert(alert_data)
            workflow_ids.append(workflow_id)
            print(f"  → Workflow started: {workflow_id}")
        
        # Wait for processing
        await asyncio.sleep(10)
        
        # Check results
        print("\nWebhook processing results:")
        for i, workflow_id in enumerate(workflow_ids):
            status = await system.get_workflow_status(workflow_id)
            if status:
                endpoint = webhook_examples[i]['endpoint']
                print(f"{endpoint}: {status['status']} - {status.get('final_decision', 'pending')}")
        
    finally:
        await system.shutdown()
    
    print("✓ Webhook integration example completed\n")


# ===============================================
# Example 4: Custom Agent Development
# ===============================================

class ThreatHuntingAgent(CoralAgent):
    """
    Example custom agent for proactive threat hunting
    """
    
    def __init__(self):
        from coral_protocol import AgentCapability
        
        capabilities = [
            AgentCapability(
                name="hunt_threats",
                description="Perform proactive threat hunting based on alert indicators",
                input_schema={"type": "object"},
                output_schema={"type": "object"}
            )
        ]
        
        super().__init__(
            agent_id="threat_hunter",
            name="Threat Hunting Agent",
            capabilities=capabilities
        )
        
        self.hunting_rules = [
            {
                "name": "lateral_movement_detection",
                "indicators": ["multiple_hosts", "admin_tools", "network_scanning"],
                "threshold": 0.7
            },
            {
                "name": "persistence_mechanism",
                "indicators": ["registry_modification", "scheduled_task", "service_creation"],
                "threshold": 0.8
            }
        ]
    
    async def handle_message(self, message):
        """Handle threat hunting requests"""
        if message.message_type == MessageType.THREAT_HUNT_REQUEST:
            await self._perform_threat_hunt(message)
    
    async def _perform_threat_hunt(self, message):
        """Perform threat hunting analysis"""
        alert_data = message.payload.get("alert", {})
        
        # Simulate threat hunting logic
        hunting_results = {
            "hunting_performed": True,
            "rules_triggered": [],
            "risk_score": 0.0,
            "recommendations": []
        }
        
        # Check hunting rules
        for rule in self.hunting_rules:
            score = self._evaluate_hunting_rule(rule, alert_data)
            if score > rule["threshold"]:
                hunting_results["rules_triggered"].append({
                    "rule_name": rule["name"],
                    "confidence": score
                })
                hunting_results["risk_score"] = max(hunting_results["risk_score"], score)
        
        # Generate recommendations
        if hunting_results["risk_score"] > 0.7:
            hunting_results["recommendations"].extend([
                "Immediate investigation required",
                "Check for lateral movement",
                "Review authentication logs"
            ])
        
        # Send results back
        response = message.create_reply(
            sender_id=self.agent_id,
            payload={"hunting_results": hunting_results}
        )
        
        await self.send_message(response)
    
    def _evaluate_hunting_rule(self, rule, alert_data):
        """Evaluate a hunting rule against alert data"""
        # Simplified rule evaluation
        score = 0.0
        for indicator in rule["indicators"]:
            if indicator.lower() in str(alert_data).lower():
                score += 0.3
        
        return min(score, 1.0)


async def example_custom_agent():
    """
    Demonstrate how to create and integrate custom agents
    """
    print("=== Example 4: Custom Agent Development ===")
    
    # Create system with custom agent
    system = AlertTriageSystem()
    
    # Add custom agent to the system
    threat_hunter = ThreatHuntingAgent()
    
    # Initialize system
    await system.initialize()
    
    # Register custom agent
    await threat_hunter.register_with_coral(system.coral_registry)
    
    # Start custom agent processing
    hunting_task = asyncio.create_task(threat_hunter.process_messages())
    
    try:
        print("Custom Threat Hunting Agent registered")
        
        # Create alert that might trigger threat hunting
        alert_data = {
            "alert_id": "CUSTOM-001",
            "timestamp": datetime.datetime.now().isoformat(),
            "source_system": "EDR",
            "type": "lateral_movement",
            "description": "Suspicious admin tools usage detected across multiple_hosts",
            "user_id": "admin_user",
            "tools_used": ["psexec", "wmic", "net"],
            "affected_hosts": ["server01", "server02", "workstation05"]
        }
        
        # Process alert through system
        workflow_id = await system.process_alert(alert_data)
        print(f"Alert processing started: {workflow_id}")
        
        # Simulate threat hunting request
        hunt_message = CoralMessage(
            id="hunt_001",
            sender_id="system",
            receiver_id="threat_hunter",
            message_type=MessageType.THREAT_HUNT_REQUEST,
            thread_id=workflow_id,
            payload={"alert": alert_data},
            timestamp=datetime.datetime.now()
        )
        
        await system.coral_registry.route_message(hunt_message)
        
        # Wait for processing
        await asyncio.sleep(5)
        
        print("Custom agent processing completed")
        
        # Check system metrics including custom agent
        metrics = await system.get_system_metrics()
        print(f"Agents in system: {len(metrics['agents'])}")
        
    finally:
        hunting_task.cancel()
        await system.shutdown()
    
    print("✓ Custom agent development example completed\n")


# ===============================================
# Example 5: Performance Monitoring
# ===============================================

async def example_performance_monitoring():
    """
    Demonstrate system performance monitoring and metrics collection
    """
    print("=== Example 5: Performance Monitoring ===")
    
    system = AlertTriageSystem()
    await system.initialize()
    
    try:
        print("Monitoring system performance during alert processing...")
        
        # Generate alerts with performance tracking
        start_time = datetime.datetime.now()
        workflow_ids = []
        
        # Process alerts in batches to monitor performance
        for batch in range(3):
            print(f"Processing batch {batch + 1}...")
            
            batch_start = datetime.datetime.now()
            batch_workflows = []
            
            # Generate 10 alerts per batch
            for i in range(10):
                alert_data = {
                    "alert_id": f"PERF-B{batch+1}-{i+1:02d}",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "source_system": f"test_system_{batch+1}",
                    "type": ["brute_force", "malware", "phishing"][i % 3],
                    "description": f"Performance test alert {i+1} from batch {batch+1}",
                    "source_ip": f"203.0.113.{(i % 254) + 1}",
                    "user_id": f"test_user_{i+1}"
                }
                
                workflow_id = await system.process_alert(alert_data)
                batch_workflows.append(workflow_id)
            
            workflow_ids.extend(batch_workflows)
            
            # Wait for batch to complete
            await asyncio.sleep(8)
            
            batch_duration = (datetime.datetime.now() - batch_start).total_seconds()
            print(f"  Batch {batch+1} submitted in {batch_duration:.2f}s")
            
            # Check batch completion
            completed = 0
            for wf_id in batch_workflows:
                status = await system.get_workflow_status(wf_id)
                if status and status['status'] == 'completed':
                    completed += 1
            
            print(f"  Batch {batch+1} completion: {completed}/10 workflows")
        
        total_duration = (datetime.datetime.now() - start_time).total_seconds()
        print(f"\nTotal processing time: {total_duration:.2f}s for 30 alerts")
        
        # Get comprehensive metrics
        metrics = await system.get_system_metrics()
        
        print("\n=== System Performance Metrics ===")
        print(f"Total alerts processed: {metrics['system']['alerts_processed']}")
        print(f"Average processing time: {metrics['system']['average_processing_time']:.2f}s")
        print(f"Processing rate: {metrics['system']['alerts_per_second']:.2f} alerts/second")
        print(f"False positive rate: {metrics['system']['false_positive_rate']:.2%}")
        
        print("\n=== Agent Performance ===")
        for agent_id, agent_metrics in metrics['agents'].items():
            if 'queue_size' in agent_metrics:
                print(f"{agent_id}: queue={agent_metrics['queue_size']}")
        
        print("\n=== Registry Metrics ===")
        registry_metrics = metrics['registry']
        print(f"Messages routed: {registry_metrics['total_messages_routed']}")
        print(f"Success rate: {registry_metrics['success_rate']:.2%}")
        print(f"Active workflows: {registry_metrics['active_workflows']}")
        
        # Health check
        health = await system.health_check()
        print(f"\nSystem health: {health['status']}")
        if health['status'] != 'healthy':
            print(f"Issues: {health.get('issues', [])}")
        
    finally:
        await system.shutdown()
    
    print("✓ Performance monitoring example completed\n")


# ===============================================
# Main Example Runner
# ===============================================

async def run_all_examples():
    """Run all examples in sequence"""
    print("Alert Triage System - Usage Examples")
    print("====================================\n")
    
    examples = [
        example_basic_alert_processing,
        example_batch_alert_processing,
        example_webhook_integration,
        example_custom_agent,
        example_performance_monitoring
    ]
    
    for i, example_func in enumerate(examples, 1):
        try:
            await example_func()
        except Exception as e:
            print(f"❌ Example {i} failed: {e}\n")
            continue
        
        # Small delay between examples
        await asyncio.sleep(2)
    
    print("🎉 All examples completed!")


# Utility functions for examples
def create_sample_alerts(count: int) -> List[Dict[str, Any]]:
    """Create sample alerts for testing"""
    alert_types = ["brute_force", "malware", "phishing", "data_exfiltration", "network_anomaly"]
    source_systems = ["Splunk", "QRadar", "Sentinel", "EDR", "Firewall"]
    
    alerts = []
    for i in range(count):
        alerts.append({
            "alert_id": f"SAMPLE-{i+1:03d}",
            "timestamp": datetime.datetime.now().isoformat(),
            "source_system": source_systems[i % len(source_systems)],
            "type": alert_types[i % len(alert_types)],
            "description": f"Sample alert {i+1} for testing",
            "source_ip": f"203.0.113.{(i % 254) + 1}",
            "user_id": f"user_{i+1}",
            "severity": ["low", "medium", "high"][i % 3]
        })
    
    return alerts


# Run examples if script is executed directly
if __name__ == "__main__":
    # Run individual example
    # asyncio.run(example_basic_alert_processing())
    
    # Or run all examples
    asyncio.run(run_all_examples())