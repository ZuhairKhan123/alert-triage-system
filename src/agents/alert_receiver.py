"""
Alert Receiver Agent - First stage of the alert triage workflow
"""

import datetime
import uuid
import logging
from typing import Dict, Any
from dataclasses import asdict

from coral_protocol import CoralAgent, AgentCapability, CoralMessage, MessageType
from models.alert_models import SecurityAlert, AlertType, AlertStatus, normalize_alert_data, validate_alert_data


logger = logging.getLogger(__name__)


class AlertReceiverAgent(CoralAgent):
    """
    Agent responsible for receiving and initial processing of security alerts
    
    This agent:
    1. Receives raw alert data from various sources
    2. Normalizes the alert format
    3. Validates the alert data
    4. Forwards to the False Positive Checker
    """
    
    def __init__(self):
        capabilities = [
            AgentCapability(
                name="receive_alert",
                description="Receive and normalize security alerts from various sources",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert_data": {
                            "type": "object",
                            "required": ["alert_id", "timestamp", "source_system", "type", "description"]
                        }
                    },
                    "required": ["alert_data"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "normalized_alert": {"type": "object"},
                        "validation_status": {"type": "string"},
                        "processing_time": {"type": "number"}
                    }
                }
            ),
            AgentCapability(
                name="validate_alert",
                description="Validate alert data structure and content",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert_data": {"type": "object"}
                    }
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "is_valid": {"type": "boolean"},
                        "validation_errors": {"type": "array"}
                    }
                }
            )
        ]
        
        super().__init__(
            agent_id="alert_receiver",
            name="Alert Receiver",
            capabilities=capabilities
        )
        
        # Statistics tracking
        self.alerts_received = 0
        self.alerts_processed = 0
        self.validation_failures = 0
        
        # Configuration
        self.supported_source_systems = [
            "splunk", "qradar", "sentinel", "edr", "ids", "firewall",
            "email_security", "web_proxy", "antivirus", "custom"
        ]
        
    async def handle_message(self, message: CoralMessage):
        """Handle incoming messages"""
        if message.message_type == MessageType.ALERT_RECEIVED:
            await self._process_incoming_alert(message)
        else:
            logger.warning(f"Unexpected message type: {message.message_type}")
            
    async def _process_incoming_alert(self, message: CoralMessage):
        """Process incoming alert data"""
        start_time = datetime.datetime.now()
        
        try:
            self.alerts_received += 1
            
            # Extract alert data from message
            raw_alert_data = message.payload.get("alert_data", message.payload)
            
            logger.info(f"Processing incoming alert: {raw_alert_data.get('alert_id', 'unknown')}")
            
            # Normalize the alert data
            normalized_data = normalize_alert_data(raw_alert_data)
            
            # Validate the alert
            validation_errors = validate_alert_data(normalized_data)
            
            if validation_errors:
                self.validation_failures += 1
                logger.error(f"Alert validation failed: {validation_errors}")
                
                # Send error response
                await self._send_validation_error(message, validation_errors)
                return
            
            # Create SecurityAlert object
            alert = await self._create_security_alert(normalized_data)
            
            # Set workflow tracking
            alert.workflow_id = message.thread_id
            alert.processing_start_time = start_time
            
            # Forward to False Positive Checker
            await self._forward_to_next_agent(alert, message.thread_id)
            
            self.alerts_processed += 1
            
            processing_time = (datetime.datetime.now() - start_time).total_seconds()
            logger.info(f"Alert {alert.alert_id} processed in {processing_time:.2f}s")
            
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
            await self._send_processing_error(message, str(e))
            
    async def _create_security_alert(self, normalized_data: Dict[str, Any]) -> SecurityAlert:
        """Create SecurityAlert object from normalized data"""
        
        # Handle timestamp conversion
        timestamp = normalized_data.get("timestamp")
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.datetime.fromisoformat(timestamp)
            except ValueError:
                timestamp = datetime.datetime.now()
        elif not isinstance(timestamp, datetime.datetime):
            timestamp = datetime.datetime.now()
            
        # Handle alert type conversion
        alert_type_str = normalized_data.get("alert_type", normalized_data.get("type", "unknown"))
        try:
            alert_type = AlertType(alert_type_str.lower())
        except ValueError:
            logger.warning(f"Unknown alert type '{alert_type_str}', using UNKNOWN")
            alert_type = AlertType.UNKNOWN
            
        # Create the alert
        alert = SecurityAlert(
            alert_id=normalized_data.get("alert_id", str(uuid.uuid4())),
            timestamp=timestamp,
            source_system=self._normalize_source_system(normalized_data.get("source_system", "unknown")),
            alert_type=alert_type,
            description=normalized_data.get("description", ""),
            
            # Network information
            source_ip=normalized_data.get("source_ip"),
            destination_ip=normalized_data.get("destination_ip"),
            source_port=normalized_data.get("source_port"),
            destination_port=normalized_data.get("destination_port"),
            protocol=normalized_data.get("protocol"),
            
            # User and asset information
            user_id=normalized_data.get("user_id"),
            hostname=normalized_data.get("hostname"),
            process_name=normalized_data.get("process_name"),
            file_path=normalized_data.get("file_path"),
            file_hash=normalized_data.get("file_hash"),
            
            # Metadata
            raw_data=normalized_data,
            tags=normalized_data.get("tags", []),
            status=AlertStatus.IN_PROGRESS
        )
        
        return alert
        
    def _normalize_source_system(self, source_system: str) -> str:
        """Normalize source system names"""
        source_lower = source_system.lower()
        
        # Map variations to standard names
        system_mappings = {
            "microsoft sentinel": "sentinel",
            "azure sentinel": "sentinel",
            "ibm qradar": "qradar",
            "crowdstrike": "edr",
            "carbon black": "edr",
            "snort": "ids",
            "suricata": "ids",
            "palo alto": "firewall",
            "cisco asa": "firewall",
            "fortinet": "firewall"
        }
        
        for pattern, standard_name in system_mappings.items():
            if pattern in source_lower:
                return standard_name
                
        return source_system
        
    async def _forward_to_next_agent(self, alert: SecurityAlert, thread_id: str):
        """Forward alert to False Positive Checker"""
        
        next_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id="false_positive_checker",
            message_type=MessageType.FALSE_POSITIVE_CHECK,
            thread_id=thread_id,
            payload={
                "alert": alert.to_dict(),
                "processing_metadata": {
                    "received_at": datetime.datetime.now().isoformat(),
                    "source_agent": self.agent_id
                }
            },
            timestamp=datetime.datetime.now()
        )
        
        await self.send_message(next_message)
        logger.debug(f"Forwarded alert {alert.alert_id} to false positive checker")
        
    async def _send_validation_error(self, original_message: CoralMessage, validation_errors: list):
        """Send validation error response"""
        
        error_message = original_message.create_reply(
            sender_id=self.agent_id,
            payload={
                "error": "Alert validation failed",
                "validation_errors": validation_errors,
                "original_alert_data": original_message.payload
            },
            message_type=MessageType.ERROR
        )
        
        await self.send_message(error_message)
        
    async def _send_processing_error(self, original_message: CoralMessage, error: str):
        """Send processing error response"""
        
        error_message = original_message.create_reply(
            sender_id=self.agent_id,
            payload={
                "error": f"Alert processing failed: {error}",
                "original_message_id": original_message.id
            },
            message_type=MessageType.ERROR
        )
        
        await self.send_message(error_message)
        
    def get_agent_metrics(self) -> Dict[str, Any]:
        """Get agent performance metrics"""
        return {
            "alerts_received": self.alerts_received,
            "alerts_processed": self.alerts_processed,
            "validation_failures": self.validation_failures,
            "success_rate": (
                self.alerts_processed / self.alerts_received 
                if self.alerts_received > 0 else 0
            ),
            "queue_size": self.message_queue.qsize(),
            "active_threads": len(self.active_threads)
        }
        
    async def health_check(self) -> Dict[str, Any]:
        """Perform agent health check"""
        metrics = self.get_agent_metrics()
        
        # Determine health status
        health_status = "healthy"
        issues = []
        
        if metrics["queue_size"] > 100:
            health_status = "degraded"
            issues.append("High message queue size")
            
        if metrics["success_rate"] < 0.95:
            health_status = "degraded"
            issues.append("Low success rate")
            
        return {
            "status": health_status,
            "issues": issues,
            "metrics": metrics,
            "supported_systems": self.supported_source_systems
        }