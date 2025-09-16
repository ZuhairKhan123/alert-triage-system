"""
Unit tests for Alert Receiver Agent
"""

import pytest
import asyncio
import datetime
from unittest.mock import Mock, AsyncMock, patch

from src.agents.alert_receiver import AlertReceiverAgent
from src.coral_protocol import CoralRegistry, CoralMessage, MessageType
from src.models.alert_models import SecurityAlert, AlertType, AlertStatus


class TestAlertReceiverAgent:
    """Test suite for Alert Receiver Agent"""
    
    @pytest.fixture
    async def agent(self):
        """Create a test agent instance"""
        agent = AlertReceiverAgent()
        registry = CoralRegistry()
        await agent.register_with_coral(registry)
        return agent
    
    @pytest.fixture
    def sample_alert_data(self):
        """Sample alert data for testing"""
        return {
            "alert_id": "TEST-001",
            "timestamp": datetime.datetime.now().isoformat(),
            "source_system": "test_siem",
            "type": "brute_force",
            "description": "Test brute force alert",
            "source_ip": "203.0.113.45",
            "user_id": "test_user"
        }
    
    @pytest.mark.asyncio
    async def test_agent_initialization(self, agent):
        """Test agent initialization"""
        assert agent.agent_id == "alert_receiver"
        assert agent.name == "Alert Receiver"
        assert len(agent.capabilities) > 0
        assert agent.alerts_received == 0
        assert agent.alerts_processed == 0
    
    @pytest.mark.asyncio
    async def test_process_valid_alert(self, agent, sample_alert_data):
        """Test processing a valid alert"""
        # Create test message
        message = CoralMessage(
            id="test_msg_001",
            sender_id="test_sender",
            receiver_id=agent.agent_id,
            message_type=MessageType.ALERT_RECEIVED,
            thread_id="test_thread_001",
            payload={"alert_data": sample_alert_data},
            timestamp=datetime.datetime.now()
        )
        
        # Mock the send_message method
        agent.send_message = AsyncMock()
        
        # Process the message
        await agent.handle_message(message)
        
        # Verify stats updated
        assert agent.alerts_received == 1
        assert agent.alerts_processed == 1
        
        # Verify message was forwarded
        agent.send_message.assert_called_once()
        sent_message = agent.send_message.call_args[0][0]
        assert sent_message.receiver_id == "false_positive_checker"
        assert sent_message.message_type == MessageType.FALSE_POSITIVE_CHECK
    
    @pytest.mark.asyncio
    async def test_process_invalid_alert(self, agent):
        """Test processing an invalid alert"""
        # Create test message with invalid data
        invalid_data = {
            "invalid_field": "test"
            # Missing required fields
        }
        
        message = CoralMessage(
            id="test_msg_002",
            sender_id="test_sender",
            receiver_id=agent.agent_id,
            message_type=MessageType.ALERT_RECEIVED,
            thread_id="test_thread_002",
            payload={"alert_data": invalid_data},
            timestamp=datetime.datetime.now()
        )
        
        # Mock the send_message method
        agent.send_message = AsyncMock()
        
        # Process the message
        await agent.handle_message(message)
        
        # Verify validation failure tracked
        assert agent.validation_failures == 1
        
        # Verify error message sent
        agent.send_message.assert_called_once()
        sent_message = agent.send_message.call_args[0][0]
        assert sent_message.message_type == MessageType.ERROR
    
    @pytest.mark.asyncio
    async def test_normalize_source_system(self, agent):
        """Test source system normalization"""
        test_cases = [
            ("Microsoft Sentinel", "sentinel"),
            ("IBM QRadar", "qradar"),
            ("CrowdStrike Falcon", "edr"),
            ("Snort IDS", "ids"),
            ("Custom System", "Custom System")
        ]
        
        for input_system, expected_output in test_cases:
            result = agent._normalize_source_system(input_system)
            assert result == expected_output
    
    @pytest.mark.asyncio
    async def test_create_security_alert(self, agent, sample_alert_data):
        """Test SecurityAlert object creation"""
        alert = await agent._create_security_alert(sample_alert_data)
        
        assert isinstance(alert, SecurityAlert)
        assert alert.alert_id == sample_alert_data["alert_id"]
        assert alert.alert_type == AlertType.BRUTE_FORCE
        assert alert.source_ip == sample_alert_data["source_ip"]
        assert alert.status == AlertStatus.IN_PROGRESS
    
    @pytest.mark.asyncio
    async def test_unknown_alert_type_handling(self, agent):
        """Test handling of unknown alert types"""
        alert_data = {
            "alert_id": "TEST-002",
            "timestamp": datetime.datetime.now().isoformat(),
            "source_system": "test_siem",
            "type": "unknown_type",
            "description": "Test unknown alert type"
        }
        
        alert = await agent._create_security_alert(alert_data)
        assert alert.alert_type == AlertType.UNKNOWN
    
    @pytest.mark.asyncio
    async def test_agent_metrics(self, agent, sample_alert_data):
        """Test agent metrics collection"""
        # Process some alerts
        for i in range(5):
            alert_data = sample_alert_data.copy()
            alert_data["alert_id"] = f"TEST-{i:03d}"
            
            message = CoralMessage(
                id=f"test_msg_{i:03d}",
                sender_id="test_sender",
                receiver_id=agent.agent_id,
                message_type=MessageType.ALERT_RECEIVED,
                thread_id=f"test_thread_{i:03d}",
                payload={"alert_data": alert_data},
                timestamp=datetime.datetime.now()
            )
            
            agent.send_message = AsyncMock()
            await agent.handle_message(message)
        
        # Check metrics
        metrics = agent.get_agent_metrics()
        assert metrics["alerts_received"] == 5
        assert metrics["alerts_processed"] == 5
        assert metrics["success_rate"] == 1.0
        assert metrics["validation_failures"] == 0
    
    @pytest.mark.asyncio
    async def test_health_check(self, agent):
        """Test agent health check"""
        health = await agent.health_check()
        
        assert "status" in health
        assert "metrics" in health
        assert "supported_systems" in health
        assert health["status"] in ["healthy", "degraded"]
    
    @pytest.mark.asyncio
    async def test_concurrent_alert_processing(self, agent, sample_alert_data):
        """Test concurrent alert processing"""
        agent.send_message = AsyncMock()
        
        # Create multiple concurrent alerts
        tasks = []
        for i in range(10):
            alert_data = sample_alert_data.copy()
            alert_data["alert_id"] = f"CONCURRENT-{i:03d}"
            
            message = CoralMessage(
                id=f"concurrent_msg_{i:03d}",
                sender_id="test_sender",
                receiver_id=agent.agent_id,
                message_type=MessageType.ALERT_RECEIVED,
                thread_id=f"concurrent_thread_{i:03d}",
                payload={"alert_data": alert_data},
                timestamp=datetime.datetime.now()
            )
            
            tasks.append(agent.handle_message(message))
        
        # Wait for all to complete
        await asyncio.gather(*tasks)
        
        # Verify all processed
        assert agent.alerts_received == 10
        assert agent.alerts_processed == 10
        assert agent.send_message.call_count == 10
    
    @pytest.mark.asyncio
    async def test_error_handling(self, agent, sample_alert_data):
        """Test error handling in alert processing"""
        # Mock an exception in message sending
        agent.send_message = AsyncMock(side_effect=Exception("Network error"))
        
        message = CoralMessage(
            id="error_test_msg",
            sender_id="test_sender",
            receiver_id=agent.agent_id,
            message_type=MessageType.ALERT_RECEIVED,
            thread_id="error_test_thread",
            payload={"alert_data": sample_alert_data},
            timestamp=datetime.datetime.now()
        )
        
        # Process should not raise exception
        await agent.handle_message(message)
        
        # Verify alert was received but error occurred
        assert agent.alerts_received == 1
        # Processing might not complete due to error


@pytest.mark.integration
class TestAlertReceiverIntegration:
    """Integration tests for Alert Receiver Agent"""
    
    @pytest.fixture
    async def system_setup(self):
        """Setup a minimal system for integration testing"""
        registry = CoralRegistry()
        receiver = AlertReceiverAgent()
        
        await receiver.register_with_coral(registry)
        
        # Start processing
        processing_task = asyncio.create_task(receiver.process_messages())
        
        yield registry, receiver
        
        # Cleanup
        processing_task.cancel()
        try:
            await processing_task
        except asyncio.CancelledError:
            pass
    
    @pytest.mark.asyncio
    async def test_end_to_end_alert_flow(self, system_setup):
        """Test complete alert processing flow"""
        registry, receiver = system_setup
        
        # Create a mock next agent
        mock_fp_checker = Mock()
        mock_fp_checker.agent_id = "false_positive_checker"
        mock_fp_checker.receive_message = AsyncMock()
        
        registry.agents["false_positive_checker"] = mock_fp_checker
        
        # Send alert
        alert_data = {
            "alert_id": "INTEGRATION-001",
            "timestamp": datetime.datetime.now().isoformat(),
            "source_system": "integration_test",
            "type": "malware",
            "description": "Integration test malware alert",
            "source_ip": "198.51.100.42",
            "file_hash": "abc123def456"
        }
        
        message = CoralMessage(
            id="integration_msg_001",
            sender_id="test_system",
            receiver_id=receiver.agent_id,
            message_type=MessageType.ALERT_RECEIVED,
            thread_id="integration_thread_001",
            payload={"alert_data": alert_data},
            timestamp=datetime.datetime.now()
        )
        
        # Route message through registry
        await registry.route_message(message)
        
        # Wait for processing
        await asyncio.sleep(0.1)
        
        # Verify message was forwarded to next agent
        mock_fp_checker.receive_message.assert_called_once()
        
        forwarded_message = mock_fp_checker.receive_message.call_args[0][0]
        assert forwarded_message.message_type == MessageType.FALSE_POSITIVE_CHECK
        assert forwarded_message.sender_id == receiver.agent_id
        
        # Verify alert data in forwarded message
        forwarded_alert = forwarded_message.payload["alert"]
        assert forwarded_alert["alert_id"] == alert_data["alert_id"]
        assert forwarded_alert["alert_type"] == "malware"


# Test fixtures and utilities
@pytest.fixture
def sample_alerts():
    """Collection of sample alerts for testing"""
    return [
        {
            "alert_id": "SAMPLE-001",
            "timestamp": datetime.datetime.now().isoformat(),
            "source_system": "splunk",
            "type": "brute_force",
            "description": "Multiple failed login attempts",
            "source_ip": "203.0.113.45",
            "user_id": "admin_user"
        },
        {
            "alert_id": "SAMPLE-002",
            "timestamp": datetime.datetime.now().isoformat(),
            "source_system": "edr",
            "type": "malware",
            "description": "Suspicious executable detected",
            "file_hash": "abc123def456",
            "hostname": "workstation-001"
        },
        {
            "alert_id": "SAMPLE-003",
            "timestamp": datetime.datetime.now().isoformat(),
            "source_system": "firewall",
            "type": "network_anomaly",
            "description": "Unusual network traffic pattern",
            "source_ip": "10.0.0.100",
            "destination_ip": "198.51.100.42"
        }
    ]


class TestAlertValidation:
    """Test alert data validation"""
    
    def test_valid_alert_data(self, sample_alerts):
        """Test validation of valid alert data"""
        from src.models.alert_models import validate_alert_data
        
        for alert in sample_alerts:
            errors = validate_alert_data(alert)
            assert len(errors) == 0
    
    def test_missing_required_fields(self):
        """Test validation with missing required fields"""
        from src.models.alert_models import validate_alert_data
        
        incomplete_alert = {
            "alert_id": "INCOMPLETE-001",
            # Missing timestamp, source_system, type, description
        }
        
        errors = validate_alert_data(incomplete_alert)
        assert len(errors) > 0
        assert any("timestamp" in error for error in errors)
    
    def test_invalid_ip_addresses(self):
        """Test validation of invalid IP addresses"""
        from src.models.alert_models import validate_alert_data
        
        invalid_alert = {
            "alert_id": "INVALID-001",
            "timestamp": datetime.datetime.now().isoformat(),
            "source_system": "test",
            "type": "network_anomaly",
            "description": "Test alert",
            "source_ip": "999.999.999.999"  # Invalid IP
        }
        
        errors = validate_alert_data(invalid_alert)
        assert any("Invalid IP address format" in error for error in errors)