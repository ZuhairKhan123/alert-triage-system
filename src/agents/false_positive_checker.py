"""
False Positive Checker Agent - Determines if alerts are false positives
"""

import datetime
import uuid
import logging
from typing import Dict, Any, Tuple, List

from coral_protocol import CoralAgent, AgentCapability, CoralMessage, MessageType
from models.alert_models import SecurityAlert, AlertType, AlertStatus


logger = logging.getLogger(__name__)


class FalsePositiveCheckerAgent(CoralAgent):
    """
    Agent that determines if an alert is a false positive
    
    This agent:
    1. Analyzes alerts for false positive indicators
    2. Uses rule-based and ML-based detection
    3. Routes false positives to completion
    4. Routes legitimate alerts to severity analysis
    """
    
    def __init__(self):
        capabilities = [
            AgentCapability(
                name="check_false_positive",
                description="Analyze alerts for false positive indicators using multiple techniques",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "analysis_options": {
                            "type": "object",
                            "properties": {
                                "use_ml_model": {"type": "boolean"},
                                "confidence_threshold": {"type": "number"}
                            }
                        }
                    },
                    "required": ["alert"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "is_false_positive": {"type": "boolean"},
                        "confidence": {"type": "number"},
                        "reasoning": {"type": "array"},
                        "analysis_method": {"type": "string"}
                    }
                }
            ),
            AgentCapability(
                name="update_false_positive_rules",
                description="Update false positive detection rules based on feedback",
                input_schema={
                    "type": "object",
                    "properties": {
                        "feedback_data": {"type": "array"}
                    }
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "rules_updated": {"type": "integer"},
                        "new_patterns": {"type": "array"}
                    }
                }
            )
        ]
        
        super().__init__(
            agent_id="false_positive_checker",
            name="False Positive Checker",
            capabilities=capabilities
        )
        
        # False positive detection patterns
        self._initialize_detection_patterns()
        
        # Statistics
        self.alerts_analyzed = 0
        self.false_positives_detected = 0
        self.confidence_scores = []
        
        # Configuration
        self.confidence_threshold = 0.7
        self.enable_ml_analysis = True
        
    def _initialize_detection_patterns(self):
        """Initialize false positive detection patterns"""
        
        # Known good IP ranges (typically internal/trusted)
        self.known_good_ips = {
            "10.0.0.0/8",
            "172.16.0.0/12", 
            "192.168.0.0/16",
            "127.0.0.0/8"
        }
        
        # Specific trusted IPs (load from config in production)
        self.trusted_ips = {
            "10.0.0.1",      # Internal DNS
            "192.168.1.1",   # Default gateway
            "10.0.0.100",    # Domain controller
            "192.168.1.100"  # Mail server
        }
        
        # Test and service accounts
        self.test_accounts = {
            "test_user", "qa_account", "service_account", 
            "monitor_user", "backup_service", "scan_user"
        }
        
        # Scheduled processes and legitimate activities
        self.scheduled_processes = {
            "backup_process", "maintenance_script", "antivirus_scan",
            "log_rotation", "system_update", "health_check",
            "scheduled_task", "cron_job"
        }
        
        # Known false positive patterns by alert type
        self.fp_patterns = {
            AlertType.BRUTE_FORCE: [
                "password_policy_test",
                "account_lockout_test",
                "authentication_service_restart"
            ],
            AlertType.SUSPICIOUS_LOGIN: [
                "scheduled_service_login",
                "automated_monitoring_login",
                "service_account_authentication"
            ],
            AlertType.NETWORK_ANOMALY: [
                "backup_traffic",
                "software_update_download",
                "legitimate_file_transfer"
            ],
            AlertType.MALWARE: [
                "antivirus_test_file",
                "security_training_simulation",
                "penetration_test_tool"
            ]
        }
        
        # Business hours configuration
        self.business_hours = {
            "start": 8,  # 8 AM
            "end": 18,   # 6 PM
            "timezone": "UTC"
        }
        
    async def handle_message(self, message: CoralMessage):
        """Handle incoming messages"""
        if message.message_type == MessageType.FALSE_POSITIVE_CHECK:
            await self._analyze_false_positive(message)
        else:
            logger.warning(f"Unexpected message type: {message.message_type}")
            
    async def _analyze_false_positive(self, message: CoralMessage):
        """Analyze alert for false positive indicators"""
        
        try:
            self.alerts_analyzed += 1
            
            # Extract alert from message
            alert_data = message.payload["alert"]
            alert = SecurityAlert.from_dict(alert_data)
            
            logger.info(f"Analyzing false positive for alert: {alert.alert_id}")
            
            # Perform analysis
            is_false_positive, confidence, reasoning = await self._perform_analysis(alert)
            
            # Update alert
            alert.is_false_positive = is_false_positive
            alert.confidence_score = confidence
            
            # Track statistics
            if is_false_positive:
                self.false_positives_detected += 1
                alert.status = AlertStatus.FALSE_POSITIVE
                
            self.confidence_scores.append(confidence)
            
            # Route to next step
            if is_false_positive:
                await self._complete_workflow_as_false_positive(alert, message.thread_id, reasoning)
            else:
                await self._forward_to_severity_analysis(alert, message.thread_id, reasoning)
                
            logger.info(f"Alert {alert.alert_id} analysis complete: FP={is_false_positive}, confidence={confidence:.2f}")
            
        except Exception as e:
            logger.error(f"Error analyzing false positive: {e}")
            await self._send_analysis_error(message, str(e))
            
    async def _perform_analysis(self, alert: SecurityAlert) -> Tuple[bool, float, List[str]]:
        """Perform comprehensive false positive analysis"""
        
        reasoning = []
        confidence_factors = []
        
        # Rule-based analysis
        rule_score, rule_reasoning = await self._rule_based_analysis(alert)
        confidence_factors.append(rule_score)
        reasoning.extend(rule_reasoning)
        
        # Time-based analysis
        time_score, time_reasoning = await self._time_based_analysis(alert)
        confidence_factors.append(time_score)
        reasoning.extend(time_reasoning)
        
        # Pattern-based analysis
        pattern_score, pattern_reasoning = await self._pattern_based_analysis(alert)
        confidence_factors.append(pattern_score)
        reasoning.extend(pattern_reasoning)
        
        # ML-based analysis (if enabled)
        if self.enable_ml_analysis:
            ml_score, ml_reasoning = await self._ml_based_analysis(alert)
            confidence_factors.append(ml_score)
            reasoning.extend(ml_reasoning)
            
        # Calculate overall confidence
        overall_confidence = sum(confidence_factors) / len(confidence_factors)
        is_false_positive = overall_confidence > self.confidence_threshold
        
        return is_false_positive, overall_confidence, reasoning
        
    async def _rule_based_analysis(self, alert: SecurityAlert) -> Tuple[float, List[str]]:
        """Rule-based false positive analysis"""
        
        score = 0.0
        reasoning = []
        
        # Check trusted IPs
        if alert.source_ip and alert.source_ip in self.trusted_ips:
            score += 0.8
            reasoning.append(f"Source IP {alert.source_ip} is in trusted list")
            
        # Check for internal IP ranges
        if alert.source_ip and self._is_internal_ip(alert.source_ip):
            score += 0.3
            reasoning.append("Alert from internal IP range")
            
        # Check test accounts
        if alert.user_id and any(test_acc in alert.user_id.lower() 
                                for test_acc in self.test_accounts):
            score += 0.9
            reasoning.append(f"User {alert.user_id} appears to be a test/service account")
            
        # Check scheduled processes
        if any(process in alert.description.lower() 
               for process in self.scheduled_processes):
            score += 0.7
            reasoning.append("Alert description contains scheduled process indicators")
            
        # Check alert type specific patterns
        if alert.alert_type in self.fp_patterns:
            for pattern in self.fp_patterns[alert.alert_type]:
                if pattern in alert.description.lower():
                    score += 0.6
                    reasoning.append(f"Found known false positive pattern: {pattern}")
                    break
                    
        return min(score, 1.0), reasoning
        
    async def _time_based_analysis(self, alert: SecurityAlert) -> Tuple[float, List[str]]:
        """Time-based false positive analysis"""
        
        score = 0.0
        reasoning = []
        
        alert_hour = alert.timestamp.hour
        
        # Business hours are typically less suspicious for many activities
        if self.business_hours["start"] <= alert_hour <= self.business_hours["end"]:
            score += 0.2
            reasoning.append("Alert occurred during business hours")
        else:
            # After hours could be more suspicious, but some activities are scheduled
            if alert.alert_type in [AlertType.NETWORK_ANOMALY, AlertType.SUSPICIOUS_LOGIN]:
                # These could be legitimate maintenance activities
                score += 0.1
                reasoning.append("After-hours activity that could be maintenance")
                
        # Weekend analysis (assuming Sunday = 6)
        if alert.timestamp.weekday() in [5, 6]:  # Saturday, Sunday
            if alert.alert_type in [AlertType.BRUTE_FORCE, AlertType.SUSPICIOUS_LOGIN]:
                score += 0.1
                reasoning.append("Weekend activity could be automated systems")
                
        return score, reasoning
        
    async def _pattern_based_analysis(self, alert: SecurityAlert) -> Tuple[float, List[str]]:
        """Pattern-based analysis using historical data"""
        
        score = 0.0
        reasoning = []
        
        # Analyze description for common false positive keywords
        fp_keywords = [
            "test", "demo", "training", "simulation", "exercise",
            "scheduled", "automated", "backup", "maintenance",
            "update", "patch", "scan", "monitor", "health_check"
        ]
        
        description_lower = alert.description.lower()
        matching_keywords = [kw for kw in fp_keywords if kw in description_lower]
        
        if matching_keywords:
            score += 0.4 * len(matching_keywords) / len(fp_keywords)
            reasoning.append(f"Description contains FP keywords: {matching_keywords}")
            
        # Check for repeated identical alerts (common for false positives)
        # In production, this would check a database of recent alerts
        if self._is_repeated_alert_pattern(alert):
            score += 0.3
            reasoning.append("Similar alert pattern detected recently")
            
        return min(score, 1.0), reasoning
        
    async def _ml_based_analysis(self, alert: SecurityAlert) -> Tuple[float, List[str]]:
        """ML-based false positive analysis"""
        
        # In production, this would use a trained ML model
        # For demo purposes, we'll simulate ML analysis
        
        score = 0.0
        reasoning = []
        
        # Extract features for ML model
        features = self._extract_ml_features(alert)
        
        # Simulate ML model prediction
        # In reality: ml_score = self.ml_model.predict_proba([features])[0][1]
        ml_score = self._simulate_ml_prediction(features)
        
        score = ml_score
        reasoning.append(f"ML model prediction confidence: {ml_score:.2f}")
        
        return score, reasoning
        
    def _extract_ml_features(self, alert: SecurityAlert) -> List[float]:
        """Extract features for ML model"""
        
        features = []
        
        # Time-based features
        features.append(alert.timestamp.hour / 24.0)  # Hour of day normalized
        features.append(alert.timestamp.weekday() / 7.0)  # Day of week normalized
        
        # Alert type encoding (simplified)
        alert_type_encoding = {
            AlertType.MALWARE: 0.1,
            AlertType.BRUTE_FORCE: 0.3,
            AlertType.SUSPICIOUS_LOGIN: 0.5,
            AlertType.NETWORK_ANOMALY: 0.7,
            AlertType.UNKNOWN: 0.9
        }
        features.append(alert_type_encoding.get(alert.alert_type, 0.5))
        
        # IP-based features
        features.append(1.0 if self._is_internal_ip(alert.source_ip) else 0.0)
        
        # User-based features
        features.append(1.0 if self._is_service_account(alert.user_id) else 0.0)
        
        # Description length (normalized)
        features.append(min(len(alert.description) / 1000.0, 1.0))
        
        return features
        
    def _simulate_ml_prediction(self, features: List[float]) -> float:
        """Simulate ML model prediction for demo purposes"""
        # Simple heuristic that mimics ML behavior
        weighted_sum = (
            features[0] * 0.1 +  # Hour weight
            features[1] * 0.05 + # Day weight  
            features[2] * 0.3 +  # Alert type weight
            features[3] * 0.4 +  # Internal IP weight
            features[4] * 0.15   # Service account weight
        )
        
        # Add some randomness to simulate model uncertainty
        import random
        noise = random.uniform(-0.1, 0.1)
        
        return max(0.0, min(1.0, weighted_sum + noise))
        
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is in internal ranges"""
        if not ip:
            return False
            
        # Simple check for RFC 1918 private addresses
        return (ip.startswith("10.") or 
                ip.startswith("192.168.") or 
                ip.startswith("172."))
                
    def _is_service_account(self, user_id: str) -> bool:
        """Check if user appears to be a service account"""
        if not user_id:
            return False
            
        service_indicators = ["service", "svc", "system", "admin", "test", "monitor"]
        user_lower = user_id.lower()
        
        return any(indicator in user_lower for indicator in service_indicators)
        
    def _is_repeated_alert_pattern(self, alert: SecurityAlert) -> bool:
        """Check if this alert matches recent patterns (simplified for demo)"""
        # In production, this would check a database
        # For demo, simulate based on certain conditions
        
        if alert.alert_type == AlertType.BRUTE_FORCE and alert.source_ip:
            # Simulate: if it's from internal IP and during business hours
            return self._is_internal_ip(alert.source_ip) and 8 <= alert.timestamp.hour <= 18
            
        return False
        
    async def _complete_workflow_as_false_positive(self, alert: SecurityAlert, 
                                                 thread_id: str, reasoning: List[str]):
        """Complete workflow marking alert as false positive"""
        
        completion_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id="workflow_orchestrator",
            message_type=MessageType.WORKFLOW_COMPLETE,
            thread_id=thread_id,
            payload={
                "alert": alert.to_dict(),
                "action": "dismissed_false_positive",
                "analysis_reasoning": reasoning,
                "processing_metadata": {
                    "completed_by": self.agent_id,
                    "completion_time": datetime.datetime.now().isoformat(),
                    "confidence_score": alert.confidence_score
                }
            },
            timestamp=datetime.datetime.now()
        )
        
        await self.send_message(completion_message)
        logger.info(f"Completed workflow for false positive alert {alert.alert_id}")
        
    async def _forward_to_severity_analysis(self, alert: SecurityAlert, 
                                          thread_id: str, reasoning: List[str]):
        """Forward legitimate alert to severity analysis"""
        
        next_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id="severity_analyzer",
            message_type=MessageType.SEVERITY_DETERMINATION,
            thread_id=thread_id,
            payload={
                "alert": alert.to_dict(),
                "fp_analysis_reasoning": reasoning,
                "processing_metadata": {
                    "analyzed_by": self.agent_id,
                    "analysis_time": datetime.datetime.now().isoformat(),
                    "confidence_score": alert.confidence_score
                }
            },
            timestamp=datetime.datetime.now()
        )
        
        await self.send_message(next_message)
        logger.debug(f"Forwarded alert {alert.alert_id} to severity analyzer")
        
    async def _send_analysis_error(self, original_message: CoralMessage, error: str):
        """Send analysis error response"""
        
        error_message = original_message.create_reply(
            sender_id=self.agent_id,
            payload={
                "error": f"False positive analysis failed: {error}",
                "original_message_id": original_message.id
            },
            message_type=MessageType.ERROR
        )
        
        await self.send_message(error_message)
        
    def get_agent_metrics(self) -> Dict[str, Any]:
        """Get agent performance metrics"""
        avg_confidence = (
            sum(self.confidence_scores) / len(self.confidence_scores)
            if self.confidence_scores else 0
        )
        
        return {
            "alerts_analyzed": self.alerts_analyzed,
            "false_positives_detected": self.false_positives_detected,
            "false_positive_rate": (
                self.false_positives_detected / self.alerts_analyzed
                if self.alerts_analyzed > 0 else 0
            ),
            "average_confidence": avg_confidence,
            "confidence_threshold": self.confidence_threshold,
            "queue_size": self.message_queue.qsize()
        }