"""
Severity Analyzer Agent - Determines alert severity levels
"""

import datetime
import uuid
import logging
from typing import Dict, Any, Tuple, List

from coral_protocol import CoralAgent, AgentCapability, CoralMessage, MessageType
from models.alert_models import SecurityAlert, AlertType, AlertSeverity, UserContext, NetworkContext


logger = logging.getLogger(__name__)


class SeverityAnalyzerAgent(CoralAgent):
    """
    Agent that determines alert severity based on multiple factors
    
    This agent:
    1. Analyzes alert characteristics
    2. Considers contextual factors (time, user, network)
    3. Applies severity rules and ML models
    4. Routes to context gathering with severity assigned
    """
    
    def __init__(self):
        capabilities = [
            AgentCapability(
                name="determine_severity",
                description="Analyze and determine alert severity level using multiple factors",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "context_data": {"type": "object"}
                    },
                    "required": ["alert"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "severity": {"type": "string"},
                        "confidence": {"type": "number"},
                        "reasoning": {"type": "array"},
                        "risk_score": {"type": "number"}
                    }
                }
            ),
            AgentCapability(
                name="escalate_severity",
                description="Escalate alert severity based on new information",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "escalation_reason": {"type": "string"}
                    }
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "new_severity": {"type": "string"},
                        "escalation_approved": {"type": "boolean"}
                    }
                }
            )
        ]
        
        super().__init__(
            agent_id="severity_analyzer",
            name="Severity Analyzer",
            capabilities=capabilities
        )
        
        # Initialize severity rules and scoring
        self._initialize_severity_rules()
        
        # Statistics
        self.alerts_analyzed = 0
        self.severity_distribution = {}
        self.escalations_performed = 0
        
        # Configuration
        self.enable_dynamic_scoring = True
        self.escalation_threshold = 0.8
        
    def _initialize_severity_rules(self):
        """Initialize severity determination rules"""
        
        # Base severity scores by alert type
        self.alert_type_scores = {
            AlertType.MALWARE: 4,
            AlertType.DATA_EXFILTRATION: 5,
            AlertType.PRIVILEGE_ESCALATION: 4,
            AlertType.LATERAL_MOVEMENT: 4,
            AlertType.COMMAND_AND_CONTROL: 4,
            AlertType.BRUTE_FORCE: 2,
            AlertType.PHISHING: 3,
            AlertType.SUSPICIOUS_LOGIN: 2,
            AlertType.NETWORK_ANOMALY: 2,
            AlertType.INSIDER_THREAT: 4,
            AlertType.SUPPLY_CHAIN_ATTACK: 5,
            AlertType.VULNERABILITY_EXPLOITATION: 3,
            AlertType.AI_ANOMALY: 2,
            AlertType.CUSTOM_RULE_MATCH: 1,
            AlertType.UNKNOWN: 1
        }
        
        # Critical assets that increase severity
        self.critical_assets = {
            "domain_controller", "file_server", "database_server",
            "email_server", "web_server", "backup_server",
            "financial_system", "hr_system", "customer_database"
        }
        
        # High-privilege users that increase severity
        self.high_privilege_indicators = {
            "admin", "administrator", "root", "sa", "svc",
            "domain admin", "enterprise admin", "schema admin"
        }
        
        # External threat indicators
        self.external_threat_indicators = {
            "tor_exit_node", "known_malicious", "botnet",
            "malware_c2", "phishing_host", "scanning_source"
        }
        
        # Time-based risk factors
        self.high_risk_hours = set(range(0, 6)) | set(range(22, 24))  # Night hours
        self.high_risk_days = {5, 6}  # Saturday, Sunday
        
    async def handle_message(self, message: CoralMessage):
        """Handle incoming messages"""
        if message.message_type == MessageType.SEVERITY_DETERMINATION:
            await self._analyze_severity(message)
        else:
            logger.warning(f"Unexpected message type: {message.message_type}")
            
    async def _analyze_severity(self, message: CoralMessage):
        """Analyze alert severity"""
        
        try:
            self.alerts_analyzed += 1
            
            # Extract alert from message
            alert_data = message.payload["alert"]
            alert = SecurityAlert.from_dict(alert_data)
            
            logger.info(f"Analyzing severity for alert: {alert.alert_id}")
            
            # Perform severity analysis
            severity, confidence, reasoning, risk_score = await self._determine_severity(alert)
            
            # Update alert
            alert.severity = severity
            if not alert.confidence_score:
                alert.confidence_score = confidence
            else:
                # Combine with previous confidence
                alert.confidence_score = (alert.confidence_score + confidence) / 2
                
            # Track statistics
            severity_str = severity.value
            if severity_str not in self.severity_distribution:
                self.severity_distribution[severity_str] = 0
            self.severity_distribution[severity_str] += 1
            
            # Forward to context gatherer
            await self._forward_to_context_gathering(alert, message.thread_id, reasoning, risk_score)
            
            logger.info(f"Alert {alert.alert_id} severity: {severity.value} (risk score: {risk_score:.2f})")
            
        except Exception as e:
            logger.error(f"Error analyzing severity: {e}")
            await self._send_analysis_error(message, str(e))
            
    async def _determine_severity(self, alert: SecurityAlert) -> Tuple[AlertSeverity, float, List[str], float]:
        """Comprehensive severity determination"""
        
        reasoning = []
        risk_score = 0.0
        
        # Base score from alert type
        base_score = self.alert_type_scores.get(alert.alert_type, 1)
        risk_score += base_score
        reasoning.append(f"Base score for {alert.alert_type.value}: {base_score}")
        
        # Time-based risk assessment
        time_risk, time_reasoning = await self._assess_time_risk(alert)
        risk_score += time_risk
        reasoning.extend(time_reasoning)
        
        # Asset-based risk assessment
        asset_risk, asset_reasoning = await self._assess_asset_risk(alert)
        risk_score += asset_risk
        reasoning.extend(asset_reasoning)
        
        # User-based risk assessment
        user_risk, user_reasoning = await self._assess_user_risk(alert)
        risk_score += user_risk
        reasoning.extend(user_reasoning)
        
        # Network-based risk assessment
        network_risk, network_reasoning = await self._assess_network_risk(alert)
        risk_score += network_risk
        reasoning.extend(network_reasoning)
        
        # Pattern-based risk assessment
        pattern_risk, pattern_reasoning = await self._assess_pattern_risk(alert)
        risk_score += pattern_risk
        reasoning.extend(pattern_reasoning)
        
        # Convert risk score to severity
        severity = self._risk_score_to_severity(risk_score)
        
        # Calculate confidence based on number of contributing factors
        confidence = min(0.9, 0.5 + (len(reasoning) * 0.05))
        
        return severity, confidence, reasoning, risk_score
        
    async def _assess_time_risk(self, alert: SecurityAlert) -> Tuple[float, List[str]]:
        """Assess time-based risk factors"""
        
        risk = 0.0
        reasoning = []
        
        alert_hour = alert.timestamp.hour
        alert_day = alert.timestamp.weekday()
        
        # After-hours activity increases risk
        if alert_hour in self.high_risk_hours:
            risk += 1.0
            reasoning.append(f"Alert occurred during high-risk hours ({alert_hour}:00)")
            
        # Weekend activity increases risk for certain alert types
        if alert_day in self.high_risk_days:
            if alert.alert_type in [AlertType.BRUTE_FORCE, AlertType.DATA_EXFILTRATION,
                                  AlertType.PRIVILEGE_ESCALATION]:
                risk += 0.5
                reasoning.append("Weekend activity for high-risk alert type")
                
        # Holiday/maintenance window logic (simplified)
        if self._is_maintenance_window(alert.timestamp):
            risk -= 0.5
            reasoning.append("Alert during scheduled maintenance window")
            
        return risk, reasoning
        
    async def _assess_asset_risk(self, alert: SecurityAlert) -> Tuple[float, List[str]]:
        """Assess asset-based risk factors"""
        
        risk = 0.0
        reasoning = []
        
        # Check hostname for critical assets
        if alert.hostname:
            hostname_lower = alert.hostname.lower()
            for critical_asset in self.critical_assets:
                if critical_asset in hostname_lower:
                    risk += 2.0
                    reasoning.append(f"Alert involves critical asset: {alert.hostname}")
                    break
                    
        # Check destination IP for critical internal systems
        if alert.destination_ip and self._is_internal_ip(alert.destination_ip):
            # Simplified: assume certain IP ranges are critical
            if alert.destination_ip.startswith("10.0.0."):
                risk += 1.0
                reasoning.append("Alert targets critical internal IP range")
                
        return risk, reasoning
        
    async def _assess_user_risk(self, alert: SecurityAlert) -> Tuple[float, List[str]]:
        """Assess user-based risk factors"""
        
        risk = 0.0
        reasoning = []
        
        if not alert.user_id:
            return risk, reasoning
            
        user_lower = alert.user_id.lower()
        
        # High-privilege account
        for priv_indicator in self.high_privilege_indicators:
            if priv_indicator in user_lower:
                risk += 2.0
                reasoning.append(f"Alert involves high-privilege account: {alert.user_id}")
                break
                
        # Service account (usually lower risk unless compromised)
        if any(svc in user_lower for svc in ["service", "svc", "system"]):
            if alert.alert_type in [AlertType.BRUTE_FORCE, AlertType.SUSPICIOUS_LOGIN]:
                risk -= 0.5
                reasoning.append("Service account activity (potentially legitimate)")
            else:
                risk += 1.0
                reasoning.append("Suspicious activity from service account")
                
        # Executive/sensitive user patterns
        if any(exec_indicator in user_lower for exec_indicator in ["ceo", "cfo", "cto", "vp", "president"]):
            risk += 1.5
            reasoning.append("Alert involves executive/VIP account")
            
        return risk, reasoning
        
    async def _assess_network_risk(self, alert: SecurityAlert) -> Tuple[float, List[str]]:
        """Assess network-based risk factors"""
        
        risk = 0.0
        reasoning = []
        
        # External source IP increases risk
        if alert.source_ip and not self._is_internal_ip(alert.source_ip):
            risk += 1.0
            reasoning.append("Alert from external IP address")
            
            # Check for known threat indicators (simplified)
            if self._is_suspicious_ip(alert.source_ip):
                risk += 2.0
                reasoning.append("Source IP matches threat intelligence indicators")
                
        # Unusual ports
        if alert.destination_port:
            if alert.destination_port in [22, 23, 135, 139, 445, 1433, 3389]:
                risk += 0.5
                reasoning.append(f"Activity on high-risk port: {alert.destination_port}")
                
        # Data volume (for data exfiltration alerts)
        if alert.alert_type == AlertType.DATA_EXFILTRATION:
            # Extract data volume from raw data or description
            data_volume = self._extract_data_volume(alert)
            if data_volume and data_volume > 100:  # MB
                risk += 1.0
                reasoning.append(f"Large data transfer detected: {data_volume}MB")
                
        return risk, reasoning
        
    async def _assess_pattern_risk(self, alert: SecurityAlert) -> Tuple[float, List[str]]:
        """Assess pattern-based risk factors"""
        
        risk = 0.0
        reasoning = []
        
        # Description analysis for high-risk keywords
        if alert.description:
            desc_lower = alert.description.lower()
            
            high_risk_keywords = [
                "privilege escalation", "lateral movement", "credential theft",
                "ransomware", "backdoor", "command and control", "data theft",
                "zero day", "exploit", "persistence", "evasion"
            ]
            
            for keyword in high_risk_keywords:
                if keyword in desc_lower:
                    risk += 1.0
                    reasoning.append(f"High-risk keyword detected: {keyword}")
                    
        # File hash analysis (if available)
        if alert.file_hash:
            # In production, this would check threat intelligence
            if self._is_known_malicious_hash(alert.file_hash):
                risk += 3.0
                reasoning.append("Known malicious file hash detected")
                
        # Process name analysis
        if alert.process_name:
            suspicious_processes = [
                "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                "rundll32.exe", "regsvr32.exe", "mshta.exe"
            ]
            
            if any(proc in alert.process_name.lower() for proc in suspicious_processes):
                risk += 0.5
                reasoning.append(f"Suspicious process detected: {alert.process_name}")
                
        return risk, reasoning
        
    def _risk_score_to_severity(self, risk_score: float) -> AlertSeverity:
        """Convert risk score to severity level"""
        
        if risk_score >= 7.0:
            return AlertSeverity.CRITICAL
        elif risk_score >= 5.0:
            return AlertSeverity.HIGH
        elif risk_score >= 3.0:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
            
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal"""
        return ip.startswith(("10.", "192.168.", "172."))
        
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is suspicious (simplified for demo)"""
        # In production, this would check threat intelligence databases
        suspicious_ranges = ["203.0.113.", "198.51.100.", "192.0.2."]
        return any(ip.startswith(range_) for range_ in suspicious_ranges)
        
    def _is_maintenance_window(self, timestamp: datetime.datetime) -> bool:
        """Check if timestamp falls in maintenance window"""
        # Simplified: assume Sunday 2-4 AM is maintenance
        return timestamp.weekday() == 6 and 2 <= timestamp.hour <= 4
        
    def _extract_data_volume(self, alert: SecurityAlert) -> int:
        """Extract data volume from alert (in MB)"""
        # Look for data volume in raw data or description
        import re
        
        text = alert.description
        if alert.raw_data and 'data_volume' in alert.raw_data:
            text = str(alert.raw_data['data_volume'])
            
        if text:
            # Look for patterns like "500MB", "1.2GB", etc.
            pattern = r'(\d+(?:\.\d+)?)\s*(MB|GB|TB)'
            match = re.search(pattern, text, re.IGNORECASE)
            
            if match:
                value = float(match.group(1))
                unit = match.group(2).upper()
                
                if unit == 'GB':
                    value *= 1024
                elif unit == 'TB':
                    value *= 1024 * 1024
                    
                return int(value)
                
        return 0
        
    def _is_known_malicious_hash(self, file_hash: str) -> bool:
        """Check if file hash is known malicious (simplified)"""
        # In production, this would check threat intelligence
        known_malicious = {
            "abc123def456", "malware_hash_example", "bad_file_hash"
        }
        return file_hash.lower() in known_malicious
        
    async def _forward_to_context_gathering(self, alert: SecurityAlert, thread_id: str,
                                          reasoning: List[str], risk_score: float):
        """Forward alert to context gathering agent"""
        
        next_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id="context_gatherer",
            message_type=MessageType.CONTEXT_GATHERING,
            thread_id=thread_id,
            payload={
                "alert": alert.to_dict(),
                "severity_analysis": {
                    "reasoning": reasoning,
                    "risk_score": risk_score,
                    "analysis_timestamp": datetime.datetime.now().isoformat()
                }
            },
            timestamp=datetime.datetime.now()
        )
        
        await self.send_message(next_message)
        logger.debug(f"Forwarded alert {alert.alert_id} to context gatherer")
        
    async def _send_analysis_error(self, original_message: CoralMessage, error: str):
        """Send analysis error response"""
        
        error_message = original_message.create_reply(
            sender_id=self.agent_id,
            payload={
                "error": f"Severity analysis failed: {error}",
                "original_message_id": original_message.id
            },
            message_type=MessageType.ERROR
        )
        
        await self.send_message(error_message)
        
    def get_agent_metrics(self) -> Dict[str, Any]:
        """Get agent performance metrics"""
        
        return {
            "alerts_analyzed": self.alerts_analyzed,
            "severity_distribution": self.severity_distribution,
            "escalations_performed": self.escalations_performed,
            "average_risk_score": 0.0,  # Would calculate from stored data
            "queue_size": self.message_queue.qsize()
        }
        
    async def health_check(self) -> Dict[str, Any]:
        """Perform agent health check"""
        
        metrics = self.get_agent_metrics()
        
        health_status = "healthy"
        issues = []
        
        if metrics["queue_size"] > 50:
            health_status = "degraded"
            issues.append("High message queue size")
            
        return {
            "status": health_status,
            "issues": issues,
            "metrics": metrics
        }