"""
Response Coordinator Agent - Determines and coordinates appropriate response actions
"""

import datetime
import uuid
import logging
from typing import Dict, Any, List, Tuple

from coral_protocol import CoralAgent, AgentCapability, CoralMessage, MessageType
from models.alert_models import (
    SecurityAlert, AlertSeverity, AlertType, ResponseAction, 
    AlertStatus, IncidentTicket
)


logger = logging.getLogger(__name__)


class ResponseCoordinatorAgent(CoralAgent):
    """
    Agent that determines and coordinates appropriate response actions
    
    This agent:
    1. Analyzes enriched alert data
    2. Determines appropriate response actions
    3. Assigns to appropriate analysts/teams
    4. Creates incidents in SOAR platforms
    5. Coordinates automated response actions
    6. Completes the workflow
    """
    
    def __init__(self):
        capabilities = [
            AgentCapability(
                name="coordinate_response",
                description="Determine and coordinate comprehensive response actions",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "context_data": {"type": "object"},
                        "response_options": {"type": "object"}
                    },
                    "required": ["alert"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "response_actions": {"type": "array"},
                        "assignment": {"type": "string"},
                        "incident_created": {"type": "boolean"},
                        "automation_triggered": {"type": "boolean"}
                    }
                }
            ),
            AgentCapability(
                name="escalate_response",
                description="Escalate response for high-severity or complex alerts",
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
                        "escalation_level": {"type": "string"},
                        "escalated_to": {"type": "string"},
                        "urgency": {"type": "string"}
                    }
                }
            )
        ]
        
        super().__init__(
            agent_id="response_coordinator",
            name="Response Coordinator",
            capabilities=capabilities
        )
        
        # Initialize response logic and assignments
        self._initialize_response_logic()
        
        # Statistics
        self.alerts_processed = 0
        self.incidents_created = 0
        self.escalations_performed = 0
        self.automated_actions_triggered = 0
        
        # Configuration
        self.auto_escalation_threshold = 0.8
        self.enable_automation = True
        self.default_assignment_tier = "tier1_analyst"
        
    def _initialize_response_logic(self):
        """Initialize response determination logic"""
        
        # Response action mapping by severity
        self.severity_response_map = {
            AlertSeverity.CRITICAL: [
                ResponseAction.ESCALATE,
                ResponseAction.CREATE_INCIDENT,
                ResponseAction.NOTIFY_ANALYST,
                ResponseAction.PRESERVE_EVIDENCE,
                ResponseAction.CONTAIN
            ],
            AlertSeverity.HIGH: [
                ResponseAction.CREATE_INCIDENT,
                ResponseAction.INVESTIGATE,
                ResponseAction.NOTIFY_ANALYST,
                ResponseAction.MONITOR
            ],
            AlertSeverity.MEDIUM: [
                ResponseAction.INVESTIGATE,
                ResponseAction.MONITOR,
                ResponseAction.NOTIFY_ANALYST
            ],
            AlertSeverity.LOW: [
                ResponseAction.MONITOR,
                ResponseAction.AUTO_RESOLVE
            ]
        }
        
        # Assignment mapping by severity and alert type
        self.assignment_map = {
            AlertSeverity.CRITICAL: "senior_analyst",
            AlertSeverity.HIGH: "tier2_analyst", 
            AlertSeverity.MEDIUM: "tier1_analyst",
            AlertSeverity.LOW: "automated_system"
        }
        
        # Escalation conditions
        self.escalation_conditions = {
            "executive_user": lambda alert: self._is_executive_user(alert.user_id),
            "critical_asset": lambda alert: self._is_critical_asset(alert.hostname),
            "active_campaign": lambda alert: self._is_active_campaign(alert),
            "multi_stage_attack": lambda alert: self._is_multi_stage_attack(alert),
            "data_exfiltration": lambda alert: alert.alert_type == AlertType.DATA_EXFILTRATION,
            "external_threat": lambda alert: self._has_external_threat_indicators(alert)
        }
        
        # Automated response capabilities
        self.automation_rules = {
            "block_malicious_ip": {
                "condition": lambda alert, context: self._should_block_ip(alert, context),
                "action": "block_source_ip",
                "approval_required": False
            },
            "isolate_compromised_host": {
                "condition": lambda alert, context: self._should_isolate_host(alert, context),
                "action": "isolate_host",
                "approval_required": True
            },
            "disable_compromised_user": {
                "condition": lambda alert, context: self._should_disable_user(alert, context),
                "action": "disable_user_account",
                "approval_required": True
            },
            "quarantine_malware": {
                "condition": lambda alert, context: alert.alert_type == AlertType.MALWARE,
                "action": "quarantine_file",
                "approval_required": False
            }
        }
        
        # SOAR integration settings
        self.soar_enabled = False
        self.soar_incident_templates = {
            AlertSeverity.CRITICAL: "critical_incident_template",
            AlertSeverity.HIGH: "high_priority_template",
            AlertSeverity.MEDIUM: "standard_incident_template"
        }
        
    async def handle_message(self, message: CoralMessage):
        """Handle incoming messages"""
        if message.message_type == MessageType.RESPONSE_DECISION:
            await self._coordinate_response(message)
        else:
            logger.warning(f"Unexpected message type: {message.message_type}")
            
    async def _coordinate_response(self, message: CoralMessage):
        """Coordinate comprehensive response for the alert"""
        
        try:
            self.alerts_processed += 1
            
            # Extract alert and context from message
            alert_data = message.payload["alert"]
            alert = SecurityAlert.from_dict(alert_data)
            context_data = alert.context_data or {}
            
            logger.info(f"Coordinating response for alert: {alert.alert_id}")
            
            # Determine response actions
            actions, assignment = await self._determine_response_actions(alert, context_data)
            
            # Check for escalation conditions
            escalation_needed, escalation_reason = await self._check_escalation_conditions(alert, context_data)
            
            if escalation_needed:
                actions, assignment = await self._escalate_response(alert, escalation_reason, actions, assignment)
                
            # Execute automated actions
            automation_results = await self._execute_automated_actions(alert, context_data, actions)
            
            # Create incident ticket if needed
            incident_ticket = await self._create_incident_ticket(alert, actions, assignment)
            
            # Update alert with response information
            alert.recommended_actions = actions
            alert.assigned_analyst = assignment
            alert.status = self._determine_alert_status(actions)
            
            # Complete the workflow
            await self._complete_workflow(alert, message.thread_id, {
                "response_actions": [action.value for action in actions],
                "assignment": assignment,
                "incident_ticket": incident_ticket.to_dict() if incident_ticket else None,
                "automation_results": automation_results,
                "escalation_performed": escalation_needed
            })
            
            logger.info(f"Response coordination complete for alert {alert.alert_id}: "
                       f"{len(actions)} actions, assigned to {assignment}")
            
        except Exception as e:
            logger.error(f"Error coordinating response: {e}")
            await self._send_coordination_error(message, str(e))
            
    async def _determine_response_actions(self, alert: SecurityAlert, 
                                        context_data: Dict[str, Any]) -> Tuple[List[ResponseAction], str]:
        """Determine appropriate response actions and assignment"""
        
        # Start with base actions for severity level
        base_actions = self.severity_response_map.get(alert.severity, [ResponseAction.MONITOR])
        actions = list(base_actions)
        
        # Get base assignment
        assignment = self.assignment_map.get(alert.severity, self.default_assignment_tier)
        
        # Add context-specific actions
        context_actions = await self._determine_context_actions(alert, context_data)
        actions.extend(context_actions)
        
        # Add threat intelligence-based actions
        threat_intel_actions = await self._determine_threat_intel_actions(alert, context_data)
        actions.extend(threat_intel_actions)
        
        # Add user context-based actions
        user_actions = await self._determine_user_actions(alert, context_data)
        actions.extend(user_actions)
        
        # Add network context-based actions
        network_actions = await self._determine_network_actions(alert, context_data)
        actions.extend(network_actions)
        
        # Remove duplicates while preserving order
        unique_actions = []
        for action in actions:
            if action not in unique_actions:
                unique_actions.append(action)
                
        return unique_actions, assignment
        
    async def _determine_context_actions(self, alert: SecurityAlert, 
                                       context_data: Dict[str, Any]) -> List[ResponseAction]:
        """Determine actions based on alert context"""
        
        actions = []
        
        # Check for historical patterns
        if "historical_patterns" in context_data:
            similar_alerts = context_data["historical_patterns"].get("similar_alerts", [])
            
            # If similar alerts were false positives, be cautious
            fp_count = sum(1 for sa in similar_alerts if sa.get("outcome") == "false_positive")
            if fp_count >= 2:
                actions.append(ResponseAction.MONITOR)
            # If similar alerts were escalated, escalate this one too
            elif any(sa.get("outcome") == "escalated" for sa in similar_alerts):
                actions.append(ResponseAction.ESCALATE)
                
        # Check for campaign indicators
        if "campaign_analysis" in context_data:
            campaigns = context_data["campaign_analysis"].get("potential_campaigns", [])
            if campaigns:
                actions.extend([ResponseAction.INVESTIGATE, ResponseAction.PRESERVE_EVIDENCE])
                
        return actions
        
    async def _determine_threat_intel_actions(self, alert: SecurityAlert,
                                            context_data: Dict[str, Any]) -> List[ResponseAction]:
        """Determine actions based on threat intelligence"""
        
        actions = []
        
        threat_intel = context_data.get("threat_intelligence", {})
        
        for indicator, intel in threat_intel.items():
            if isinstance(intel, dict):
                reputation = intel.get("reputation", "unknown")
                confidence = intel.get("confidence", 0.0)
                
                if reputation == "malicious" and confidence > 0.8:
                    # High-confidence malicious indicator
                    if self._is_ip_address(indicator):
                        actions.append(ResponseAction.BLOCK_IP)
                    actions.extend([ResponseAction.INVESTIGATE, ResponseAction.PRESERVE_EVIDENCE])
                    
                elif reputation == "suspicious" and confidence > 0.6:
                    # Suspicious indicator requires investigation
                    actions.extend([ResponseAction.INVESTIGATE, ResponseAction.MONITOR])
                    
        return actions
        
    async def _determine_user_actions(self, alert: SecurityAlert,
                                    context_data: Dict[str, Any]) -> List[ResponseAction]:
        """Determine actions based on user context"""
        
        actions = []
        
        user_context = context_data.get("user_context")
        if user_context:
            privilege_level = user_context.get("privilege_level", "standard")
            
            # High-privilege users require more careful handling
            if privilege_level in ["admin", "elevated"]:
                actions.extend([ResponseAction.INVESTIGATE, ResponseAction.NOTIFY_ANALYST])
                
            # Check for unusual behavior
            behavior_analysis = context_data.get("behavior_analysis", {})
            risk_factors = behavior_analysis.get("risk_factors", [])
            
            if "activity_outside_normal_hours" in risk_factors:
                actions.append(ResponseAction.INVESTIGATE)
                
            if "suspicious_authentication_activity" in risk_factors:
                actions.extend([ResponseAction.INVESTIGATE, ResponseAction.MONITOR])
                
        return actions
        
    async def _determine_network_actions(self, alert: SecurityAlert,
                                       context_data: Dict[str, Any]) -> List[ResponseAction]:
        """Determine actions based on network context"""
        
        actions = []
        
        # Check network flow analysis
        flow_analysis = context_data.get("flow_analysis", {})
        connection_type = flow_analysis.get("connection_type")
        
        if connection_type == "outbound":
            # Outbound connections to external IPs
            actions.append(ResponseAction.MONITOR)
            
            # Large data transfers warrant investigation
            data_volume = flow_analysis.get("data_volume", 0)
            if isinstance(data_volume, str) and "GB" in data_volume:
                actions.extend([ResponseAction.INVESTIGATE, ResponseAction.CONTAIN])
                
        # Check geolocation context
        geolocation = context_data.get("geolocation", {})
        for ip, geo_info in geolocation.items():
            country = geo_info.get("country", "unknown")
            
            # High-risk countries require additional scrutiny
            high_risk_countries = ["RU", "CN", "KP", "IR"]
            if country in high_risk_countries:
                actions.extend([ResponseAction.INVESTIGATE, ResponseAction.BLOCK_IP])
                
        return actions
        
    async def _check_escalation_conditions(self, alert: SecurityAlert,
                                         context_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Check if alert meets escalation conditions"""
        
        escalation_reasons = []
        
        # Check each escalation condition
        for condition_name, condition_func in self.escalation_conditions.items():
            try:
                if condition_func(alert):
                    escalation_reasons.append(condition_name)
            except Exception as e:
                logger.warning(f"Error checking escalation condition {condition_name}: {e}")
                
        # Check confidence-based escalation
        if alert.confidence_score and alert.confidence_score > self.auto_escalation_threshold:
            escalation_reasons.append("high_confidence_threat")
            
        # Check threat intelligence-based escalation
        threat_intel = context_data.get("threat_intelligence", {})
        for intel in threat_intel.values():
            if isinstance(intel, dict) and intel.get("reputation") == "malicious":
                escalation_reasons.append("confirmed_malicious_indicator")
                break
                
        escalation_needed = len(escalation_reasons) > 0
        escalation_reason = ", ".join(escalation_reasons) if escalation_reasons else ""
        
        return escalation_needed, escalation_reason
        
    async def _escalate_response(self, alert: SecurityAlert, escalation_reason: str,
                               current_actions: List[ResponseAction], 
                               current_assignment: str) -> Tuple[List[ResponseAction], str]:
        """Escalate response for high-priority alerts"""
        
        self.escalations_performed += 1
        
        # Upgrade assignment
        escalated_assignment = self._get_escalated_assignment(current_assignment, escalation_reason)
        
        # Add escalation-specific actions
        escalation_actions = [
            ResponseAction.ESCALATE,
            ResponseAction.NOTIFY_ANALYST,
            ResponseAction.CREATE_INCIDENT,
            ResponseAction.PRESERVE_EVIDENCE
        ]
        
        # Combine with existing actions
        all_actions = list(current_actions)
        for action in escalation_actions:
            if action not in all_actions:
                all_actions.append(action)
                
        # Update alert status
        alert.status = AlertStatus.ESCALATED
        
        logger.info(f"Escalated alert {alert.alert_id} due to: {escalation_reason}")
        
        return all_actions, escalated_assignment
        
    async def _execute_automated_actions(self, alert: SecurityAlert, context_data: Dict[str, Any],
                                       actions: List[ResponseAction]) -> Dict[str, Any]:
        """Execute automated response actions"""
        
        if not self.enable_automation:
            return {"automation_enabled": False}
            
        automation_results = {
            "actions_executed": [],
            "actions_pending_approval": [],
            "actions_failed": []
        }
        
        # Check each automation rule
        for rule_name, rule_config in self.automation_rules.items():
            try:
                condition_func = rule_config["condition"]
                
                if condition_func(alert, context_data):
                    action_name = rule_config["action"]
                    approval_required = rule_config["approval_required"]
                    
                    if approval_required:
                        automation_results["actions_pending_approval"].append({
                            "rule": rule_name,
                            "action": action_name,
                            "reason": "requires_human_approval"
                        })
                    else:
                        # Execute automated action
                        success = await self._execute_automation_action(action_name, alert, context_data)
                        
                        if success:
                            automation_results["actions_executed"].append({
                                "rule": rule_name,
                                "action": action_name,
                                "timestamp": datetime.datetime.now().isoformat()
                            })
                            self.automated_actions_triggered += 1
                        else:
                            automation_results["actions_failed"].append({
                                "rule": rule_name,
                                "action": action_name,
                                "reason": "execution_failed"
                            })
                            
            except Exception as e:
                logger.error(f"Error executing automation rule {rule_name}: {e}")
                automation_results["actions_failed"].append({
                    "rule": rule_name,
                    "action": "unknown",
                    "reason": f"rule_error: {e}"
                })
                
        return automation_results
        
    async def _execute_automation_action(self, action_name: str, alert: SecurityAlert,
                                       context_data: Dict[str, Any]) -> bool:
        """Execute a specific automation action"""
        
        logger.info(f"Executing automated action: {action_name} for alert {alert.alert_id}")
        
        try:
            if action_name == "block_source_ip":
                return await self._block_ip_address(alert.source_ip)
            elif action_name == "isolate_host":
                return await self._isolate_host(alert.hostname)
            elif action_name == "disable_user_account":
                return await self._disable_user_account(alert.user_id)
            elif action_name == "quarantine_file":
                return await self._quarantine_file(alert.file_path)
            else:
                logger.warning(f"Unknown automation action: {action_name}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to execute automation action {action_name}: {e}")
            return False
            
    async def _create_incident_ticket(self, alert: SecurityAlert, actions: List[ResponseAction],
                                    assignment: str) -> Optional[IncidentTicket]:
        """Create incident ticket in SOAR platform"""
        
        # Only create incidents for certain actions or severities
        create_incident = (
            ResponseAction.CREATE_INCIDENT in actions or
            alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]
        )
        
        if not create_incident:
            return None
            
        self.incidents_created += 1
        
        # Create incident ticket
        ticket = IncidentTicket(
            ticket_id=f"INC-{datetime.datetime.now().strftime('%Y%m%d')}-{self.incidents_created:04d}",
            alert_id=alert.alert_id,
            title=f"Security Alert: {alert.alert_type.value.title()} - {alert.alert_id}",
            description=self._generate_incident_description(alert),
            severity=alert.severity,
            status="open",
            assigned_to=assignment,
            created_time=datetime.datetime.now(),
            soar_platform="phantom"  # Default platform
        )
        
        # In production, this would call SOAR API
        await self._send_to_soar_platform(ticket)
        
        logger.info(f"Created incident ticket {ticket.ticket_id} for alert {alert.alert_id}")
        
        return ticket
        
    def _generate_incident_description(self, alert: SecurityAlert) -> str:
        """Generate incident description from alert data"""
        
        description = f"""
Security Alert Details:
- Alert ID: {alert.alert_id}
- Type: {alert.alert_type.value}
- Severity: {alert.severity.value if alert.severity else 'unknown'}
- Source: {alert.source_system}
- Timestamp: {alert.timestamp.isoformat()}

Description: {alert.description}

Network Information:
- Source IP: {alert.source_ip or 'N/A'}
- Destination IP: {alert.destination_ip or 'N/A'}
- User: {alert.user_id or 'N/A'}
- Host: {alert.hostname or 'N/A'}

Recommended Actions:
{chr(10).join(f"- {action.value}" for action in alert.recommended_actions)}

Confidence Score: {alert.confidence_score or 'N/A'}
""".strip()
        
        return description
        
    def _determine_alert_status(self, actions: List[ResponseAction]) -> AlertStatus:
        """Determine final alert status based on actions"""
        
        if ResponseAction.ESCALATE in actions:
            return AlertStatus.ESCALATED
        elif ResponseAction.AUTO_RESOLVE in actions:
            return AlertStatus.RESOLVED
        else:
            return AlertStatus.IN_PROGRESS
            
    # Helper methods for escalation conditions
    def _is_executive_user(self, user_id: str) -> bool:
        """Check if user is executive/VIP"""
        if not user_id:
            return False
        user_lower = user_id.lower()
        exec_indicators = ["ceo", "cfo", "cto", "vp", "president", "director"]
        return any(indicator in user_lower for indicator in exec_indicators)
        
    def _is_critical_asset(self, hostname: str) -> bool:
        """Check if hostname represents a critical asset"""
        if not hostname:
            return False
        hostname_lower = hostname.lower()
        critical_indicators = ["dc", "domain", "sql", "db", "mail", "web", "dns", "dhcp"]
        return any(indicator in hostname_lower for indicator in critical_indicators)
        
    def _is_active_campaign(self, alert: SecurityAlert) -> bool:
        """Check if alert is part of an active campaign"""
        # In production, this would check campaign tracking database
        return alert.alert_type in [AlertType.MALWARE, AlertType.DATA_EXFILTRATION]
        
    def _is_multi_stage_attack(self, alert: SecurityAlert) -> bool:
        """Check if alert indicates multi-stage attack"""
        multi_stage_types = [
            AlertType.LATERAL_MOVEMENT,
            AlertType.PRIVILEGE_ESCALATION, 
            AlertType.COMMAND_AND_CONTROL
        ]
        return alert.alert_type in multi_stage_types
        
    def _has_external_threat_indicators(self, alert: SecurityAlert) -> bool:
        """Check for external threat indicators"""
        return (alert.source_ip and not alert.source_ip.startswith(("10.", "192.168.", "172.")))
        
    def _get_escalated_assignment(self, current_assignment: str, escalation_reason: str) -> str:
        """Get escalated assignment based on reason"""
        
        escalation_map = {
            "tier1_analyst": "tier2_analyst",
            "tier2_analyst": "senior_analyst",
            "senior_analyst": "incident_commander",
            "automated_system": "tier1_analyst"
        }
        
        # Special escalations
        if "executive_user" in escalation_reason:
            return "senior_analyst"
        elif "critical_asset" in escalation_reason:
            return "incident_commander"
        else:
            return escalation_map.get(current_assignment, "senior_analyst")
            
    # Automation action implementations (mock)
    async def _block_ip_address(self, ip: str) -> bool:
        """Block IP address on firewall"""
        logger.info(f"[AUTOMATION] Blocking IP address: {ip}")
        return True  # Mock success
        
    async def _isolate_host(self, hostname: str) -> bool:
        """Isolate host from network"""
        logger.info(f"[AUTOMATION] Isolating host: {hostname}")
        return True  # Mock success
        
    async def _disable_user_account(self, user_id: str) -> bool:
        """Disable user account"""
        logger.info(f"[AUTOMATION] Disabling user account: {user_id}")
        return True  # Mock success
        
    async def _quarantine_file(self, file_path: str) -> bool:
        """Quarantine malicious file"""
        logger.info(f"[AUTOMATION] Quarantining file: {file_path}")
        return True  # Mock success
        
    async def _send_to_soar_platform(self, ticket: IncidentTicket) -> bool:
        """Send incident ticket to SOAR platform"""
        logger.info(f"[SOAR] Creating incident ticket: {ticket.ticket_id}")
        return True  # Mock success
        
    def _is_ip_address(self, value: str) -> bool:
        """Check if value is an IP address"""
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, value))
        
    # Automation condition helpers
    def _should_block_ip(self, alert: SecurityAlert, context_data: Dict[str, Any]) -> bool:
        """Check if IP should be automatically blocked"""
        if not alert.source_ip or alert.source_ip.startswith(("10.", "192.168.", "172.")):
            return False
            
        threat_intel = context_data.get("threat_intelligence", {})
        ip_intel = threat_intel.get(alert.source_ip, {})
        
        return (isinstance(ip_intel, dict) and 
                ip_intel.get("reputation") == "malicious" and
                ip_intel.get("confidence", 0) > 0.8)
                
    def _should_isolate_host(self, alert: SecurityAlert, context_data: Dict[str, Any]) -> bool:
        """Check if host should be automatically isolated"""
        return (alert.alert_type == AlertType.MALWARE and 
                alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL])
                
    def _should_disable_user(self, alert: SecurityAlert, context_data: Dict[str, Any]) -> bool:
        """Check if user account should be automatically disabled"""
        if not alert.user_id:
            return False
            
        # Only for severe brute force or credential theft
        return (alert.alert_type == AlertType.BRUTE_FORCE and
                alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL])
                
    async def _complete_workflow(self, alert: SecurityAlert, thread_id: str, 
                                response_metadata: Dict[str, Any]):
        """Complete the alert triage workflow"""
        
        completion_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id="workflow_orchestrator",
            message_type=MessageType.WORKFLOW_COMPLETE,
            thread_id=thread_id,
            payload={
                "alert": alert.to_dict(),
                "action": "response_coordinated",
                "response_metadata": response_metadata,
                "completion_timestamp": datetime.datetime.now().isoformat()
            },
            timestamp=datetime.datetime.now()
        )
        
        await self.send_message(completion_message)
        logger.info(f"Completed workflow for alert {alert.alert_id}")
        
    async def _send_coordination_error(self, original_message: CoralMessage, error: str):
        """Send response coordination error"""
        
        error_message = original_message.create_reply(
            sender_id=self.agent_id,
            payload={
                "error": f"Response coordination failed: {error}",
                "original_message_id": original_message.id
            },
            message_type=MessageType.ERROR
        )
        
        await self.send_message(error_message)
        
    def get_agent_metrics(self) -> Dict[str, Any]:
        """Get agent performance metrics"""
        
        return {
            "alerts_processed": self.alerts_processed,
            "incidents_created": self.incidents_created,
            "escalations_performed": self.escalations_performed,
            "automated_actions_triggered": self.automated_actions_triggered,
            "escalation_rate": (
                self.escalations_performed / self.alerts_processed
                if self.alerts_processed > 0 else 0
            ),
            "automation_rate": (
                self.automated_actions_triggered / self.alerts_processed
                if self.alerts_processed > 0 else 0
            ),
            "queue_size": self.message_queue.qsize()
        }