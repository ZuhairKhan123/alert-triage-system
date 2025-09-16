"""
Context Gatherer Agent - Enriches alerts with additional context and threat intelligence
"""

import datetime
import uuid
import logging
import asyncio
from typing import Dict, Any, List, Optional

from coral_protocol import CoralAgent, AgentCapability, CoralMessage, MessageType
from models.alert_models import (
    SecurityAlert, ThreatIntelligence, UserContext, NetworkContext,
    AlertType, AlertSeverity
)


logger = logging.getLogger(__name__)


class ContextGathererAgent(CoralAgent):
    """
    Agent that gathers additional context and threat intelligence for alerts
    
    This agent:
    1. Queries threat intelligence sources
    2. Gathers user context information
    3. Analyzes network context
    4. Enriches alerts with historical pattern data
    5. Routes enriched alerts to response coordination
    """
    
    def __init__(self):
        capabilities = [
            AgentCapability(
                name="gather_context",
                description="Gather comprehensive context including threat intel, user info, and network data",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "context_types": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["alert"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "enriched_alert": {"type": "object"},
                        "context_data": {"type": "object"},
                        "confidence": {"type": "number"}
                    }
                }
            ),
            AgentCapability(
                name="query_threat_intelligence",
                description="Query external threat intelligence sources for indicators",
                input_schema={
                    "type": "object",
                    "properties": {
                        "indicators": {"type": "array"},
                        "indicator_types": {"type": "array"}
                    }
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "threat_intelligence": {"type": "object"},
                        "enrichment_status": {"type": "string"}
                    }
                }
            )
        ]
        
        super().__init__(
            agent_id="context_gatherer",
            name="Context Gatherer",
            capabilities=capabilities
        )
        
        # Initialize context sources
        self._initialize_context_sources()
        
        # Statistics
        self.alerts_enriched = 0
        self.threat_intel_queries = 0
        self.user_context_queries = 0
        self.network_context_queries = 0
        
        # Configuration
        self.enable_threat_intel = True
        self.enable_user_context = True
        self.enable_network_context = True
        self.enable_historical_analysis = True
        self.context_timeout = 30  # seconds
        
    def _initialize_context_sources(self):
        """Initialize mock context sources and databases"""
        
        # Mock threat intelligence database
        self.threat_intel_db = {
            "203.0.113.45": ThreatIntelligence(
                indicator="203.0.113.45",
                indicator_type="ip",
                reputation="malicious",
                confidence=0.9,
                sources=["VirusTotal", "MISP"],
                tags=["botnet", "scanning"],
                campaigns=["APT29"],
                malware_families=["TrickBot"]
            ),
            "198.51.100.42": ThreatIntelligence(
                indicator="198.51.100.42", 
                indicator_type="ip",
                reputation="suspicious",
                confidence=0.7,
                sources=["VirusTotal"],
                tags=["proxy", "tor"],
                campaigns=[],
                malware_families=[]
            ),
            "malware_hash_example": ThreatIntelligence(
                indicator="malware_hash_example",
                indicator_type="hash",
                reputation="malicious",
                confidence=0.95,
                sources=["VirusTotal", "Hybrid Analysis"],
                tags=["trojan", "backdoor"],
                campaigns=["Lazarus"],
                malware_families=["Ryuk"]
            )
        }
        
        # Mock user directory
        self.user_directory = {
            "admin_user": UserContext(
                user_id="admin_user",
                username="admin_user",
                department="IT",
                title="System Administrator",
                privilege_level="admin",
                last_login=datetime.datetime.now() - datetime.timedelta(hours=2),
                login_count_24h=5,
                failed_login_count_24h=0,
                recent_activities=["server_maintenance", "user_provisioning"]
            ),
            "finance_user": UserContext(
                user_id="finance_user",
                username="jane.doe",
                department="Finance",
                title="Financial Analyst",
                privilege_level="standard",
                last_login=datetime.datetime.now() - datetime.timedelta(hours=1),
                login_count_24h=3,
                failed_login_count_24h=0,
                recent_activities=["excel_access", "database_query"]
            ),
            "test_user": UserContext(
                user_id="test_user",
                username="test_account",
                department="QA",
                title="Test Account",
                privilege_level="standard",
                last_login=datetime.datetime.now() - datetime.timedelta(hours=6),
                login_count_24h=1,
                failed_login_count_24h=0,
                is_service_account=True,
                recent_activities=["automated_testing", "application_scan"]
            )
        }
        
        # Mock network topology data
        self.network_topology = {
            "10.0.0.0/8": {"segment": "internal", "criticality": "medium"},
            "192.168.1.0/24": {"segment": "dmz", "criticality": "high"},
            "172.16.0.0/12": {"segment": "isolated", "criticality": "critical"}
        }
        
        # Historical pattern cache (simplified)
        self.historical_patterns = {}
        
    async def handle_message(self, message: CoralMessage):
        """Handle incoming messages"""
        if message.message_type == MessageType.CONTEXT_GATHERING:
            await self._gather_context(message)
        else:
            logger.warning(f"Unexpected message type: {message.message_type}")
            
    async def _gather_context(self, message: CoralMessage):
        """Gather comprehensive context for the alert"""
        
        try:
            self.alerts_enriched += 1
            
            # Extract alert from message
            alert_data = message.payload["alert"]
            alert = SecurityAlert.from_dict(alert_data)
            
            logger.info(f"Gathering context for alert: {alert.alert_id}")
            
            # Gather context from multiple sources concurrently
            context_tasks = []
            
            if self.enable_threat_intel:
                context_tasks.append(self._gather_threat_intelligence(alert))
                
            if self.enable_user_context and alert.user_id:
                context_tasks.append(self._gather_user_context(alert))
                
            if self.enable_network_context:
                context_tasks.append(self._gather_network_context(alert))
                
            if self.enable_historical_analysis:
                context_tasks.append(self._analyze_historical_patterns(alert))
                
            # Execute all context gathering tasks concurrently with timeout
            context_results = await asyncio.wait_for(
                asyncio.gather(*context_tasks, return_exceptions=True),
                timeout=self.context_timeout
            )
            
            # Compile context data
            context_data = await self._compile_context_data(context_results, alert)
            
            # Update alert with context
            alert.context_data = context_data
            
            # Forward to response coordinator
            await self._forward_to_response_coordination(alert, message.thread_id, context_data)
            
            logger.info(f"Context gathering complete for alert {alert.alert_id}")
            
        except asyncio.TimeoutError:
            logger.warning(f"Context gathering timed out for alert")
            await self._handle_timeout(message)
        except Exception as e:
            logger.error(f"Error gathering context: {e}")
            await self._send_context_error(message, str(e))
            
    async def _gather_threat_intelligence(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Gather threat intelligence for alert indicators"""
        
        self.threat_intel_queries += 1
        threat_intel = {}
        
        # Gather intel for IP addresses
        for ip_field in ['source_ip', 'destination_ip']:
            ip = getattr(alert, ip_field)
            if ip and not self._is_internal_ip(ip):
                intel = await self._query_threat_intel_ip(ip)
                if intel:
                    threat_intel[ip] = intel
                    
        # Gather intel for file hashes
        if alert.file_hash:
            intel = await self._query_threat_intel_hash(alert.file_hash)
            if intel:
                threat_intel[alert.file_hash] = intel
                
        # Gather intel for domains (if present in description or raw data)
        domains = self._extract_domains(alert)
        for domain in domains:
            intel = await self._query_threat_intel_domain(domain)
            if intel:
                threat_intel[domain] = intel
                
        return {
            "threat_intelligence": threat_intel,
            "query_count": len(threat_intel),
            "sources_queried": ["internal_db", "virustotal", "misp"],
            "query_timestamp": datetime.datetime.now().isoformat()
        }
        
    async def _gather_user_context(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Gather user context information"""
        
        self.user_context_queries += 1
        
        user_context = await self._query_user_directory(alert.user_id)
        
        # Additional user behavior analysis
        behavior_analysis = await self._analyze_user_behavior(alert.user_id, alert)
        
        return {
            "user_context": user_context.to_dict() if user_context else None,
            "behavior_analysis": behavior_analysis,
            "query_timestamp": datetime.datetime.now().isoformat()
        }
        
    async def _gather_network_context(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Gather network context information"""
        
        self.network_context_queries += 1
        
        # Analyze source network
        source_context = None
        if alert.source_ip:
            source_context = await self._analyze_network_location(alert.source_ip)
            
        # Analyze destination network  
        dest_context = None
        if alert.destination_ip:
            dest_context = await self._analyze_network_location(alert.destination_ip)
            
        # Network flow analysis
        flow_analysis = await self._analyze_network_flows(alert)
        
        # Geolocation analysis
        geo_context = await self._gather_geolocation_context(alert)
        
        return {
            "source_network": source_context,
            "destination_network": dest_context,
            "flow_analysis": flow_analysis,
            "geolocation": geo_context,
            "query_timestamp": datetime.datetime.now().isoformat()
        }
        
    async def _analyze_historical_patterns(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Analyze historical patterns for similar alerts"""
        
        # Find similar alerts in the past
        similar_alerts = await self._find_similar_alerts(alert)
        
        # Analyze trends
        trend_analysis = await self._analyze_alert_trends(alert)
        
        # Check for campaign patterns
        campaign_analysis = await self._analyze_campaign_patterns(alert)
        
        return {
            "similar_alerts": similar_alerts,
            "trend_analysis": trend_analysis,
            "campaign_analysis": campaign_analysis,
            "analysis_timestamp": datetime.datetime.now().isoformat()
        }
        
    async def _query_threat_intel_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query threat intelligence for IP address"""
        
        # Check local database first
        if ip in self.threat_intel_db:
            intel = self.threat_intel_db[ip]
            return {
                "reputation": intel.reputation,
                "confidence": intel.confidence,
                "sources": intel.sources,
                "tags": intel.tags,
                "campaigns": intel.campaigns,
                "malware_families": intel.malware_families,
                "last_seen": intel.last_seen.isoformat() if intel.last_seen else None
            }
            
        # In production, query external APIs here
        # - VirusTotal
        # - MISP
        # - OTX
        # - Commercial threat intel feeds
        
        return None
        
    async def _query_threat_intel_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query threat intelligence for file hash"""
        
        if file_hash in self.threat_intel_db:
            intel = self.threat_intel_db[file_hash]
            return {
                "reputation": intel.reputation,
                "confidence": intel.confidence,
                "sources": intel.sources,
                "malware_families": intel.malware_families,
                "tags": intel.tags
            }
            
        return None
        
    async def _query_threat_intel_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Query threat intelligence for domain"""
        
        # Simplified domain analysis
        suspicious_domains = ["malicious.example", "phishing.test", "bad.domain"]
        
        if domain in suspicious_domains:
            return {
                "reputation": "malicious",
                "confidence": 0.8,
                "sources": ["internal_analysis"],
                "tags": ["phishing", "malware_hosting"]
            }
            
        return None
        
    async def _query_user_directory(self, user_id: str) -> Optional[UserContext]:
        """Query user directory for user information"""
        
        return self.user_directory.get(user_id)
        
    async def _analyze_user_behavior(self, user_id: str, alert: SecurityAlert) -> Dict[str, Any]:
        """Analyze user behavior patterns"""
        
        # Simplified behavior analysis
        analysis = {
            "normal_login_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
            "typical_locations": ["office", "home"],
            "usual_systems": ["workstation", "email", "file_server"],
            "risk_factors": []
        }
        
        # Check for unusual activity timing
        current_hour = alert.timestamp.hour
        if current_hour not in analysis["normal_login_hours"]:
            analysis["risk_factors"].append("activity_outside_normal_hours")
            
        # Check for unusual login patterns
        if alert.alert_type in [AlertType.SUSPICIOUS_LOGIN, AlertType.BRUTE_FORCE]:
            analysis["risk_factors"].append("suspicious_authentication_activity")
            
        return analysis
        
    async def _analyze_network_location(self, ip: str) -> Dict[str, Any]:
        """Analyze network location and context"""
        
        context = {
            "is_internal": self._is_internal_ip(ip),
            "network_segment": "unknown",
            "criticality": "medium"
        }
        
        # Determine network segment
        for network, info in self.network_topology.items():
            if self._ip_in_network(ip, network):
                context.update(info)
                break
                
        return context
        
    async def _analyze_network_flows(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Analyze network flow patterns"""
        
        # Simplified flow analysis
        analysis = {
            "connection_type": "unknown",
            "data_volume": 0,
            "duration": 0,
            "protocol_analysis": {}
        }
        
        if alert.source_ip and alert.destination_ip:
            # Determine connection direction
            if self._is_internal_ip(alert.source_ip) and not self._is_internal_ip(alert.destination_ip):
                analysis["connection_type"] = "outbound"
            elif not self._is_internal_ip(alert.source_ip) and self._is_internal_ip(alert.destination_ip):
                analysis["connection_type"] = "inbound"
            else:
                analysis["connection_type"] = "internal"
                
        # Extract data volume if available
        if alert.raw_data and "data_volume" in alert.raw_data:
            analysis["data_volume"] = alert.raw_data["data_volume"]
            
        return analysis
        
    async def _gather_geolocation_context(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Gather geolocation context for IP addresses"""
        
        geo_context = {}
        
        # Mock geolocation data
        geo_db = {
            "203.0.113.45": {"country": "RU", "city": "Moscow", "asn": "AS12345"},
            "198.51.100.42": {"country": "CN", "city": "Beijing", "asn": "AS67890"}
        }
        
        for ip_field in ['source_ip', 'destination_ip']:
            ip = getattr(alert, ip_field)
            if ip and not self._is_internal_ip(ip):
                geo_info = geo_db.get(ip, {"country": "unknown", "city": "unknown"})
                geo_context[ip] = geo_info
                
        return geo_context
        
    async def _find_similar_alerts(self, alert: SecurityAlert) -> List[Dict[str, Any]]:
        """Find similar historical alerts"""
        
        # Simplified similarity matching
        similar_alerts = []
        
        # In production, this would query a database
        # For demo, return mock similar alerts
        if alert.alert_type == AlertType.BRUTE_FORCE:
            similar_alerts = [
                {
                    "alert_id": "ALT-2024-HIST-001",
                    "timestamp": (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat(),
                    "similarity_score": 0.8,
                    "outcome": "false_positive"
                },
                {
                    "alert_id": "ALT-2024-HIST-002", 
                    "timestamp": (datetime.datetime.now() - datetime.timedelta(days=3)).isoformat(),
                    "similarity_score": 0.7,
                    "outcome": "escalated"
                }
            ]
            
        return similar_alerts
        
    async def _analyze_alert_trends(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Analyze trends for this type of alert"""
        
        # Mock trend analysis
        return {
            "alert_frequency_24h": 5,
            "alert_frequency_7d": 23,
            "trend": "increasing",
            "seasonal_pattern": "weekday_peaks",
            "similar_source_count": 3
        }
        
    async def _analyze_campaign_patterns(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Analyze potential campaign patterns"""
        
        # Mock campaign analysis
        campaign_indicators = []
        
        if alert.source_ip and alert.source_ip.startswith("203.0.113."):
            campaign_indicators.append({
                "campaign_name": "APT29_Infrastructure",
                "confidence": 0.7,
                "indicators": ["ip_range", "timing_pattern"]
            })
            
        return {
            "potential_campaigns": campaign_indicators,
            "ttp_mapping": ["T1078", "T1190"],  # MITRE ATT&CK techniques
            "threat_actor_attribution": "medium_confidence"
        }
        
    async def _compile_context_data(self, context_results: List[Any], 
                                  alert: SecurityAlert) -> Dict[str, Any]:
        """Compile all context data into a unified structure"""
        
        compiled_context = {
            "enrichment_timestamp": datetime.datetime.now().isoformat(),
            "enrichment_version": "1.0",
            "confidence_score": 0.0
        }
        
        # Process each context result
        confidence_scores = []
        
        for i, result in enumerate(context_results):
            if isinstance(result, Exception):
                logger.warning(f"Context gathering task {i} failed: {result}")
                continue
                
            if isinstance(result, dict):
                # Merge context data
                for key, value in result.items():
                    compiled_context[key] = value
                    
                # Calculate confidence contribution
                if "confidence" in result:
                    confidence_scores.append(result["confidence"])
                else:
                    confidence_scores.append(0.7)  # Default confidence
                    
        # Calculate overall enrichment confidence
        if confidence_scores:
            compiled_context["confidence_score"] = sum(confidence_scores) / len(confidence_scores)
        else:
            compiled_context["confidence_score"] = 0.5
            
        return compiled_context
        
    def _extract_domains(self, alert: SecurityAlert) -> List[str]:
        """Extract domain names from alert data"""
        
        import re
        domains = []
        
        # Simple domain extraction from description
        if alert.description:
            domain_pattern = r'\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b'
            domains.extend(re.findall(domain_pattern, alert.description))
            
        return domains
        
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal"""
        return ip.startswith(("10.", "192.168.", "172."))
        
    def _ip_in_network(self, ip: str, network: str) -> bool:
        """Check if IP is in network range (simplified)"""
        # Simplified CIDR matching
        if "/" in network:
            network_base = network.split("/")[0]
            return ip.startswith(network_base.rsplit(".", 1)[0])
        return False
        
    async def _handle_timeout(self, message: CoralMessage):
        """Handle context gathering timeout"""
        
        # Extract alert and forward with partial context
        alert_data = message.payload["alert"]
        alert = SecurityAlert.from_dict(alert_data)
        
        # Set minimal context
        alert.context_data = {
            "enrichment_status": "partial",
            "timeout_occurred": True,
            "enrichment_timestamp": datetime.datetime.now().isoformat()
        }
        
        await self._forward_to_response_coordination(alert, message.thread_id, alert.context_data)
        
    async def _forward_to_response_coordination(self, alert: SecurityAlert, thread_id: str,
                                             context_data: Dict[str, Any]):
        """Forward enriched alert to response coordinator"""
        
        next_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id="response_coordinator",
            message_type=MessageType.RESPONSE_DECISION,
            thread_id=thread_id,
            payload={
                "alert": alert.to_dict(),
                "context_enrichment": {
                    "enrichment_complete": True,
                    "enrichment_timestamp": datetime.datetime.now().isoformat(),
                    "context_sources": ["threat_intel", "user_directory", "network_analysis", "historical_data"]
                }
            },
            timestamp=datetime.datetime.now()
        )
        
        await self.send_message(next_message)
        logger.debug(f"Forwarded enriched alert {alert.alert_id} to response coordinator")
        
    async def _send_context_error(self, original_message: CoralMessage, error: str):
        """Send context gathering error response"""
        
        error_message = original_message.create_reply(
            sender_id=self.agent_id,
            payload={
                "error": f"Context gathering failed: {error}",
                "original_message_id": original_message.id
            },
            message_type=MessageType.ERROR
        )
        
        await self.send_message(error_message)
        
    def get_agent_metrics(self) -> Dict[str, Any]:
        """Get agent performance metrics"""
        
        return {
            "alerts_enriched": self.alerts_enriched,
            "threat_intel_queries": self.threat_intel_queries,
            "user_context_queries": self.user_context_queries,
            "network_context_queries": self.network_context_queries,
            "average_enrichment_time": 0.0,  # Would calculate from stored data
            "enrichment_success_rate": 0.95,  # Would calculate from stored data
            "queue_size": self.message_queue.qsize()
        }