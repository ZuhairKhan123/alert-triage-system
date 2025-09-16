"""
Webhook server for receiving security alerts from external systems
"""

import json
import hmac
import hashlib
import asyncio
import logging
from typing import Dict, Any, Optional
from aiohttp import web, ClientTimeout
from datetime import datetime

from main import AlertTriageSystem
from utils.logging_config import SecurityAuditLogger


logger = logging.getLogger(__name__)


class WebhookReceiver:
    """
    HTTP webhook receiver for security alerts
    
    Supports receiving alerts from:
    - SIEM platforms (Splunk, QRadar, Sentinel)
    - EDR solutions (CrowdStrike, Carbon Black, SentinelOne)
    - Email security (Proofpoint, Mimecast)
    - Custom security tools
    """
    
    def __init__(self, triage_system: AlertTriageSystem, config: Dict[str, Any]):
        self.triage_system = triage_system
        self.config = config
        self.security_logger = SecurityAuditLogger()
        
        # Configuration
        self.webhook_secret = config.get("secret", "")
        self.require_auth = config.get("require_auth", False)
        self.max_payload_size = config.get("max_payload_size", 1048576)  # 1MB
        
        # Rate limiting
        self.rate_limit_enabled = config.get("rate_limiting", {}).get("enabled", True)
        self.requests_per_minute = config.get("rate_limiting", {}).get("requests_per_minute", 1000)
        self.request_counts = {}
        
        # Statistics
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.alerts_processed = 0
        
        # Setup web application
        self.app = web.Application(
            middlewares=[
                self._rate_limiting_middleware,
                self._request_logging_middleware,
                self._error_handling_middleware
            ]
        )
        self._setup_routes()
        
    def _setup_routes(self):
        """Setup webhook routes"""
        
        # Main webhook endpoints
        self.app.router.add_post('/webhook/alert', self._handle_alert_webhook)
        self.app.router.add_post('/webhook/splunk', self._handle_splunk_webhook)
        self.app.router.add_post('/webhook/qradar', self._handle_qradar_webhook)
        self.app.router.add_post('/webhook/sentinel', self._handle_sentinel_webhook)
        self.app.router.add_post('/webhook/edr', self._handle_edr_webhook)
        self.app.router.add_post('/webhook/custom', self._handle_custom_webhook)
        
        # Administrative endpoints
        self.app.router.add_get('/health', self._health_check)
        self.app.router.add_get('/metrics', self._get_metrics)
        self.app.router.add_get('/status', self._get_status)
        
        # CORS support
        self.app.router.add_options('/{path:.*}', self._handle_cors_preflight)
        
    @web.middleware
    async def _rate_limiting_middleware(self, request, handler):
        """Rate limiting middleware"""
        
        if not self.rate_limit_enabled:
            return await handler(request)
            
        client_ip = request.remote
        current_minute = datetime.now().minute
        
        # Initialize or reset counter for this IP
        if client_ip not in self.request_counts:
            self.request_counts[client_ip] = {"minute": current_minute, "count": 0}
        elif self.request_counts[client_ip]["minute"] != current_minute:
            self.request_counts[client_ip] = {"minute": current_minute, "count": 0}
            
        # Check rate limit
        self.request_counts[client_ip]["count"] += 1
        
        if self.request_counts[client_ip]["count"] > self.requests_per_minute:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return web.Response(
                status=429,
                text="Rate limit exceeded",
                headers={"Retry-After": "60"}
            )
            
        return await handler(request)
        
    @web.middleware
    async def _request_logging_middleware(self, request, handler):
        """Request logging middleware"""
        
        start_time = datetime.now()
        self.total_requests += 1
        
        try:
            response = await handler(request)
            
            # Log successful request
            duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"Request: {request.method} {request.path} - "
                       f"Status: {response.status} - Duration: {duration:.3f}s")
            
            if response.status < 400:
                self.successful_requests += 1
            else:
                self.failed_requests += 1
                
            return response
            
        except Exception as e:
            # Log failed request
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(f"Request failed: {request.method} {request.path} - "
                        f"Error: {e} - Duration: {duration:.3f}s")
            
            self.failed_requests += 1
            raise
            
    @web.middleware
    async def _error_handling_middleware(self, request, handler):
        """Global error handling middleware"""
        
        try:
            return await handler(request)
        except web.HTTPException:
            raise  # Re-raise HTTP exceptions
        except Exception as e:
            logger.error(f"Unhandled error in webhook handler: {e}")
            
            # Log security event for unexpected errors
            self.security_logger.log_system_event(
                "webhook_error",
                {
                    "path": request.path,
                    "method": request.method,
                    "client_ip": request.remote,
                    "error": str(e)
                }
            )
            
            return web.Response(
                status=500,
                text="Internal server error",
                content_type="text/plain"
            )
            
    async def _handle_alert_webhook(self, request):
        """Handle generic security alert webhook"""
        
        try:
            # Validate request
            await self._validate_request(request)
            
            # Parse alert data
            alert_data = await self._parse_request_data(request)
            
            # Normalize alert format
            normalized_alert = await self._normalize_generic_alert(alert_data)
            
            # Submit to triage system
            workflow_id = await self.triage_system.process_alert(normalized_alert)
            
            self.alerts_processed += 1
            
            return web.json_response({
                "status": "accepted",
                "workflow_id": workflow_id,
                "message": "Alert submitted for processing"
            })
            
        except ValueError as e:
            return web.Response(status=400, text=f"Bad request: {e}")
        except Exception as e:
            logger.error(f"Error processing generic alert webhook: {e}")
            return web.Response(status=500, text="Internal server error")
            
    async def _handle_splunk_webhook(self, request):
        """Handle Splunk-specific webhook format"""
        
        try:
            await self._validate_request(request)
            raw_data = await self._parse_request_data(request)
            
            # Splunk sends alerts in specific format
            splunk_alert = raw_data.get("result", {})
            
            normalized_alert = {
                "alert_id": splunk_alert.get("sid", f"splunk_{datetime.now().strftime('%Y%m%d_%H%M%S')}"),
                "timestamp": splunk_alert.get("_time", datetime.now().isoformat()),
                "source_system": "splunk",
                "type": self._map_splunk_alert_type(splunk_alert.get("search_name", "")),
                "description": splunk_alert.get("search_name", "Splunk Alert"),
                "source_ip": splunk_alert.get("src_ip"),
                "destination_ip": splunk_alert.get("dest_ip"),
                "user_id": splunk_alert.get("user"),
                "hostname": splunk_alert.get("host"),
                "raw_data": raw_data
            }
            
            workflow_id = await self.triage_system.process_alert(normalized_alert)
            self.alerts_processed += 1
            
            return web.json_response({
                "status": "accepted",
                "workflow_id": workflow_id
            })
            
        except Exception as e:
            logger.error(f"Error processing Splunk webhook: {e}")
            return web.Response(status=500, text="Internal server error")
            
    async def _handle_qradar_webhook(self, request):
        """Handle QRadar-specific webhook format"""
        
        try:
            await self._validate_request(request)
            raw_data = await self._parse_request_data(request)
            
            # QRadar offense format
            offense = raw_data.get("offense", {})
            
            normalized_alert = {
                "alert_id": f"qradar_{offense.get('id', 'unknown')}",
                "timestamp": datetime.fromtimestamp(
                    offense.get("start_time", 0) / 1000
                ).isoformat() if offense.get("start_time") else datetime.now().isoformat(),
                "source_system": "qradar",
                "type": self._map_qradar_offense_type(offense.get("offense_type", 0)),
                "description": offense.get("description", "QRadar Offense"),
                "source_ip": self._extract_qradar_source_ip(offense),
                "user_id": self._extract_qradar_username(offense),
                "raw_data": raw_data
            }
            
            workflow_id = await self.triage_system.process_alert(normalized_alert)
            self.alerts_processed += 1
            
            return web.json_response({
                "status": "accepted",
                "workflow_id": workflow_id
            })
            
        except Exception as e:
            logger.error(f"Error processing QRadar webhook: {e}")
            return web.Response(status=500, text="Internal server error")
            
    async def _handle_sentinel_webhook(self, request):
        """Handle Microsoft Sentinel webhook format"""
        
        try:
            await self._validate_request(request)
            raw_data = await self._parse_request_data(request)
            
            # Sentinel incident format
            incident = raw_data.get("object", {}).get("properties", {})
            
            normalized_alert = {
                "alert_id": f"sentinel_{incident.get('incidentNumber', 'unknown')}",
                "timestamp": incident.get("createdTimeUtc", datetime.now().isoformat()),
                "source_system": "sentinel",
                "type": self._map_sentinel_alert_type(incident.get("title", "")),
                "description": incident.get("description", incident.get("title", "Sentinel Incident")),
                "severity": incident.get("severity", "medium").lower(),
                "raw_data": raw_data
            }
            
            workflow_id = await self.triage_system.process_alert(normalized_alert)
            self.alerts_processed += 1
            
            return web.json_response({
                "status": "accepted",
                "workflow_id": workflow_id
            })
            
        except Exception as e:
            logger.error(f"Error processing Sentinel webhook: {e}")
            return web.Response(status=500, text="Internal server error")
            
    async def _handle_edr_webhook(self, request):
        """Handle EDR (CrowdStrike, Carbon Black, etc.) webhook format"""
        
        try:
            await self._validate_request(request)
            raw_data = await self._parse_request_data(request)
            
            # Generic EDR alert format
            edr_alert = raw_data.get("alert", raw_data)
            
            normalized_alert = {
                "alert_id": edr_alert.get("id", f"edr_{datetime.now().strftime('%Y%m%d_%H%M%S')}"),
                "timestamp": edr_alert.get("timestamp", datetime.now().isoformat()),
                "source_system": "edr",
                "type": self._map_edr_alert_type(edr_alert.get("type", "")),
                "description": edr_alert.get("description", "EDR Alert"),
                "hostname": edr_alert.get("hostname", edr_alert.get("device_name")),
                "process_name": edr_alert.get("process_name"),
                "file_path": edr_alert.get("file_path"),
                "file_hash": edr_alert.get("file_hash", edr_alert.get("sha256")),
                "user_id": edr_alert.get("username"),
                "raw_data": raw_data
            }
            
            workflow_id = await self.triage_system.process_alert(normalized_alert)
            self.alerts_processed += 1
            
            return web.json_response({
                "status": "accepted",
                "workflow_id": workflow_id
            })
            
        except Exception as e:
            logger.error(f"Error processing EDR webhook: {e}")
            return web.Response(status=500, text="Internal server error")
            
    async def _handle_custom_webhook(self, request):
        """Handle custom webhook format"""
        
        try:
            await self._validate_request(request)
            alert_data = await self._parse_request_data(request)
            
            # Custom alerts should already be in the correct format
            # but we'll add some defaults
            if "source_system" not in alert_data:
                alert_data["source_system"] = "custom"
            if "timestamp" not in alert_data:
                alert_data["timestamp"] = datetime.now().isoformat()
                
            workflow_id = await self.triage_system.process_alert(alert_data)
            self.alerts_processed += 1
            
            return web.json_response({
                "status": "accepted",
                "workflow_id": workflow_id
            })
            
        except Exception as e:
            logger.error(f"Error processing custom webhook: {e}")
            return web.Response(status=500, text="Internal server error")
            
    async def _validate_request(self, request):
        """Validate incoming webhook request"""
        
        # Check content type
        if request.content_type not in ["application/json", "application/x-www-form-urlencoded"]:
            raise ValueError(f"Unsupported content type: {request.content_type}")
            
        # Check payload size
        content_length = request.headers.get("Content-Length")
        if content_length and int(content_length) > self.max_payload_size:
            raise ValueError(f"Payload too large: {content_length} bytes")
            
        # Validate webhook signature if secret is configured
        if self.webhook_secret:
            await self._validate_webhook_signature(request)
            
    async def _validate_webhook_signature(self, request):
        """Validate HMAC signature for webhook security"""
        
        signature_header = request.headers.get("X-Webhook-Signature", "")
        if not signature_header:
            raise ValueError("Missing webhook signature")
            
        # Read body for signature verification
        body = await request.read()
        
        # Calculate expected signature
        expected_signature = hmac.new(
            self.webhook_secret.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        
        # Compare signatures
        if not hmac.compare_digest(f"sha256={expected_signature}", signature_header):
            self.security_logger.log_security_violation(
                "webhook_signature_validation",
                "webhook_receiver",
                {
                    "client_ip": request.remote,
                    "path": request.path,
                    "provided_signature": signature_header
                }
            )
            raise ValueError("Invalid webhook signature")
            
    async def _parse_request_data(self, request) -> Dict[str, Any]:
        """Parse request data based on content type"""
        
        if request.content_type == "application/json":
            try:
                return await request.json()
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON: {e}")
        elif request.content_type == "application/x-www-form-urlencoded":
            form_data = await request.post()
            return dict(form_data)
        else:
            raise ValueError(f"Unsupported content type: {request.content_type}")
            
    async def _normalize_generic_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize generic alert data to standard format"""
        
        normalized = {
            "alert_id": alert_data.get("id", alert_data.get("alert_id", f"webhook_{datetime.now().strftime('%Y%m%d_%H%M%S')}")),
            "timestamp": alert_data.get("timestamp", alert_data.get("time", datetime.now().isoformat())),
            "source_system": alert_data.get("source", alert_data.get("source_system", "webhook")),
            "type": alert_data.get("type", alert_data.get("alert_type", "unknown")),
            "description": alert_data.get("description", alert_data.get("message", "Webhook Alert")),
            "source_ip": alert_data.get("source_ip", alert_data.get("src_ip")),
            "destination_ip": alert_data.get("destination_ip", alert_data.get("dst_ip", alert_data.get("dest_ip"))),
            "user_id": alert_data.get("user_id", alert_data.get("user", alert_data.get("username"))),
            "hostname": alert_data.get("hostname", alert_data.get("host")),
            "raw_data": alert_data
        }
        
        # Remove None values
        return {k: v for k, v in normalized.items() if v is not None}
        
    # Alert type mapping functions
    def _map_splunk_alert_type(self, search_name: str) -> str:
        """Map Splunk search name to alert type"""
        search_lower = search_name.lower()
        
        if "brute" in search_lower or "failed_login" in search_lower:
            return "brute_force"
        elif "malware" in search_lower or "virus" in search_lower:
            return "malware"
        elif "data_loss" in search_lower or "exfil" in search_lower:
            return "data_exfiltration"
        elif "phish" in search_lower:
            return "phishing"
        else:
            return "unknown"
            
    def _map_qradar_offense_type(self, offense_type: int) -> str:
        """Map QRadar offense type ID to alert type"""
        # QRadar offense type mappings (simplified)
        type_map = {
            1: "suspicious_login",
            2: "brute_force", 
            3: "malware",
            4: "network_anomaly",
            5: "data_exfiltration"
        }
        return type_map.get(offense_type, "unknown")
        
    def _map_sentinel_alert_type(self, title: str) -> str:
        """Map Sentinel incident title to alert type"""
        title_lower = title.lower()
        
        if "brute force" in title_lower:
            return "brute_force"
        elif "malware" in title_lower:
            return "malware"
        elif "phishing" in title_lower:
            return "phishing"
        elif "suspicious sign-in" in title_lower or "anomalous login" in title_lower:
            return "suspicious_login"
        else:
            return "unknown"
            
    def _map_edr_alert_type(self, alert_type: str) -> str:
        """Map EDR alert type to standard type"""
        type_lower = alert_type.lower()
        
        if "malware" in type_lower or "virus" in type_lower:
            return "malware"
        elif "suspicious_process" in type_lower:
            return "suspicious_login"
        elif "network" in type_lower:
            return "network_anomaly"
        else:
            return "unknown"
            
    def _extract_qradar_source_ip(self, offense: Dict[str, Any]) -> Optional[str]:
        """Extract source IP from QRadar offense data"""
        source_addresses = offense.get("source_address_ids", [])
        if source_addresses:
            # In real implementation, you'd look up the address ID
            return f"10.0.0.{source_addresses[0]}"  # Simplified
        return None
        
    def _extract_qradar_username(self, offense: Dict[str, Any]) -> Optional[str]:
        """Extract username from QRadar offense data"""
        # Simplified extraction from offense data
        return offense.get("username")
        
    async def _health_check(self, request):
        """Health check endpoint"""
        
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "system_status": "operational",
            "triage_system_healthy": True
        }
        
        try:
            # Check triage system health
            triage_health = await self.triage_system.health_check()
            health_status["triage_system_healthy"] = triage_health["status"] == "healthy"
            
            if not health_status["triage_system_healthy"]:
                health_status["status"] = "degraded"
                health_status["issues"] = triage_health.get("issues", [])
                
        except Exception as e:
            health_status["status"] = "unhealthy"
            health_status["error"] = str(e)
            
        status_code = 200 if health_status["status"] == "healthy" else 503
        return web.json_response(health_status, status=status_code)
        
    async def _get_metrics(self, request):
        """Get webhook receiver metrics"""
        
        metrics = {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "alerts_processed": self.alerts_processed,
            "success_rate": (
                self.successful_requests / self.total_requests
                if self.total_requests > 0 else 0
            ),
            "processing_rate": (
                self.alerts_processed / self.total_requests
                if self.total_requests > 0 else 0
            )
        }
        
        return web.json_response(metrics)
        
    async def _get_status(self, request):
        """Get system status information"""
        
        status = {
            "service": "Alert Triage Webhook Receiver",
            "version": "1.0.0",
            "uptime": "unknown",  # Would calculate actual uptime
            "configuration": {
                "webhook_secret_configured": bool(self.webhook_secret),
                "auth_required": self.require_auth,
                "rate_limiting_enabled": self.rate_limit_enabled,
                "max_payload_size": self.max_payload_size
            },
            "endpoints": [
                "/webhook/alert",
                "/webhook/splunk", 
                "/webhook/qradar",
                "/webhook/sentinel",
                "/webhook/edr",
                "/webhook/custom"
            ]
        }
        
        return web.json_response(status)
        
    async def _handle_cors_preflight(self, request):
        """Handle CORS preflight requests"""
        
        return web.Response(
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, X-Webhook-Signature, Authorization",
                "Access-Control-Max-Age": "86400"
            }
        )
        
    async def start_server(self, host: str = "0.0.0.0", port: int = 8080):
        """Start the webhook server"""
        
        runner = web.AppRunner(self.app)
        await runner.setup()
        
        site = web.TCPSite(runner, host, port)
        await site.start()
        
        logger.info(f"Webhook server started on {host}:{port}")
        
        # Log available endpoints
        logger.info("Available webhook endpoints:")
        for route in self.app.router.routes():
            if route.method == "POST":
                logger.info(f"  POST {route.resource.canonical}")