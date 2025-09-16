"""
Metrics collection and monitoring utilities
"""

import time
import datetime
import asyncio
from typing import Dict, Any, List
from dataclasses import dataclass, field
from collections import defaultdict, deque
import logging

# Prometheus metrics (optional import)
try:
    from prometheus_client import Counter, Histogram, Gauge, start_http_server, CollectorRegistry
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    Counter = Histogram = Gauge = None

logger = logging.getLogger(__name__)


@dataclass
class MetricPoint:
    """Individual metric data point"""
    timestamp: datetime.datetime
    value: float
    labels: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """
    Comprehensive metrics collection for the Alert Triage System
    
    Collects performance, operational, and business metrics for monitoring
    and analysis purposes.
    """
    
    def __init__(self, enable_prometheus: bool = True):
        self.enable_prometheus = enable_prometheus and PROMETHEUS_AVAILABLE
        self.start_time = datetime.datetime.now()
        
        # In-memory metrics storage
        self.metrics_data = defaultdict(list)
        self.counters = defaultdict(int)
        self.gauges = defaultdict(float)
        self.histograms = defaultdict(lambda: deque(maxlen=1000))
        
        # Prometheus metrics (if available)
        if self.enable_prometheus:
            self._setup_prometheus_metrics()
            
        logger.info(f"Metrics collector initialized (Prometheus: {self.enable_prometheus})")
        
    def _setup_prometheus_metrics(self):
        """Setup Prometheus metrics"""
        
        if not PROMETHEUS_AVAILABLE:
            return
            
        # Alert processing metrics
        self.prom_alerts_total = Counter(
            'alerts_processed_total',
            'Total number of alerts processed',
            ['source_system', 'alert_type', 'status']
        )
        
        self.prom_alert_processing_time = Histogram(
            'alert_processing_seconds',
            'Time spent processing alerts',
            ['agent_id', 'operation']
        )
        
        self.prom_false_positives_total = Counter(
            'false_positives_detected_total',
            'Total number of false positives detected',
            ['alert_type', 'detection_method']
        )
        
        # Agent metrics
        self.prom_agent_queue_size = Gauge(
            'agent_queue_size',
            'Current agent message queue size',
            ['agent_id']
        )
        
        self.prom_messages_routed_total = Counter(
            'messages_routed_total',
            'Total messages routed through Coral Protocol',
            ['sender_id', 'receiver_id', 'message_type']
        )
        
        self.prom_workflow_duration = Histogram(
            'workflow_duration_seconds',
            'Complete workflow execution time',
            ['workflow_type', 'outcome']
        )
        
        # System metrics
        self.prom_active_workflows = Gauge(
            'active_workflows',
            'Number of currently active workflows'
        )
        
        self.prom_system_errors_total = Counter(
            'system_errors_total',
            'Total system errors',
            ['error_type', 'component']
        )
        
    async def record_alert_submitted(self, workflow_id: str, alert_data: Dict[str, Any] = None):
        """Record alert submission"""
        
        self.counters['alerts_submitted'] += 1
        
        if self.enable_prometheus and alert_data:
            self.prom_alerts_total.labels(
                source_system=alert_data.get('source_system', 'unknown'),
                alert_type=alert_data.get('type', 'unknown'),
                status='submitted'
            ).inc()
            
    async def record_alert_processed(self, workflow_id: str, alert_data: Dict[str, Any],
                                   processing_time: float, outcome: str):
        """Record alert processing completion"""
        
        self.counters['alerts_processed'] += 1
        self.histograms['processing_time'].append(processing_time)
        
        if self.enable_prometheus:
            self.prom_alerts_total.labels(
                source_system=alert_data.get('source_system', 'unknown'),
                alert_type=alert_data.get('type', 'unknown'),
                status=outcome
            ).inc()
            
            self.prom_workflow_duration.labels(
                workflow_type='alert_triage',
                outcome=outcome
            ).observe(processing_time)
            
    async def record_false_positive(self, alert_id: str, alert_type: str,
                                  detection_method: str, confidence: float):
        """Record false positive detection"""
        
        self.counters['false_positives'] += 1
        self.histograms['fp_confidence'].append(confidence)
        
        if self.enable_prometheus:
            self.prom_false_positives_total.labels(
                alert_type=alert_type,
                detection_method=detection_method
            ).inc()
            
    async def record_agent_operation(self, agent_id: str, operation: str,
                                   duration: float, success: bool):
        """Record agent operation metrics"""
        
        key = f'agent_{agent_id}_{operation}'
        self.histograms[f'{key}_duration'].append(duration)
        
        if success:
            self.counters[f'{key}_success'] += 1
        else:
            self.counters[f'{key}_failure'] += 1
            
        if self.enable_prometheus:
            self.prom_alert_processing_time.labels(
                agent_id=agent_id,
                operation=operation
            ).observe(duration)
            
    async def record_message_routed(self, sender_id: str, receiver_id: str,
                                  message_type: str):
        """Record message routing"""
        
        self.counters['messages_routed'] += 1
        
        if self.enable_prometheus:
            self.prom_messages_routed_total.labels(
                sender_id=sender_id,
                receiver_id=receiver_id,
                message_type=message_type
            ).inc()
            
    async def update_agent_queue_size(self, agent_id: str, queue_size: int):
        """Update agent queue size gauge"""
        
        self.gauges[f'agent_{agent_id}_queue_size'] = queue_size
        
        if self.enable_prometheus:
            self.prom_agent_queue_size.labels(agent_id=agent_id).set(queue_size)
            
    async def update_active_workflows(self, count: int):
        """Update active workflows count"""
        
        self.gauges['active_workflows'] = count
        
        if self.enable_prometheus:
            self.prom_active_workflows.set(count)
            
    async def record_error(self, error_type: str, component: str, details: str = None):
        """Record system error"""
        
        self.counters[f'error_{error_type}_{component}'] += 1
        
        if self.enable_prometheus:
            self.prom_system_errors_total.labels(
                error_type=error_type,
                component=component
            ).inc()
            
        logger.error(f"Recorded error: {error_type} in {component}: {details}")
        
    async def get_system_metrics(self) -> Dict[str, Any]:
        """Get comprehensive system metrics"""
        
        uptime = (datetime.datetime.now() - self.start_time).total_seconds()
        
        # Calculate derived metrics
        alerts_per_second = self.counters.get('alerts_processed', 0) / uptime if uptime > 0 else 0
        
        avg_processing_time = (
            sum(self.histograms['processing_time']) / len(self.histograms['processing_time'])
            if self.histograms['processing_time'] else 0
        )
        
        false_positive_rate = (
            self.counters.get('false_positives', 0) / self.counters.get('alerts_processed', 1)
        )
        
        return {
            'uptime_seconds': uptime,
            'alerts_submitted': self.counters.get('alerts_submitted', 0),
            'alerts_processed': self.counters.get('alerts_processed', 0),
            'false_positives': self.counters.get('false_positives', 0),
            'messages_routed': self.counters.get('messages_routed', 0),
            'active_workflows': self.gauges.get('active_workflows', 0),
            
            # Derived metrics
            'alerts_per_second': alerts_per_second,
            'average_processing_time': avg_processing_time,
            'false_positive_rate': false_positive_rate,
            
            # Performance metrics
            'processing_time_p95': self._calculate_percentile('processing_time', 95),
            'processing_time_p99': self._calculate_percentile('processing_time', 99),
            
            # Error metrics
            'total_errors': sum(v for k, v in self.counters.items() if k.startswith('error_')),
            
            'timestamp': datetime.datetime.now().isoformat()
        }
        
    async def get_agent_metrics(self, agent_id: str) -> Dict[str, Any]:
        """Get metrics for specific agent"""
        
        agent_prefix = f'agent_{agent_id}_'
        agent_metrics = {}
        
        # Extract agent-specific counters
        for key, value in self.counters.items():
            if key.startswith(agent_prefix):
                metric_name = key[len(agent_prefix):]
                agent_metrics[metric_name] = value
                
        # Extract agent-specific gauges
        for key, value in self.gauges.items():
            if key.startswith(agent_prefix):
                metric_name = key[len(agent_prefix):]
                agent_metrics[metric_name] = value
                
        return agent_metrics
        
    def _calculate_percentile(self, histogram_name: str, percentile: int) -> float:
        """Calculate percentile for histogram data"""
        
        data = list(self.histograms.get(histogram_name, []))
        if not data:
            return 0.0
            
        data.sort()
        index = int((percentile / 100.0) * len(data))
        index = min(index, len(data) - 1)
        
        return data[index]
        
    async def export_metrics_json(self) -> Dict[str, Any]:
        """Export all metrics as JSON"""
        
        return {
            'counters': dict(self.counters),
            'gauges': dict(self.gauges),
            'histograms': {
                name: list(values) for name, values in self.histograms.items()
            },
            'system_metrics': await self.get_system_metrics()
        }
        
    async def start_prometheus_server(self, port: int = 9090):
        """Start Prometheus metrics server"""
        
        if not self.enable_prometheus:
            logger.warning("Prometheus not available, cannot start metrics server")
            return
            
        try:
            start_http_server(port)
            logger.info(f"Prometheus metrics server started on port {port}")
        except Exception as e:
            logger.error(f"Failed to start Prometheus server: {e}")
            
    async def periodic_metrics_collection(self, interval: int = 60):
        """Periodically collect and log metrics"""
        
        while True:
            try:
                metrics = await self.get_system_metrics()
                
                logger.info(
                    "periodic_metrics",
                    **metrics
                )
                
                # Optional: Send to external monitoring system
                await self._send_to_external_monitoring(metrics)
                
            except Exception as e:
                logger.error(f"Error in periodic metrics collection: {e}")
                
            await asyncio.sleep(interval)
            
    async def _send_to_external_monitoring(self, metrics: Dict[str, Any]):
        """Send metrics to external monitoring system (placeholder)"""
        
        # This is where you would send metrics to:
        # - DataDog
        # - New Relic  
        # - Custom monitoring API
        # - Time-series database
        
        pass


class PerformanceMonitor:
    """Context manager for performance monitoring"""
    
    def __init__(self, metrics_collector: MetricsCollector, 
                 agent_id: str, operation: str):
        self.metrics_collector = metrics_collector
        self.agent_id = agent_id
        self.operation = operation
        self.start_time = None
        
    async def __aenter__(self):
        self.start_time = time.time()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        success = exc_type is None
        
        await self.metrics_collector.record_agent_operation(
            self.agent_id, self.operation, duration, success
        )


def performance_monitor(metrics_collector: MetricsCollector):
    """Decorator for automatic performance monitoring"""
    
    def decorator(func):
        import functools
        
        @functools.wraps(func)
        async def wrapper(self, *args, **kwargs):
            agent_id = getattr(self, 'agent_id', 'unknown')
            operation = func.__name__
            
            async with PerformanceMonitor(metrics_collector, agent_id, operation):
                return await func(self, *args, **kwargs)
                
        return wrapper
    return decorator


class AlertMetrics:
    """Specialized metrics for alert analysis"""
    
    def __init__(self):
        self.alert_types = defaultdict(int)
        self.source_systems = defaultdict(int)
        self.severity_distribution = defaultdict(int)
        self.hourly_distribution = defaultdict(int)
        
    def record_alert(self, alert_data: Dict[str, Any]):
        """Record alert for analysis"""
        
        alert_type = alert_data.get('type', 'unknown')
        source_system = alert_data.get('source_system', 'unknown')
        severity = alert_data.get('severity', 'unknown')
        
        self.alert_types[alert_type] += 1
        self.source_systems[source_system] += 1
        self.severity_distribution[severity] += 1
        
        # Time-based analysis
        if 'timestamp' in alert_data:
            try:
                timestamp = datetime.datetime.fromisoformat(alert_data['timestamp'])
                hour = timestamp.hour
                self.hourly_distribution[hour] += 1
            except ValueError:
                pass
                
    def get_analytics(self) -> Dict[str, Any]:
        """Get alert analytics"""
        
        total_alerts = sum(self.alert_types.values())
        
        return {
            'total_alerts': total_alerts,
            'alert_types': dict(self.alert_types),
            'source_systems': dict(self.source_systems),
            'severity_distribution': dict(self.severity_distribution),
            'hourly_distribution': dict(self.hourly_distribution),
            'top_alert_types': sorted(
                self.alert_types.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5],
            'peak_hours': sorted(
                self.hourly_distribution.items(),
                key=lambda x: x[1],
                reverse=True
            )[:3]
        }